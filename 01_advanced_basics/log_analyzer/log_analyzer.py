#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import gzip
import re
from collections import defaultdict
from dataclasses import dataclass
import os.path
import os

from datetime import datetime

import argparse
import configparser
import logging
import string
import json
from pathlib import Path
from typing import Union, Optional, Iterator
from decimal import Decimal as D

ConfigOrError = Union[configparser.ConfigParser, str]
ConfigSec = configparser.SectionProxy

DEFAULT_CONFIG = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "log_file_error_percentage": 50,
    # can have log_filename entry
}
CONFIG_FILE_SECTION = 'log_analyzer'
logger = logging.getLogger(__name__)

nginx_line_re = re.compile(r"""^\S+\s+\S+\s+\S+\s+\[.*]\s+\S+\s+(?P<url>\S+).*\s+(?P<time>\d+(?:\.\d+)?)$""")


def get_argparse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Log analyzer')
    parser.add_argument('--config', nargs='?', default='./config.ini')
    return parser.parse_args()


def read_config_file(filename: str) -> ConfigOrError:
    """returns config from file or throw an error"""
    config_file = configparser.ConfigParser(
        defaults=DEFAULT_CONFIG,
        default_section=CONFIG_FILE_SECTION)
    try:
        with open(filename, 'r') as fp:
            config_file.read_file(fp)
            return config_file
    except configparser.ParsingError as e:
        return f'Parsing error: {str(e)}'
    except FileNotFoundError as e:
        return f'File not found: {str(e)}'


def configure_logging(global_config: configparser.ConfigParser):
    logging.basicConfig(filename=global_config[CONFIG_FILE_SECTION].get('log_filename'),
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)


def validate_and_get_config_section(global_config: configparser.ConfigParser) -> Optional[ConfigSec]:
    config: ConfigSec = global_config[CONFIG_FILE_SECTION]

    try:
        if not ensure_dir_from_config_exists(config, 'log_dir'):
            logger.error('bad "log_dir" config path, directory must exist!')
            return
        ensure_dir_from_config_exists(config, 'report_dir', create_if_not=True)
        if not check_config_value_castable_to(config, 'report_size', int) or \
                not check_config_value_castable_to(config, 'log_file_error_percentage', float):
            return
    except KeyError as e:
        logger.error('missing mandatory %s config value', e)
        return
    return config


def ensure_dir_from_config_exists(config: ConfigSec, config_path: str, create_if_not: bool = False) -> bool:
    dir_name = config[config_path]
    exists: bool = os.path.exists(dir_name)

    if exists:
        logger.info('directory %s exists', dir_name)
        return True
    elif create_if_not:
        Path(dir_name).mkdir(parents=True)
        logger.info('directory %s was successfully created: %s', config_path, dir_name)
        return True
    logger.info('directory %s does not exist', dir_name)
    return False


def check_config_value_castable_to(config: ConfigSec, config_path: str, type_: type) -> bool:
    value = config[config_path]
    try:
        type_(value)
        return True
    except ValueError:
        logger.error('bad "%s" config value (%s), expected %s', config_path, value, type_)
    return False


@dataclass
class LogFileInfo:
    filename: str
    dt: datetime
    extension: str


def get_newest_log_file(config: ConfigSec) -> Optional[LogFileInfo]:
    log_dir = config['log_dir']
    logger.info('looking for the newest log file in %s dir', log_dir)
    regex = re.compile(r'^nginx-access-ui\.log-(?P<date>\d{8})(?P<ext>(?:\.gz)?)$')
    res: Optional[LogFileInfo] = None
    for filename in os.listdir(log_dir):  # throws FileNotFoundError
        full_path = os.path.join(log_dir, filename)
        if os.path.isfile(full_path) and (m := regex.match(filename)):
            try:
                dt = datetime.strptime(m.group('date'), '%Y%m%d')
            except ValueError:  # bad date
                continue
            if not res or dt > res.dt:
                res = LogFileInfo(filename=full_path, dt=dt, extension=m.group('ext'))
    logger.info('newest log file: %s', res)
    return res


def make_report_file_path(config: ConfigSec, log_file_info: LogFileInfo) -> str:
    return os.path.join(config['report_dir'], log_file_info.dt.strftime('report-%Y.%m.%d.html'))


def read_log_file_generator(log_file_info: LogFileInfo, encoding='utf-8') -> Iterator[str]:
    open_func = gzip.open if log_file_info.extension == '.gz' else open
    logger.info('open log file %s', log_file_info.filename)
    with open_func(log_file_info.filename) as f:
        for line in f:
            yield line.decode(encoding)
    logger.info('log file %s was closed', log_file_info.filename)


def parse_nginx_line(line: str) -> tuple[str, D]:
    # не стал создавать датакласс для результов этой функции, чтобы не плодить лишних объектов
    m = nginx_line_re.match(line)
    return m.group('url'), D(m.group('time'))  # throws AttributeError


def check_log_file_error_percentage(config: ConfigSec, error_number: int, line_number: int) -> bool:
    config_level = float(config['log_file_error_percentage'])
    percentage = error_number / line_number * 100
    logger.info('calculate error percentage: %d of %d (%.2f%%)', error_number, line_number, percentage)
    if percentage >= config_level:
        logger.error('a lot of error lines: %.2f%% allowed, actual %.2f%%', config_level, percentage)
        return False
    return True


def get_median(time_list: list[D]) -> D:
    sorted_time_list = sorted(time_list)
    list_len = len(sorted_time_list)

    if list_len % 2 == 1:
        return sorted_time_list[list_len // 2]
    return sum(sorted_time_list[list_len // 2 - 1: list_len // 2 + 1]) / 2


def calculate_report(config: ConfigSec, log_file_info: LogFileInfo) -> Optional[list[dict]]:
    memory: dict[str, list[D]] = defaultdict(list)
    error_number = line_number = 0
    logger.info('start to read the log')
    for line in read_log_file_generator(log_file_info):  # O(n)
        try:
            url, time = parse_nginx_line(line)
            memory[url].append(time)  # O(1)
        except AttributeError:
            error_number += 1
        line_number += 1
    logger.info('stop to read the log')

    if not check_log_file_error_percentage(config, error_number, line_number):
        return

    time_sum_iter = (
        (url, sum(time_list)) for url, time_list in memory.items()
    )
    sorted_time_sum_list = sorted(time_sum_iter, key=lambda t: t[1], reverse=True)  # sort sums grouped by url
    all_times_sum = sum(time for _, time in sorted_time_sum_list)

    report_size = int(config['report_size'])
    return [  # find max and sort time lists will only report_size times
        create_report_dict(url, time_sum, all_times_sum, memory[url], line_number)
        for (url, time_sum), _ in zip(sorted_time_sum_list, range(report_size))
    ]


def create_report_dict(url: str, url_time_sum: D, all_time_sum: D, time_list: list[D], all_count: int):
    url_count: int = len(time_list)
    return {
        "count": url_count,
        "time_avg": float(url_time_sum / url_count),
        "time_max": float(max(time_list)),
        "time_sum": float(url_time_sum),
        "url": url,
        "time_med": float(get_median(time_list)),
        "time_perc": float(url_time_sum / all_time_sum * 100),
        "count_perc": url_count / all_count * 100,
    }


def save_report(report: list[dict], report_file_path: str) -> None:
    logger.info('get report template in "report.html"')
    with open('report.html') as report_template_file:
        templ = string.Template(report_template_file.read())
    with open(report_file_path, 'w') as report_file:
        report_file.write(templ.safe_substitute(table_json=json.dumps(report)))
    logger.info('report was saved in %s', report_file_path)


def main() -> Optional[int]:
    args: argparse.Namespace = get_argparse_args()
    global_config: ConfigOrError = read_config_file(args.config)

    if isinstance(global_config, str):
        logger.error(global_config)  # всегда попадает в stderr в стандартном виде
        return 1

    # configure logging as soon as possible
    configure_logging(global_config)
    config: ConfigSec = validate_and_get_config_section(global_config)
    if not config:
        logger.info('config values error, exit')
        return 1

    log_file_info: LogFileInfo = get_newest_log_file(config)
    if log_file_info is None:
        logger.info('no log file to read, exit')
        return

    report_file_path: str = make_report_file_path(config, log_file_info)
    if os.path.exists(report_file_path):
        logger.info('report file %s already exists, exit', report_file_path)
        return

    report = calculate_report(config, log_file_info)
    if not report:
        return

    save_report(report, report_file_path)


if __name__ == "__main__":
    try:
        exit(main())
    except (Exception, KeyboardInterrupt) as e:
        logger.exception(e)
        exit(1)
    # хоть в методичке и запрещено создавать свои классы исключений, но так и напрашивается его создать,
    # чтобы тут перехватить и делать выход без logger.exception. Тогда в main не пришлось бы каждый раз проверять,
    # не None ли вернули. Логически исключение бы значило "ситуация понятная, но далее работать смысла нет"
