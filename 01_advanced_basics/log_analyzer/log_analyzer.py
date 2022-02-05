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
from statistics import median
from typing import Union, Optional, Iterator, Iterable, Callable
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


def read_config_file(filename: str) -> configparser.ConfigParser:
    """returns config from file or throw an error"""
    config_file = configparser.ConfigParser(
        defaults=DEFAULT_CONFIG,
        default_section=CONFIG_FILE_SECTION)
    try:
        with open(filename, 'r') as fp:
            config_file.read_file(fp)
            return config_file
    except configparser.ParsingError as e:
        raise SystemExit(f'Parsing error: {str(e)}')
    except FileNotFoundError as e:
        raise SystemExit(f'File not found: {str(e)}')


def validate_and_get_config(filename: str) -> ConfigSec:
    global_config: configparser.ConfigParser = read_config_file(filename)
    config: ConfigSec = global_config[CONFIG_FILE_SECTION]

    try:
        validate_dir_from_config(config, 'log_dir')
        validate_dir_from_config(config, 'report_dir', must_exist=False)
        validate_config_value_castable_to(config, 'report_size', int)
        validate_config_value_castable_to(config, 'log_file_error_percentage', float)
    except KeyError as e:
        raise SystemExit('missing mandatory %s config value' % e)
    return config


def validate_dir_from_config(config: ConfigSec, config_path: str, must_exist: bool = True) -> None:
    dir_name = config[config_path]
    exists: bool = os.path.exists(dir_name)

    logger.info('directory %s %sexist', dir_name, '' if exists else 'does not ')
    if exists:
        if os.path.isfile(dir_name):
            raise SystemExit('bad "%s" config path (%s), it must be a directory!' % (config_path, dir_name))
    elif must_exist:
        raise SystemExit('bad "%s" config path (%s), directory must exist!' % (config_path, dir_name))


def validate_config_value_castable_to(config: ConfigSec, config_path: str, type_: type) -> None:
    value = config[config_path]
    try:
        type_(value)
    except ValueError:
        raise SystemExit('bad "%s" config path (%s), expected %s' % (config_path, value, type_))


def configure_logging(config: ConfigSec):
    logging.basicConfig(filename=config.get('log_filename'),
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)


def create_report_dir(config: ConfigSec):
    try:
        Path(config['report_dir']).mkdir(parents=True)
    except FileExistsError:
        pass


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
    for filename in os.listdir(log_dir):
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


def check_log_file_error_percentage(config: ConfigSec, error_number: int, line_number: int) -> None:
    config_level = float(config['log_file_error_percentage'])
    percentage = error_number / line_number * 100
    logger.info('calculate error percentage: %d of %d (%.2f%%)', error_number, line_number, percentage)
    if percentage >= config_level:
        raise SystemExit('a lot of error lines: %.2f%% allowed, actual %.2f%%' % (config_level, percentage))


def calculate_report(config: ConfigSec,
                     log_rows: Iterable[str],
                     parse_log_row: Callable[[str], tuple[str, D]]) -> list[dict]:
    memory: dict[str, list[D]] = defaultdict(list)
    error_number = line_number = 0
    logger.info('start to read the log')
    for line in log_rows:
        try:
            url, time = parse_log_row(line)
            memory[url].append(time)  # O(1)
        except AttributeError:
            error_number += 1
        line_number += 1
    logger.info('stop to read the log')

    check_log_file_error_percentage(config, error_number, line_number)

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
        "time_med": float(median(time_list)),
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
    config: ConfigSec = validate_and_get_config(args.config)
    configure_logging(config)

    log_file_info: LogFileInfo = get_newest_log_file(config)
    if log_file_info is None:
        logger.info('no log file to read, exit')
        return

    report_file_path: str = os.path.join(config['report_dir'], log_file_info.dt.strftime('report-%Y.%m.%d.html'))
    if os.path.exists(report_file_path):
        logger.info('report file %s already exists, exit', report_file_path)
        return

    report = calculate_report(config, read_log_file_generator(log_file_info), parse_nginx_line)
    if not report:
        return

    create_report_dir(config)
    save_report(report, report_file_path)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as e:  # неожиданная ситуация
        logger.exception(e)
    except SystemExit as e:  # ожидаемая ситуация, при которой что-то пошло не так
        logger.error(e)
