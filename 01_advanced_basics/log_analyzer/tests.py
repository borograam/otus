import random
from dataclasses import dataclass

from datetime import datetime

from contextlib import contextmanager

import unittest
from decimal import Decimal as D

import log_analyzer as la
import logging
import configparser
from unittest.mock import patch, mock_open
from typing import Iterable, ContextManager, Optional, Tuple

logging.getLogger('log_analyzer').setLevel(logging.CRITICAL + 1)


def create_fake_config(fake_data: str = '', get_global=False, **kwargs):
    config = {k.lower(): v for k, v in la.DEFAULT_CONFIG.items()}
    config.update({k.lower(): v for k, v in kwargs.items()})

    with patch('log_analyzer.open', mock_open(read_data=fake_data)), patch.object(la, 'DEFAULT_CONFIG', config):
        global_config = la.read_config_file('./something')
        if get_global:
            return global_config
        return global_config[la.CONFIG_FILE_SECTION]


class TestGetArgparseArgs(unittest.TestCase):
    def test_default_path(self):
        with patch('sys.argv', ['./qwe.py']):  # no args
            args = la.get_argparse_args()
        self.assertEqual(args.config, './config.ini')

    def test_some_path(self):
        """ensure everything passed in argv will be in namespace"""
        with patch('sys.argv', ['./qwe.py', '--config', '/something']):
            args = la.get_argparse_args()
        self.assertEqual(args.config, '/something')


class TestReadConfigFile(unittest.TestCase):
    def test_no_file(self):
        res = la.read_config_file('/not_exist')
        self.assertRegex(res, r"File not found:(.*)'/not_exist'")

    def test_parse_error(self):
        message = 'mes'
        with patch('configparser.ConfigParser.read_file') as mock:
            mock.side_effect = configparser.ParsingError(message)
            res = la.read_config_file('tests.py')  # this file always exists
        self.assertRegex(res, f'Parsing error:(.*){message}')

    def test_empty_file(self):
        """ensure read_config_file has no error on empty config file"""
        res = create_fake_config(get_global=True)
        self.assertIsInstance(res, configparser.ConfigParser)
        for k, v in la.DEFAULT_CONFIG.items():
            self.assertEqual(res['log_analyzer'][k], str(v))

    def test_field_overwriting(self):
        res = create_fake_config("""
[log_analyzer]
log_dir = /here""", get_global=True)
        self.assertIsInstance(res, configparser.ConfigParser)
        self.assertEqual(res['log_analyzer']['log_dir'], '/here')


class TestValidateAndGetConfigSection(unittest.TestCase):
    def setUp(self) -> None:
        self.global_config = create_fake_config(get_global=True)
        self.config = self.global_config[la.CONFIG_FILE_SECTION]

    def test_config_paths_exists(self):
        with patch('os.path.exists', return_value=True):
            for path in ('log_dir', 'report_dir', 'report_size', 'log_file_error_percentage'):
                with self.subTest(path):
                    temp = self.config[path]
                    del self.config[path]
                    self.assertIsNone(la.validate_and_get_config_section(self.global_config))
                    self.config[path] = temp  # restore value

    def test_log_dir_not_exist(self):
        with patch('os.path.exists', return_value=False):
            self.assertIsNone(la.validate_and_get_config_section(self.global_config))

    def test_not_castable(self):
        with patch.object(la, 'check_config_value_castable_to', return_value=False):
            self.assertIsNone(la.validate_and_get_config_section(self.global_config))


class TestEnsureDirFromConfigExists(unittest.TestCase):
    def setUp(self):
        self.config = create_fake_config()
        self.config['log_dir'] = '/some'

    @dataclass
    class TestParam:
        file_exists: bool
        create_if_not: bool
        expected_result: bool
        mkdir_called: bool

    @staticmethod
    def generate_test_name(param: TestParam) -> str:
        return f'{param.file_exists=}, {param.create_if_not=}'

    def test(self):
        params: Tuple[TestEnsureDirFromConfigExists.TestParam, ...] = (
            self.TestParam(True, True, True, False),
            self.TestParam(True, False, True, False),
            self.TestParam(False, True, True, True),
            self.TestParam(False, False, False, False),
        )

        for param in params:
            with self.subTest(self.generate_test_name(param)):
                with (
                        patch('os.path.exists', return_value=param.file_exists),
                        patch.object(la, 'Path') as m
                ):
                    res = la.ensure_dir_from_config_exists(self.config, 'log_dir',
                                                           create_if_not=param.create_if_not)
                self.assertEqual(res, param.expected_result)
                self.assertEqual(m.called, param.mkdir_called)


class TestCheckConfigValueCastableTo(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_fake_config()

    @dataclass
    class TestParam:
        value: str
        type_: type
        expected: bool

    def test(self):
        params: Tuple[TestCheckConfigValueCastableTo.TestParam, ...] = (
            self.TestParam('59', int, True),
            self.TestParam('23.543', float, True),
            self.TestParam('59.1', int, False),
        )
        for param in params:
            with self.subTest(param):
                self.config['test'] = param.value
                res = la.check_config_value_castable_to(self.config, 'test', param.type_)
                self.assertEqual(res, param.expected)


class TestGetNewestLogFile(unittest.TestCase):
    def setUp(self):
        self.config = create_fake_config()

    @contextmanager
    def mock_dir(self, dirs: Iterable[str] = tuple(), files: Iterable[str] = tuple()) -> ContextManager:
        content = {dir_: False for dir_ in dirs}
        content.update({file: True for file in files})

        def isfile(full_path: str) -> bool:
            return content[full_path.split('/')[-1]]  # what about windows?

        with patch('os.listdir', return_value=content.keys()):
            with patch('os.path.isfile', side_effect=isfile):
                yield

    def test_empty_dir(self):
        with self.mock_dir():
            res = la.get_newest_log_file(self.config)
        self.assertIsNone(res)

    def test_no_dir(self):
        self.config['log_dir'] = '/no/exist'
        self.assertRaises(FileNotFoundError, la.get_newest_log_file, self.config)

    def test_dir_contains_re_accepted_dir(self):
        with self.mock_dir(dirs=['nginx-access-ui.log-20210101.gz']):
            res = la.get_newest_log_file(self.config)
        self.assertIsNone(res)

    def test_filename_re(self):
        self.config['log_dir'] = '/some/path'

        @dataclass
        class TestParam:
            files: Iterable[str]
            expected: Optional[la.LogFileInfo]
            msg: str

        parametrize: tuple[TestParam, ...] = (
            TestParam(('nginx-ui.log-20210101.gz',), None, 'no "access"'),
            TestParam(
                files=('nginx-access-ui.log-20210101.gz',),
                expected=la.LogFileInfo(
                    filename='/some/path/nginx-access-ui.log-20210101.gz',
                    dt=datetime(2021, 1, 1),
                    extension='.gz'
                ),
                msg='gz'
            ),
            TestParam(
                files=('nginx-access-ui.log-20210101',),
                expected=la.LogFileInfo(
                    filename='/some/path/nginx-access-ui.log-20210101',
                    dt=datetime(2021, 1, 1),
                    extension=''
                ),
                msg='without extension'
            ),
            TestParam(('nginx-access-ui.log-20210101.bz2',), None, 'bz2'),
            TestParam(('nginx-access-ui.log-99999999.gz',), None, 'bad date'),
            TestParam(
                files=(
                    'nginx-access-ui.log-20200101.gz',
                    'nginx-access-ui.log-20220101.gz',
                    'nginx-access-ui.log-20210101.gz',
                ),
                expected=la.LogFileInfo(
                    filename='/some/path/nginx-access-ui.log-20220101.gz',
                    dt=datetime(2022, 1, 1),
                    extension='.gz'
                ),
                msg='find max date'
            ),
        )

        for param in parametrize:
            with self.subTest(param.msg):
                with self.mock_dir(files=param.files):
                    res = la.get_newest_log_file(self.config)
                if not param.expected:
                    self.assertIsNone(res)
                else:
                    self.assertIsInstance(res, la.LogFileInfo)
                    self.assertEqual(param.expected, res)


class TestMakeReportFilePath(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_fake_config()
        self.config['report_dir'] = '/some'

        self.log_file_info = la.LogFileInfo('filename.log', datetime(2022, 1, 1), '.txt')

    def test_common(self) -> None:
        res: str = la.make_report_file_path(self.config, self.log_file_info)
        self.assertEqual(res, '/some/report-2022.01.01.html')


class TestReadLogFileGenerator(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_fake_config()

    def test_open_func(self):
        @dataclass
        class TestParam:
            ext: str
            mock_called: str

        params: tuple[TestParam, ...] = (
            TestParam('', 'm_open'),
            TestParam('.gz', 'm_gzip'),
        )
        for param in params:
            with self.subTest(param):
                with patch.object(la, 'open') as m_open, patch('gzip.open') as m_gzip:
                    gen = la.read_log_file_generator(
                        la.LogFileInfo('aaa', datetime(2022, 1, 1), param.ext))
                    list(gen)
                    self.assertNotEqual(m_open.called, m_gzip.called)
                    locals()[param.mock_called].assert_called()


class TestParseNginxLine(unittest.TestCase):
    def test(self):
        line = '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n'
        res = la.parse_nginx_line(line)
        self.assertEqual(res, ('/api/v2/banner/25019354', D('0.390')))


class TestCheckLogFileErrorPercentage(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_fake_config(log_file_error_percentage='10')

    def test(self):
        self.assertFalse(la.check_log_file_error_percentage(self.config, 10, 100))
        self.assertTrue(la.check_log_file_error_percentage(self.config, 9, 100))


class TestGetMedian(unittest.TestCase):
    def test_odd(self):
        num_list = list(D(i) for i in range(5))
        random.shuffle(num_list)
        self.assertEqual(la.get_median(num_list), D(2))

    def test_even(self):
        num_list = list(D(i) for i in range(10))
        random.shuffle(num_list)
        self.assertEqual(la.get_median(num_list), D('4.5'))


class TestCalculateReport(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_fake_config(report_size='2')
        self.log_file_info = la.LogFileInfo('', datetime.now(), '')

    def test_logic(self):
        fake_data = (
            ('/aaa', D(1)),
            ('/aaa', D(2)),
            ('/bbb', D(3)),
            ('/bbb', D(4)),
            ('/ccc', D(5)),
        )
        with (
                patch.object(la, 'read_log_file_generator', return_value=range(len(fake_data))),
                patch.object(la, 'parse_nginx_line', side_effect=fake_data)
        ):
            res = la.calculate_report(self.config, self.log_file_info)
        self.assertEqual(res, [
            la.create_report_dict('/bbb', D(7), D(15), [D(3), D(4)], 5),
            la.create_report_dict('/ccc', D(5), D(15), [D(5)], 5),
        ])


class TestCreateReportDict(unittest.TestCase):
    def test(self):
        res = la.create_report_dict('/test', D(9), D(12), [D(1), D(2), D(6)], 12)
        self.assertEqual(res, {
            'count': 3,
            'time_avg': 3.0,
            'time_max': 6.0,
            'time_sum': 9.0,
            'url': '/test',
            'time_med': 2.0,
            'time_perc': 75.0,
            'count_perc': 25.0
        })


class TestSaveReport(unittest.TestCase):
    def test(self):
        with patch.object(la, 'open', mock_open(read_data='123\n$table_json\n456')) as m:
            la.save_report([{'a': 1}, {'b': 2}], '/path.html')
        m.assert_called_with('/path.html', 'w')
        m.return_value.write.assert_called_with('123\n[{"a": 1}, {"b": 2}]\n456')
