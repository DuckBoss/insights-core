import os

from mock.mock import patch, Mock

from insights.client.archive import InsightsArchive
from insights.client.config import InsightsConfig
from insights.client.core_collector import CoreCollector
from insights.client.data_collector import DataCollector
from insights.util.spec_processor import PostProcessor

test_file_data = 'test\nabcd\n1234\npwd: p4ssw0rd\n'
test_file_data_sensitive = 'test\nabcd\n1234\npassword: p4ssw0rd\n'


@patch('insights.client.archive.InsightsArchive', Mock())
@patch('insights.client.insights_spec.InsightsCommand', Mock())
@patch('insights.client.insights_spec.InsightsFile', Mock())
@patch('insights.client.data_collector.DataCollector._parse_command_spec', Mock())
@patch('insights.client.data_collector.DataCollector._parse_file_spec', Mock())
@patch('insights.client.data_collector.DataCollector._parse_glob_spec', Mock())
def test_redact_classic():
    '''
    Verify redact is filled during classic collection
    '''
    conf = InsightsConfig()
    upload_conf = {'commands': [], 'files': [], 'globs': []}
    rm_conf = {'test': 'test'}
    branch_info = {'test1': 'test2'}
    blacklist_report = {'test3': 'test4'}
    dc = DataCollector(conf)
    pp = PostProcessor(conf, rm_conf)
    dc.run_collection(upload_conf, pp, branch_info, blacklist_report)
    assert pp.redact['commands'] == []
    assert pp.redact['files'] == []
    assert pp.redact['exclude'] == []
    assert pp.redact['regex'] is False


@patch('insights.client.archive.InsightsArchive', Mock())
@patch('insights.client.core_collector.CoreCollector._write_branch_info', Mock())
@patch('insights.client.core_collector.CoreCollector._write_display_name', Mock())
@patch('insights.client.core_collector.CoreCollector._write_version_info', Mock())
@patch('insights.client.core_collector.CoreCollector._write_tags', Mock())
@patch('insights.client.core_collector.CoreCollector._write_blacklist_report', Mock())
@patch('insights.client.core_collector.collect.collect', Mock(return_value=('/var/tmp/testarchive/insights-test', {})))
def test_redact_core():
    conf = InsightsConfig(core_collect=True)
    upload_conf = None
    rm_conf = {'test': 'test'}
    branch_info = {'test1': 'test2'}
    blacklist_report = {'test3': 'test4'}
    dc = CoreCollector(conf)
    pp = PostProcessor(conf, rm_conf)
    dc.run_collection(upload_conf, pp, branch_info, blacklist_report)
    assert pp.redact['commands'] == []
    assert pp.redact['files'] == []
    assert pp.redact['exclude'] == []
    assert pp.redact['regex'] is False


def test_redact_line_not_change():
    """No password in data"""
    conf = InsightsConfig(core_collect=False, obfuscate=True)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data)

    pp = PostProcessor(conf, {})
    pp.process_file(test_file, [])
    # file is not changed
    with open(test_file, 'r') as t:
        assert test_file_data == ''.join(t.readlines())
    arch.delete_archive_dir()


def test_redact_line_changed_password_legacy():
    conf = InsightsConfig(core_collect=False, obfuscate=True)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data_sensitive)

    pp = PostProcessor(conf, {})
    pp.process_file(test_file, [])
    # file is changed
    with open(test_file, 'r') as t:
        data = t.readlines()
        assert 'p4ssw0rd' not in data[-1]
        assert '********' in data[-1]
    arch.delete_archive_dir()


def test_redact_line_changed_password_core():
    conf = InsightsConfig(core_collect=True, obfuscate=True)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data_sensitive)

    pp = PostProcessor(conf, {})
    pp.process_file(test_file, [])
    # file is changed
    with open(test_file, 'r') as t:
        data = t.readlines()
        assert 'p4ssw0rd' not in data[-1]
        assert '********' in data[-1]
    arch.delete_archive_dir()


def test_redact_line_changed_password_keyword():
    conf = InsightsConfig(core_collect=False, obfuscate=True)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data_sensitive)

    pp = PostProcessor(conf, {'keywords': ['test']})
    pp.process_file(test_file, [])
    # file is changed
    with open(test_file, 'r') as t:
        data = t.readlines()
        assert 'test' not in data[0]
        assert 'keyword0' in data[0]
        assert 'p4ssw0rd' not in data[-1]
        assert '********' in data[-1]
    arch.delete_archive_dir()


def test_redact_line_changed_password_keyword_disabled():
    conf = InsightsConfig(core_collect=False, obfuscate=False)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data)

    pp = PostProcessor(conf, {'keywords': 'test'})
    pp.process_file(test_file, [])
    # file is not changed
    with open(test_file, 'r') as t:
        assert test_file_data == ''.join(t.readlines())
    arch.delete_archive_dir()


def test_redact_exclude_regex():
    conf = InsightsConfig(core_collect=False)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data)

    rm_conf = {'patterns': {'regex': ['12.*4', '^abcd']}}
    pp = PostProcessor(conf, rm_conf)
    pp.process_file(test_file, [])
    with open(test_file, 'r') as t:
        data = [i.strip() for i in t.readlines()]
        assert '1234' not in data
        assert 'abcd' not in data
    arch.delete_archive_dir()


def test_redact_exclude_no_regex():
    conf = InsightsConfig(core_collect=False)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data)

    rm_conf = {'patterns': ['1234', 'abcd']}
    pp = PostProcessor(conf, rm_conf)
    pp.process_file(test_file, [])
    with open(test_file, 'r') as t:
        data = [i.strip() for i in t.readlines()]
        assert '1234' not in data
        assert 'abcd' not in data
    arch.delete_archive_dir()


def test_redact_exclude_empty():
    conf = InsightsConfig(core_collect=False)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data)

    rm_conf = {'patterns': []}
    pp = PostProcessor(conf, rm_conf)
    pp.process_file(test_file, [])
    # file is not changed
    with open(test_file, 'r') as t:
        assert test_file_data == ''.join(t.readlines())
    arch.delete_archive_dir()


def test_redact_exclude_none():
    conf = InsightsConfig(core_collect=False)
    arch = InsightsArchive(conf)
    arch.create_archive_dir()

    # put something in the archive to redact
    test_file = os.path.join(arch.archive_dir, 'test.file')
    with open(test_file, 'w') as t:
        t.write(test_file_data)

    rm_conf = {'patterns': {}}
    pp = PostProcessor(conf, rm_conf)
    pp.process_file(test_file, [])
    # file is not changed
    with open(test_file, 'r') as t:
        assert test_file_data == ''.join(t.readlines())
    arch.delete_archive_dir()
