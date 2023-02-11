from mock.mock import patch

from insights.client.config import InsightsConfig
from insights.client.data_collector import DataCollector
from insights.util.spec_processor import PostProcessor


@patch('insights.client.data_collector.InsightsArchive')
def test_archive_returned(_):
    c = InsightsConfig()
    p = PostProcessor(c, {})
    d = DataCollector(c)
    ret = d.done(c, p)
    d.archive.create_tar_file.assert_called_once()
    assert ret == d.archive.create_tar_file.return_value


@patch('insights.client.data_collector.InsightsArchive')
def test_dir_returned(_):
    c = InsightsConfig(output_dir='test')
    p = PostProcessor(c, {})
    d = DataCollector(c)
    ret = d.done(c, p)
    d.archive.create_tar_file.assert_not_called()
    assert ret == d.archive.archive_dir


@patch('insights.client.data_collector.DataCollector._write_rhsm_facts')
@patch('insights.client.data_collector.InsightsArchive')
def test_obfuscated_archive_returned(_, __):
    '''
    Test that _write_rhsm_facts is called when obfuscate=True,
    '''
    c = InsightsConfig(obfuscate=True)
    r = {'keywords': ['test']}
    p = PostProcessor(c, r)
    d = DataCollector(c)
    ret = d.done(c, p)
    d.archive.create_tar_file.assert_called_once()
    d._write_rhsm_facts.assert_called_once()
    assert ret == d.archive.create_tar_file.return_value
