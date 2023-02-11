"""
Collect all the interesting data for analysis - Core version
"""
from __future__ import absolute_import
import logging
from insights import collect

from insights.core import blacklist, dr
from insights.core.blacklist import BLACKLISTED_SPECS
from insights.client.constants import InsightsConstants as constants
from insights.client.data_collector import DataCollector
from insights.client.utilities import systemd_notify_init_thread

APP_NAME = constants.app_name
logger = logging.getLogger(__name__)


class CoreCollector(DataCollector):
    def __init__(self, *args, **kwargs):
        super(CoreCollector, self).__init__(*args, **kwargs)

    def run_collection(self, conf, post_proc, branch_info, blacklist_report):
        '''
        Initialize core collection here and generate the
        output directory with collected data.
        '''
        # initialize systemd-notify thread
        systemd_notify_init_thread()

        self.archive.create_archive_dir()
        self.archive.create_command_dir()

        logger.debug('Beginning to run collection...')

        manifest = collect.default_manifest
        if hasattr(self.config, 'manifest') and self.config.manifest:
            if self.config.app is None:
                with open(self.config.manifest, 'r') as f:
                    manifest = f.read()
            else:
                manifest = self.config.manifest

        # add tokens to limit regex handling for core
        # to parse blacklist for files and commands as regex
        for f in post_proc.redact.get('files', []):
            blacklist.add_file(r'^%s$' % f)
        for c in post_proc.redact.get('commands', []):
            blacklist.add_file(r'^%s$' % c)

        for component in post_proc.redact.get('components', []):
            if not dr.get_component_by_name(component):
                logger.warning('WARNING: Unknown component in blacklist: %s' % component)
            else:
                dr.set_enabled(component, enabled=False)
                BLACKLISTED_SPECS.append(component.split('.')[-1])
                logger.warning('WARNING: Skipping component: %s', component)

        collected_data_path, exceptions = collect.collect(
            manifest=manifest,
            post_proc=post_proc,
            tmp_path=self.archive.tmp_dir,
            relative_path=self.archive.archive_name,
            client_timeout=self.config.cmd_timeout
        )

        if not collected_data_path:
            raise RuntimeError('Error running collection: no output path defined.')

        logger.debug('Collection finished.')

        # collect metadata
        logger.debug('Collecting metadata...')
        self._write_branch_info(branch_info)
        self._write_display_name()
        self._write_ansible_host()
        self._write_version_info()
        self._write_tags()
        self._write_blacklist_report(blacklist_report)
        self._write_egg_release()
        logger.debug('Metadata collection finished.')
