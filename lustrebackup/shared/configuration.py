#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# configuration - configuration wrapper
# Copyright (C) 2020-2025  The lustrebackup Project by the Science HPC Center at UCPH
#
# This file is part of lustrebackup.
#
# Python lustre backup is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Python lustre backup is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# -- END_HEADER ---
#

"""Configuration class"""

import os
import sys
import multiprocessing
from configparser import RawConfigParser

from lustrebackup.shared.base import print_stderr
from lustrebackup.shared.logger import Logger


class Configuration:
    """backup configuration in parsed form"""

    loglevel = 'info'
    logger_obj = None
    logger = None

    # GLOBAL

    logpath = None
    logdir = None
    logfile = None

    # LUSTRE

    lustre_fsname = ''
    lustre_nid = ''
    lustre_mdt = ''
    lustre_mgs = ''
    lustre_changelog_user = ''
    lustre_data_mount = ''
    lustre_data_path = ''
    lustre_meta_basepath = ''
    lustre_snapshot_create_retries = 10
    lustre_snapshot_home = ''
    lustre_snapshot_mount_opts = ''
    lustre_data_mount_opts = ''
    lustre_largefile_size = 1024**3
    lustre_hugefile_size = 1024**4

    # SOURCE

    source_host = ''
    source_conf = ''

    # BACKUP

    backup_rsync_command = ''
    backup_source_fsname = ''
    backup_checksum_choice = ''

    # SYSTEM

    system_nprocs = 0
    system_sys_memory_factor = 0
    system_user_memory_factor = 0
    system_ssh_config = '/root/.ssh/config'

    # constructor

    def __init__(self,
                 config_file,
                 verbose=False,
                 skip_log=False,
                 logpath=None):
        self.config_file = config_file
        self.logpath = logpath
        self.reload_config(verbose, skip_log, logpath)

    def reload_config(self, verbose, skip_log=False, logpath=None):
        """Re-read and parse configuration file. Optional skip_log
        initializes default logger to use the NullHandler in order to avoid
        uninitialized log while not really touching log files or causing stdio
        output."""

        try:
            if self.logger:
                self.logger.info('reloading configuration and reopening log')
        except Exception:
            pass

        if not os.path.isfile(self.config_file):
            print_stderr("""Could not find your configuration file (%s)."""
                         % self.config_file)
            raise IOError

        config = RawConfigParser()
        config.read([self.config_file])

        try:
            self.logdir = config.get(
                'GLOBAL', 'logdir').strip()
            self.logfile = config.get(
                'GLOBAL', 'logfile').strip()
            self.loglevel = config.get(
                'GLOBAL', 'loglevel').strip()
        except Exception as err:
            raise Exception(
                'Failed to find logX settings in configuration: %s' % err)

        if skip_log:
            self.logpath = None
        elif logpath:
            self.logpath = logpath
        else:
            self.logpath = os.path.join(self.logdir, self.logfile)
        if verbose:
            print_stderr('logging to:',
                         self.logpath, '; level:', self.loglevel)

        # reopen or initialize logger

        if self.logger_obj:
            self.logger_obj.reopen()
        else:
            self.logger_obj = Logger(self.loglevel, logfile=self.logpath)

        logger = self.logger_obj.logger
        self.logger = logger

        # print "logger initialized (level " + logger_obj.loglevel() + ")"
        # logger.debug("logger initialized")

        # Mandatory options first

        try:
            # LUSTRE

            fsname = config.get(
                'LUSTRE', 'fsname').strip()
            if fsname:
                self.lustre_fsname = fsname
            nid = config.get(
                'LUSTRE', 'nid').strip()
            if nid:
                self.lustre_nid = nid
            mgs = config.get(
                'LUSTRE', 'mgs').strip()
            if mgs:
                self.lustre_mgs = mgs
            mdt = config.get(
                'LUSTRE', 'mdt').strip()
            if mdt:
                self.lustre_mdt = mdt
            changelog_user = config.get(
                'LUSTRE', 'changelog_user').strip()
            if changelog_user:
                self.lustre_changelog_user = changelog_user
            data_mount = config.get(
                'LUSTRE', 'data_mount').strip()
            if data_mount:
                self.lustre_data_mount = data_mount
            data_path = config.get(
                'LUSTRE', 'data_path').strip()
            if data_path:
                self.lustre_data_path = data_path
            meta_basepath = config.get(
                'LUSTRE', 'meta_basepath').strip()
            if meta_basepath:
                self.lustre_meta_basepath = meta_basepath
            snapshot_create_retries = config.get(
                'LUSTRE', 'snapshot_create_retries').strip()
            if snapshot_create_retries:
                self.lustre_snapshot_create_retries \
                    = int(snapshot_create_retries)
            snapshot_home = config.get(
                'LUSTRE', 'snapshot_home').strip()
            if snapshot_home:
                self.lustre_snapshot_home = snapshot_home
            snapshot_mount_opts = config.get(
                'LUSTRE', 'snapshot_mount_opts').strip()
            if snapshot_mount_opts:
                self.lustre_snapshot_mount_opts = snapshot_mount_opts
            data_mount_opts = config.get(
                'LUSTRE', 'data_mount_opts').strip()
            if data_mount_opts:
                self.lustre_data_mount_opts = data_mount_opts
            largefile_size = config.get(
                'LUSTRE', 'largefile_size').strip()
            if largefile_size:
                self.lustre_largefile_size = int(largefile_size)
            hugefile_size = config.get(
                'LUSTRE', 'hugefile_size').strip()
            if hugefile_size:
                self.lustre_hugefile_size = int(hugefile_size)

            # SOURCE

            host = config.get(
                'SOURCE', 'host').strip()
            if host:
                self.source_host = host
            conf = config.get(
                'SOURCE', 'conf').strip()
            if conf:
                self.source_conf = conf

            # BACKUP

            rsync_command = config.get(
                'BACKUP', 'rsync_command').strip()
            if rsync_command:
                self.backup_rsync_command = rsync_command
            checksum_choice = config.get(
                'BACKUP', 'checksum_choice').strip()
            if checksum_choice:
                self.backup_checksum_choice = checksum_choice

            # SYSTEM

            nprocs = config.get(
                'SYSTEM', 'nprocs').strip()
            if not nprocs:
                self.system_nprocs = multiprocessing.cpu_count()
            else:
                self.system_nprocs = int(nprocs)
                if self.system_nprocs <= 0:
                    self.system_nprocs = 1
            sys_memory_factor = config.get(
                'SYSTEM', 'sys_memory_factor').strip()
            if not sys_memory_factor:
                self.system_sys_memory_factor = 0
            else:
                self.system_sys_memory_factor = float(sys_memory_factor)
                if self.system_sys_memory_factor <= 0.0:
                    self.system_sys_memory_factor = sys.maxsize
            user_memory_factor = config.get(
                'SYSTEM', 'user_memory_factor').strip()
            if not user_memory_factor:
                self.system_user_memory_factor = 0
            else:
                self.system_user_memory_factor = float(user_memory_factor)
                if self.system_user_memory_factor <= 0.0:
                    self.system_user_memory_factor = sys.maxsize
            ssh_config = config.get(
                'SYSTEM', 'ssh_config').strip()
            if ssh_config:
                self.system_ssh_config = ssh_config

        except Exception as err:
            try:
                self.logger.error('Error in reloading configuration: %s' % err)
            except Exception:
                pass
            raise Exception('Failed to parse configuration: %s' % err)


def get_configuration_object(conf_file=None,
                             skip_log=False,
                             verbose=False,
                             logpath=None):
    # Create configuration object

    if conf_file is None:
        conf_file = '/etc/lustrebackup.conf'

    try:
        configuration = Configuration(
            conf_file, skip_log=skip_log, verbose=verbose, logpath=logpath)
    except Exception as err:
        print_stderr("Failed to create configuration: %s" % err)
        return False

    return configuration


if '__main__' == __name__:
    conf = \
        Configuration('/etc/lustrebackup.conf', True)
