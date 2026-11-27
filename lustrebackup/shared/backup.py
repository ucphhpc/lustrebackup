#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# backup - lustre backup helpers
# Copyright (C) 2020-2026  The lustrebackup Project by the Science HPC Center at UCPH
#
# This file is part of lustrebackup.
#
# lustrebackup is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# lustrebackup is distributed in the hope that it will be useful,
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

"""This module contains various shared lustre backup helpers"""


import os
import re
import psutil
from lustrebackup.shared.defaults import backup_dirname, \
    bin_target_backup, bin_source_filediff, bin_target_filediff, \
    bin_source_filediff_zfs, bin_target_filediff_zfs, inprogress_backup_name
from lustrebackup.shared.fileio import makedirs_rec, path_join


def get_empty_backupinfo(configuration):
    """Returns empty backup info dict

    'snapshot_timestamp': int
    (timestamp of snapshot used for backup data)

    snapshot_mount: str
    (snapshot mountpoint used for backup)

    start_timestamp: int
    (Backup start time)

    end_timestamp: int
    (Backup end time)

    start_recno: int
    (Start changelog record)

    end_recno: int
    (End changelog record)

    type: str
    (FULL / DIFF)

    status: str
    ('PENDING', 'SKIPPED', RUNNING',  'COMPLETED', 'ABORTED')
    """

    result = {
        "snapshot_timestamp": 0,
        "snapshot_mount": None,
        "status": "PENDING",
        "start_timestamp": 0,
        "end_timestamp": 0,
        "start_recno": -1,
        "end_recno": -1,
        "largefile_size": -1,
    }

    return result


def inprogress_backup(configuration, verbose=False):
    """Check if backup is in progress"""
    logger = configuration.logger
    retval = False
    inprogress_filepath = path_join(
        configuration,
        configuration.lustre_meta_basepath,
        inprogress_backup_name,
    )
    if os.path.exists(inprogress_filepath):
        inprogress_target = os.readlink(inprogress_filepath)
        lustrebackup_bin_re = re.compile("^(.*/)?%s$" % bin_target_backup)
        rsync_re = re.compile("^(.*/)?rsync$")
        filediff_re = re.compile(
            "^(.*/)?(%s|%s|%s|%s)$"
            % (bin_target_filediff, bin_target_filediff_zfs,
               bin_source_filediff, bin_source_filediff_zfs))
        # Skip this process and whatever started it
        own_pids = {os.getpid()}
        own_pids.update(proc.pid for proc in psutil.Process().parents())
        lustrebackup_bin_proc = None
        rsync_proc_count = 0
        filediff_proc_count = 0
        for proc in psutil.process_iter(["pid", "cmdline"]):
            if proc.info["pid"] in own_pids:
                continue
            for ent in proc.info["cmdline"] or []:
                if lustrebackup_bin_re.fullmatch(ent):
                    lustrebackup_bin_proc = " ".join(proc.info["cmdline"])
                elif rsync_re.fullmatch(ent):
                    rsync_proc_count += 1
                elif filediff_re.fullmatch(ent):
                    filediff_proc_count += 1
        if lustrebackup_bin_proc is not None \
                or rsync_proc_count > 0 \
                or filediff_proc_count > 0:
            retval = True
            msg = (
                "Backup already in progress: %s : %s : rsync: %d, filediff: %d"
                % (lustrebackup_bin_proc,
                   inprogress_target,
                   rsync_proc_count,
                   filediff_proc_count)
            )
            logger.info(msg)
            if verbose:
                print(msg)

    return retval


def get_backuplog_path(configuration, source_timestamp):
    """Create and return backuplogpath"""
    logger = configuration.logger

    # Generate local backupmeta paths and check of they exists

    backuplog_path = path_join(
        configuration,
        configuration.lustre_meta_basepath,
        backup_dirname,
        str(source_timestamp),
        convert_utf8=False,
    )

    status = makedirs_rec(configuration, backuplog_path, accept_existing=True)
    if not status:
        logger.error("Failed to create backup log path: %r" % backuplog_path)
        return None

    return backuplog_path
