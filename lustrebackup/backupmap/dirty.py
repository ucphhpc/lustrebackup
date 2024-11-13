#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# dirty - lustre backup helpers
# Copyright (C) 2020-2024  The lustrebackup Project by the Science HPC Center at UCPH
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

"""This module contains various helpers used to keep track of backupmap
dirty files from lustre snapshots and their changelogs.
The dirty backup map is used by the target backup program to select
which largefiles to transfer"""

import os
import stat
import re

from lustrebackup.shared.base import __hash
from lustrebackup.shared.defaults import backupmap_dirname, \
    backupmap_merged_dirname
from lustrebackup.shared.fileio import path_join, unpickle
from lustrebackup.shared.lustre import lfs_data_version, lfs_path2fid,\
    lfs_fid2path


def update_dirty(configuration,
                 dirty,
                 modified,
                 last_backup_snapshot,
                 last_backup_snapshot_basepath,
                 snapshot_basepath,
                 snapshot_timestamp,
                 pid,
                 idx,
                 nprocs,):
    """Check if files that was dirty in last backup are still dirty.
    This happens without any traces in the changelog
    if data is still in the (client) cache when snapshots are made
    or if files are keept open by the client through several backup
    iterations.
    """
    logger = configuration.logger
    lfs_live_flush = True
    live_basepath = configuration.lustre_data_mount
    lbs_timestamp = last_backup_snapshot.get('timestamp', -1)
    result = {'last_count': 0,
              'skipped_count': 0,
              'updated_count': 0,
              'renamed_count': 0,
              'deleted_count': 0,
              'error': None,
              }
    if lbs_timestamp == 0:
        logger.warning("%d.%d: update_dirty"
                       % (idx, pid)
                       + " found no last backup timestamp")
        return (True, result)

    meta_basepath = configuration.lustre_meta_basepath

    # Backup map filepath for last backup

    lbm_merged_path = path_join(configuration,
                                meta_basepath,
                                backupmap_dirname,
                                lbs_timestamp,
                                backupmap_merged_dirname,
                                convert_utf8=False)
    if not os.path.exists(lbm_merged_path):
        logger.warning("%d.%d: update_dirty"
                       % (idx, pid)
                       + " found no last backupmap dir: %r"
                       % lbm_merged_path)
        return (True, result)

    # Current backup map filepath

    bm_merged_path = path_join(configuration,
                               meta_basepath,
                               backupmap_dirname,
                               snapshot_timestamp,
                               backupmap_merged_dirname,
                               convert_utf8=False)
    if not os.path.exists(bm_merged_path):
        msg = "update_dirty found no backupmap dir: %r" \
            % bm_merged_path
        logger.error("%d.%d: %s" % (idx, pid, msg))
        result['error'] = msg
        return (False, result)

    # Scan for last backup dirty

    dirty_re = re.compile("%d\\.[0-9]*\\.dirty\\.pck" % idx)
    lbm_dirty_filepaths = []
    with os.scandir(lbm_merged_path) as it:
        for entry in it:
            if dirty_re.fullmatch(entry.name):
                lbm_dirty_filepaths.append(entry.path)

    # Check if dirty entries from last backup are still dirty

    for lbm_dirty_filepath in lbm_dirty_filepaths:
        lbm_dirty = unpickle(configuration, lbm_dirty_filepath)
        result['last_count'] += len(lbm_dirty.keys())
        for lbm_dirty_path, lbm_dirty_values in lbm_dirty.items():
            backup_path = lbm_dirty_path
            snapshot_path = path_join(configuration,
                                      snapshot_basepath,
                                      backup_path)

            # Resolve fid for dirty entry

            backup_fid = lbm_dirty_values.get('fid', None)
            if backup_fid is None:
                msg = "update_dirty missing fid for lbm_dirty_path: %r" \
                    % bm_merged_path
                logger.warning("%d.%d: %s" % (idx, pid, msg))
                abs_lbm_dirty_path = path_join(configuration,
                                               last_backup_snapshot_basepath,
                                               lbm_dirty_path,
                                               convert_utf8=False)
                (rc, backup_fid) = lfs_path2fid(abs_lbm_dirty_path)
                logger.debug("%d.%d: lfs_path2fid: %r"
                             % (idx, pid, abs_lbm_dirty_path)
                             + ", rc: %d, path: %r"
                             % (rc, backup_fid))
                if rc != 0:
                    msg = "update_dirty failed to resolve fid" \
                        + " for lbm_dirty_path: %r" \
                        % abs_lbm_dirty_path
                    logger.error("%d.%d: %s" % (idx, pid, msg))
                    result['error'] = msg
                    return (False, result)

            # Check if entry was renamed, if renamed then
            # use fid to resolve backup path

            if not os.path.exists(snapshot_path):
                (rc, fid_path) = lfs_fid2path(snapshot_basepath,
                                              backup_fid)
                logger.debug("%d.%d: lfs_fid2path: %r : %r"
                             % (idx, pid,
                                backup_fid, snapshot_basepath)
                             + ", rc: %d, path: %s"
                             % (rc, fid_path))
                if rc == 0:
                    backup_path = fid_path
                    snapshot_path = path_join(configuration,
                                              snapshot_basepath,
                                              backup_path)
                    logger.debug("%d.%d: using renamed target backup_path: %r"
                                 % (idx, pid, backup_path)
                                 + ", snapshot_path: %r"
                                 % snapshot_path)
                    result['renamed_count'] += 1

            # Check if entry was deleted between last backup
            # and this snapshot

            if not os.path.exists(snapshot_path):
                logger.debug("%d.%d: snapshot_path does not exists: %r"
                             % (idx, pid, snapshot_path))
                logger.debug("%d.%d: No longer dirty: %r"
                             % (idx, pid, backup_path))
                result['deleted_count'] += 1
                continue

            # Get snapshot entry stats

            snapshot_stat = os.lstat(snapshot_path)
            snapshot_st_islink = stat.S_ISLNK(snapshot_stat.st_mode)
            snapshot_st_isdir = stat.S_ISDIR(snapshot_stat.st_mode)
            snapshot_st_isreg = stat.S_ISREG(snapshot_stat.st_mode)
            snapshot_st_size = int(snapshot_stat.st_size)
            snapshot_st_mtime = int(snapshot_stat.st_mtime)

            # Dirs are not dirty

            if snapshot_st_isdir:
                logger.debug("%d.%d: skipping dir entry: %r"
                             % (idx, pid, snapshot_path))
                logger.debug("%d.%d: No longer dirty: %r"
                             % (idx, pid, backup_path))
                result['skipped_count'] += 1
                continue

            # Links are not dirty

            if snapshot_st_islink:
                logger.debug("%d.%d: skipping link entry: %r"
                             % (idx, pid, snapshot_path))
                logger.debug("%d.%d: No longer dirty: %r"
                             % (idx, pid, backup_path))
                result['skipped_count'] += 1
                continue

            bidx = __hash(backup_path) % nprocs
            backup_dirpath = os.path.dirname(backup_path)
            midx = __hash(backup_dirpath) % nprocs
            lb_path = path_join(configuration,
                                last_backup_snapshot_basepath,
                                backup_path)

            # If last backup path doesn't exists then something
            # went wrong in last backupmap
            # mark dirty

            if not os.path.exists(lb_path):
                logger.error("%d.%d: Missing last backup path: %r"
                             % (idx, pid, lb_path))
                modified[midx][backup_dirpath] = modified[midx].get(
                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] \
                    = {'fid': backup_fid,
                       'size': snapshot_st_size,
                       'mtime': snapshot_st_mtime,
                       }
                result['updated_count'] += 1
                continue

            lb_stat = os.lstat(lb_path)
            lb_st_islink = stat.S_ISLNK(lb_stat.st_mode)
            lb_st_isdir = stat.S_ISDIR(lb_stat.st_mode)
            lb_st_isreg = stat.S_ISREG(lb_stat.st_mode)
            lb_st_size = int(lb_stat.st_size)
            lb_st_mtime = int(lb_stat.st_mtime)

            # If last backup path is link then something
            # went wrong in last backupmap
            # mark dirty

            if lb_st_islink:
                logger.error("%d.%d: last backup path is a link: %r"
                             % (idx, pid, lb_path))
                modified[midx][backup_dirpath] = modified[midx].get(
                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] \
                    = {'fid': backup_fid,
                       'size': snapshot_st_size,
                       'mtime': snapshot_st_mtime,
                       }
                result['updated_count'] += 1
                continue

            # If mtime changed then mark dirty

            if lb_st_mtime \
                    != snapshot_st_mtime:
                # mark as modified / dirty
                logger.debug("%d.%d: time lb != snapshot mtime:"
                             % (idx, pid)
                             + " %d != %d for %r"
                             % (lb_st_mtime,
                                 snapshot_st_mtime,
                                 snapshot_path))
                modified[midx][backup_dirpath] = modified[midx].get(
                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] = \
                    {'fid': backup_fid,
                     'size': snapshot_st_size,
                     'mtime': snapshot_st_mtime,
                     }
                result['updated_count'] += 1
                continue

            # If size changed then mark dirty

            if lb_st_size \
                    != snapshot_st_size:
                # mark as modified / dirty
                logger.debug("%d.%d: size lb != snapshot: "
                             % (idx, pid)
                             + "%d != %d for %r"
                             % (lb_st_size,
                                 snapshot_st_size,
                                 snapshot_path))
                modified[midx][backup_dirpath] = modified[midx].get(
                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] = \
                    {'fid': backup_fid,
                     'size': snapshot_st_size,
                     'mtime': snapshot_st_mtime,
                     }
                result['updated_count'] += 1
                continue

            # Size and mtime are the same check data version

            (lb_rc, lb_dataversion) = lfs_data_version(
                lb_path.decode(),
                False)
            if lb_rc != 0:
                logger.error("%d.%d: Failed to resolve"
                             % (idx, pid)
                             + " last_dataversion for: %r, rc: %d"
                             % (lb_path, lb_rc))
            (snapshot_rc, snapshot_dataversion) = lfs_data_version(
                snapshot_path.decode(),
                False)
            if snapshot_rc != 0:
                logger.error("Failed to resolve"
                             + " last_dataversion for: %r, rc: %d"
                             % (snapshot_path, snapshot_rc))
            if lb_rc != 0 or snapshot_rc != 0 \
                    or lb_dataversion != snapshot_dataversion:
                if lb_dataversion != snapshot_dataversion:
                    logger.debug("%d.%d: dataversion lb != snapshot: "
                                 % (idx, pid)
                                 + "%d != %d for %r"
                                 % (lb_dataversion,
                                     snapshot_dataversion,
                                     snapshot_path))
                modified[midx][backup_dirpath] = modified[midx].get(
                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] \
                    = {'fid': backup_fid,
                       'size': snapshot_st_size,
                       'mtime': snapshot_st_mtime,
                       }
                result['updated_count'] += 1
                continue

            # Check against live data

            if not configuration.lustre_data_mount:
                logger.debug("%d.%d: Skipping live check"
                             % (idx, pid)
                             + " No live mount point provided in conf")
                logger.debug("%d.%d: No longer dirty: %r"
                             % (idx, pid, backup_path))
                continue

            live_path = path_join(configuration,
                                  live_basepath,
                                  backup_path)
            if not os.path.exists(live_path):
                logger.debug("%d.%d: live_path does not exists: %r"
                             % (idx, pid, live_path))
                logger.debug("%d.%d: No longer dirty: %r"
                             % (idx, pid, backup_path))
                result['skipped_count'] += 1
                continue

            live_stat = os.lstat(live_path)
            live_st_islink = stat.S_ISLNK(live_stat.st_mode)
            live_st_isdir = stat.S_ISDIR(live_stat.st_mode)
            live_st_isreg = stat.S_ISREG(live_stat.st_mode)
            live_st_size = int(live_stat.st_size)
            live_st_mtime = int(live_stat.st_mtime)

            if live_st_isdir:
                logger.debug("%d.%d: Skipping live dir entry: %r"
                             % (idx, pid, live_path))
                logger.debug("%d.%d: No longer dirty: %r"
                             % (idx, pid, backup_path))
                result['skipped_count'] += 1
                continue

            # If mtime changed then skip

            if live_st_mtime \
                    != snapshot_st_mtime:
                """
                # mark as modified / dirty
                # NOTE: This should be in changelog,
                # but we also record it here for now
                modified[midx][backup_dirpath] = modified[midx].get(
                                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] = dirty[bidx].get(
                                    backup_path, 0) + 1
                """
                logger.debug("%d.%d: time live != snapshot mtime:"
                             % (idx, pid)
                             + " %d != %d for %r"
                             % (live_st_mtime,
                                 snapshot_st_mtime,
                                 snapshot_path))
                result['skipped_count'] += 1
                continue

            # If size changed then skip

            if live_st_size \
                    != snapshot_st_size:
                """
                # mark as modified / dirty
                # NOTE: This should be in changelog,
                # but we also record it here for now
                modified[midx][backup_dirpath] = modified[midx].get(
                                    backup_dirpath, 0) + 1
                dirty[bidx][backup_path] = dirty[bidx].get(
                                    backup_path, 0) + 1
                """
                logger.debug("%d.%d: size live != snapshot: "
                             % (idx, pid)
                             + "%d != %d for %r"
                             % (lb_st_size,
                                 snapshot_st_size,
                                 snapshot_path))
                result['skipped_count'] += 1
                continue

            (live_rc, live_dataversion) = lfs_data_version(
                live_path.decode(),
                lfs_live_flush)
            if live_rc == 0:
                # Only flush dirty pages to OSTs on first check
                lfs_live_flush = False
            else:
                logger.error("%d.%d: Failed to resolve"
                             % (idx, pid)
                             + " last_dataversion for: %r, rc: %d"
                             % (live_path, live_rc))
            if live_rc != 0 \
                    or live_dataversion != snapshot_dataversion:
                if live_dataversion != snapshot_dataversion:
                    logger.debug("%d.%d: dataversion live != snapshot: "
                                 % (idx, pid)
                                 + "%d != %d for %r"
                                 % (live_dataversion,
                                     snapshot_dataversion,
                                     snapshot_path))
                    modified[midx][backup_dirpath] = modified[midx].get(
                        backup_dirpath, 0) + 1
                    dirty[bidx][backup_path] \
                        = {'fid': backup_fid,
                            'size': snapshot_st_size,
                            'mtime': snapshot_st_mtime,
                           }
                continue

            result['skipped_count'] += 1
            logger.debug("%d.%d: No longer dirty: %r"
                         % (idx, pid, backup_path))

    return (True, result)
