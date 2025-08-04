#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# backupmap - lustre backup helpers
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

"""This module contains various helpers used to generate a backup map
from lustre snapshots and their changelogs. The backup map is used
by the target backup program to select which dirs/files to transfer"""

import os
import re
import time
import datetime
import multiprocessing
import stat
import traceback
import psutil

from lustrebackup.backupmap.dirty import update_dirty
from lustrebackup.backupmap.merge import merge_backupmap
from lustrebackup.shared.base import __hash, print_stderr, force_unicode
from lustrebackup.shared.backup import get_empty_backupinfo, \
    inprogress_backup
from lustrebackup.shared.configuration import get_configuration_object
from lustrebackup.shared.defaults import bin_source_map, \
    backupmap_dirname, inprogress_backupmap_name, last_backupmap_name, \
    backupmap_resolved_dirname, snapshot_dirname, \
    backupmap_merged_dirname, last_backup_name, date_format, \
    changelog_dirname, changelog_filtered_dirname
from lustrebackup.shared.lock import acquire_backupmap_lock
from lustrebackup.shared.logger import Logger
from lustrebackup.shared.shell import shellexec
from lustrebackup.shared.fileio import delete_file, pickle, unpickle, \
    make_symlink, path_join, save_json, release_file_lock, makedirs_rec
from lustrebackup.shared.lustre import lfs_fid2path, lfs_data_version
from lustrebackup.backupmap.changelog import create_changemap
from lustrebackup.snapshot.client import mount_snapshot, \
    umount_snapshot, get_last_snapshot, get_snapshots


def __get_empty_backupmap(configuration):
    """Returns empty backupmap dict
   'snapshot_timestamps': list
    (Ordered timestamps (newest first)
    (of snapshots used to generate backupmap)

    'start_recno': int
    (Start changelog record)

    'end_recno': int
    (End changelog record)
    """

    result = {'snapshot_timestamps': [],
              'start_recno': -1,
              'end_recno': -1,
              }

    return result


def __mount_live_data(configuration):
    """Mount live data and return a tuple:
    (mountpoint, umount), where umount is a bool telling
    if caller is responsible for umount
    (mount point didn't exist in advance)"""
    logger = configuration.logger
    mountpoint = configuration.lustre_data_mount
    if not mountpoint:
        logger.debug("No live mount point provided in conf")
        return (None, False)

    if not os.path.exists(mountpoint):
        status = makedirs_rec(configuration,
                              mountpoint)
        if not status:
            logger.error("Failed to live mountpoint: %r"
                         % mountpoint)
            return (None, False)
    findmnt_cmd = "findmnt %r" % mountpoint
    (rc, _, _) = shellexec(configuration, findmnt_cmd)
    if rc == 0:
        logger.debug("Live mount already mounted: %r"
                     % mountpoint)
        return (mountpoint, False)

    mount_opts = "-o ro,noatime"
    if configuration.lustre_data_mount_opts:
        mount_opts += ",%s" % configuration.lustre_data_mount_opts
    mount_cmd = "mount -t lustre %s %s:/%s %s" \
        % (mount_opts,
           configuration.lustre_nid,
           configuration.lustre_fsname,
           configuration.lustre_data_mount)
    # logger.debug(mount_cmd)
    (rc, _, err) = shellexec(configuration, mount_cmd)
    if rc == 0:
        result = (mountpoint, True)
    else:
        logger.error("Failed to mount live: %r, error: %s"
                     % (mount_cmd, err))
        result = (None, False)

    return result


def __umount(configuration, mounted):
    """Umount snapshots and live data"""
    retval = True
    umounted = []
    mounted_snapshots = mounted.get('snapshots', [])
    for snapshot in mounted_snapshots:
        (status, mountpoint) = umount_snapshot(configuration,
                                               snapshot,
                                               postfix='inprogress_backupmap')
        if status:
            umounted.append(mountpoint)
        else:
            retval = False

    return (retval, umounted)


def __fid2path(configuration,
               snapshot,
               fid,
               idx,
               pid,
               cache=None,
               ):
    """Resolve path from fid based on snapshot mounts"""
    result = None
    logger = configuration.logger
    snapshot_timestamp = snapshot.get('timestamp', 0)
    if cache is not None:
        result = cache.get(snapshot_timestamp, {}).get(fid, None)
        if result:
            return result

    if snapshot.get('status', '') == 'failed':
        # If snapshot is marked as failed, continue silently
        return None

    (mountpoint, _) = mount_snapshot(configuration,
                                     snapshot,
                                     postfix='inprogress_backupmap')
    if not mountpoint:
        logger.error("__fid2path: %d.%d: Missing snapshot mountpoint: %s"
                     % (idx, pid, snapshot))
        return None

    try:
        (rc, path) = lfs_fid2path(mountpoint, fid)
        logger.debug("%d.%d: fid: %r, snapshot (%d): %r"
                     % (idx, pid,
                        fid, snapshot['timestamp'], mountpoint)
                     + ", rc: %d, path: %s"
                     % (rc, path))
        if rc == 0:
            result = path
            if cache is not None and snapshot_timestamp > 0:
                cache_ent = cache.get(snapshot_timestamp, {})
                cache_ent[fid] = result
                cache[snapshot_timestamp] = cache_ent
    except Exception as err:
        result = None
        logger.error("__fid2path: %d.%d: fid: %r, mountpount: %r, error: %s"
                     % (idx, pid, fid, mountpoint, err))

    return result


def __update_backupmap_worker(conf_file,
                              last_backup_snapshot_basepath,
                              snapshot_basepath,
                              changemap_filepaths,
                              backupmap_resolved_path,
                              last_backup_snapshot,
                              ordered_snapshots,
                              snapshot_timestamp,
                              main_pid,
                              idx,
                              nprocs,):
    """multiprocessing worker for mapping changelog changes
    to backup actions"""
    result = {'tfid_count': 0,
              'tfid_resolved': 0,
              'renamed': 0,
              'modified': 0,
              'missing': 0,
              'dirty': 0,
              'unchanged': 0,
              'dirty_update': None,
              'error': None}
    try:
        # Use separate log file for changes worker

        configuration = get_configuration_object(conf_file=conf_file,
                                                 skip_log=True)

        # User local_logger to log path resolves for each timestamp

        worker_log_filepath = path_join(configuration,
                                        configuration.lustre_meta_basepath,
                                        backupmap_dirname,
                                        "%d.log" % snapshot_timestamp)

        worker_logger_obj = Logger(configuration.loglevel,
                                   logfile=worker_log_filepath,
                                   app='__update_backupmap_worker.%d.%d'
                                   % (snapshot_timestamp, idx))
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result['error'] = err
        return (False, result)

    try:
        # FID cache, only used for parent entries,
        # as tfids are grouped already

        pid = os.getpid()
        fid_cache = {}
        last_fid_cache = {}

        modified = {}
        renamed = {}
        missing = {}
        dirty = {}
        for i in range(nprocs):
            modified[i] = {}
            missing[i] = {}
            dirty[i] = {}
            renamed[i] = {}
        logger.debug("checkpoint changemap_filepaths: %s" %
                     changemap_filepaths)
        for changemap_file in changemap_filepaths:
            changemap = unpickle(
                configuration, changemap_file, allow_missing=False)
            for tfid in changemap.keys():
                result['tfid_count'] += 1
                # Resolve target path (tpath) from target fid (tfid)
                # NOTE: tfid == [0:0x0:0x0] is RENAME
                logger.debug("%d.%d: checkpoint tfid (%d/%d): %s"
                             % (idx, pid, result['tfid_count'],
                                result['unchanged'], tfid))
                if tfid == "[0:0x0:0x0]":
                    if not last_backup_snapshot_basepath:
                        logger.warning(
                            "No last backup snapshot, skipping RENAME")
                        continue
                    tidx = __hash(tfid) % nprocs
                    for fop in changemap[tfid]:
                        ops = fop.get('ops', {}).keys()
                        sfid = list(fop.get('sfid', {}).keys())[0]
                        recno = list(fop.get('sfid', {}).values())[0]
                        if len(ops) > 1:
                            logger.warning("%d.%d: Unexpected tfid: %rr OP: %s"
                                           % (idx, pid, tfid, str(ops)))
                            continue
                        src_path = ''
                        dest_path = ''
                        # NOTE: sfid from last backup snapshot is source dir,
                        #       sfid from current snapshot is target dir
                        #       if src_path can't be resolved it's a new entry
                        #       and we do not rename on the target
                        #       if dest_path can't be resolved then entry
                        #       was deleted and we do not rename
                        src_path = __fid2path(configuration,
                                              last_backup_snapshot,
                                              sfid,
                                              idx,
                                              pid,
                                              cache=last_fid_cache,
                                              )
                        dest_path = __fid2path(configuration,
                                               ordered_snapshots[0],
                                               sfid,
                                               idx,
                                               pid,
                                               cache=fid_cache,
                                               )
                        logger.debug("%d.%d: Found rename entry: sfid: %s"
                                     % (idx, pid, sfid)
                                     + " : %r -> %r"
                                     % (src_path, dest_path))
                        if src_path is None or dest_path is None \
                                or src_path == dest_path:
                            logger.info("%d.%d: Skipping rename for: "
                                        % (idx, pid)
                                        + "sfid: %s: %r -> %r"
                                        % (sfid, src_path, dest_path))
                        else:
                            logger.debug("%d.%d: Rename entry: sfid: %s"
                                         % (idx, pid, sfid)
                                         + " : %r -> %r"
                                         % (src_path, dest_path))
                            renamed[tidx][sfid] = {'src_path': src_path,
                                                   'dest_path': dest_path,
                                                   'recno': recno}
                else:
                    backup_path = __fid2path(configuration,
                                             ordered_snapshots[0],
                                             tfid,
                                             idx,
                                             pid,
                                             cache=fid_cache,
                                             )
                    logger.debug("%d.%d: tfid: %r, backup_path: %r"
                                 % (idx, pid, tfid, backup_path))

                    # If missing backup_path (tpath) then try to resolve ppath

                    if not backup_path:
                        # NOTE: Resolve from last change
                        fschange = changemap[tfid][-1]
                        fsops = fschange.get('ops', {})
                        pfid = ""
                        pfid_list = list(fschange.get('pfid', {}).keys())
                        if pfid_list:
                            logger.debug("%d.%d: Try to resolve backupmap"
                                         % (idx, pid)
                                         + " from pfid_list: %s"
                                         % (pfid_list))
                            pfid = pfid_list[0]
                            backup_path = __fid2path(configuration,
                                                     ordered_snapshots[0],
                                                     pfid,
                                                     idx,
                                                     pid,
                                                     cache=fid_cache,
                                                     )
                            # If parent is not found in this snapshot
                            # look in last backup snapshot
                            if not backup_path:
                                backup_path = __fid2path(configuration,
                                                         last_backup_snapshot,
                                                         pfid,
                                                         idx,
                                                         pid,
                                                         cache=fid_cache,
                                                         )
                        if not backup_path:
                            logger.error("%d.%d: tfid: %s failed to resolve"
                                         % (idx, pid, tfid)
                                         + ", using pfid: %s" % pfid
                                         + ", ppath: %s, fops: %s"
                                         % (backup_path, fsops))
                            tidx = __hash(tfid) % nprocs
                            missing[tidx][tfid] = fschange
                            continue

                    # Resolve midx and modified_path

                    abs_backup_path = path_join(configuration,
                                                snapshot_basepath,
                                                backup_path)

                    # if deleted then mark first existing parrent as modified

                    tmp_abs_backup_path = abs_backup_path
                    tmp_modified_path = backup_path
                    if not os.path.exists(tmp_abs_backup_path):
                        while tmp_modified_path \
                                and not os.path.isdir(tmp_abs_backup_path):
                            tmp_modified_path = os.path.dirname(
                                tmp_modified_path)
                            tmp_abs_backup_path = path_join(configuration,
                                                            snapshot_basepath,
                                                            tmp_modified_path)
                        modified_path = tmp_modified_path
                        if not modified_path:
                            modified_path = '/'
                        midx = __hash(modified_path) % nprocs
                        modified[midx][modified_path] = modified.get(
                            modified_path, 0) + 1
                        logger.info("%d.%d: Missing: %r"
                                    % (idx, pid, abs_backup_path)
                                    + ", update parrent path: %r"
                                    % modified_path)
                        continue

                    # Get stats

                    snapshot_stat = os.lstat(abs_backup_path)
                    st_islink = stat.S_ISLNK(snapshot_stat.st_mode)
                    st_isdir = stat.S_ISDIR(snapshot_stat.st_mode)
                    st_isreg = stat.S_ISREG(snapshot_stat.st_mode)
                    st_size = int(snapshot_stat.st_size)
                    st_mtime = int(snapshot_stat.st_mtime)

                    if st_isdir:
                        modified_path = backup_path
                    else:
                        modified_path = os.path.dirname(backup_path)

                    bidx = __hash(backup_path) % nprocs
                    midx = __hash(modified_path) % nprocs

                    # If not in last backupmap markl as modified
                    # and dirty if it's a file

                    if not last_backup_snapshot_basepath:
                        logger.debug("%d.%d: No last backup, mark modified: %r"
                                     % (idx, pid, backup_path))
                        modified[midx][modified_path] = modified.get(
                            modified_path, 0) + 1

                        if st_isreg:
                            dirty[bidx][backup_path] \
                                = {'fid': tfid,
                                   'size': st_size,
                                   'mtime': st_mtime,
                                   }

                    # Resolve last backup path

                    last_abs_backup_path = None
                    if last_backup_snapshot_basepath:
                        last_backup_path = __fid2path(configuration,
                                                      last_backup_snapshot,
                                                      tfid,
                                                      idx,
                                                      pid
                                                      )
                        if last_backup_path:
                            last_abs_backup_path \
                                = path_join(configuration,
                                            last_backup_snapshot_basepath,
                                            last_backup_path)
                        logger.debug("%d.%d: tfid: %s, last_backup_path: %r"
                                     % (idx, pid, tfid, last_backup_path)
                                     + ", last_abs_backup_path: %r"
                                     % last_abs_backup_path)

                    # New entry

                    if last_abs_backup_path is None:
                        modified[midx][modified_path] = modified.get(
                            modified_path, 0) + 1
                        logger.debug("%d.%d: New entry midx: %d in path: %r"
                                     % (idx, pid, midx, abs_backup_path)
                                     + ", update path: %r"
                                     % modified_path)
                        if st_isreg:
                            dirty[bidx][backup_path] \
                                = {'fid': tfid,
                                    'size': st_size,
                                    'mtime': st_mtime,
                                   }
                        continue

                    # Get last backup snapshot stats

                    last_snapshot_stat = os.lstat(last_abs_backup_path)
                    last_st_isreg = stat.S_ISREG(last_snapshot_stat.st_mode)
                    last_st_size = int(last_snapshot_stat.st_size)
                    last_st_mtime = int(last_snapshot_stat.st_mtime)
                    last_st_isreg = stat.S_ISREG(snapshot_stat.st_mode)

                    # Modified entry: mtime

                    if last_st_mtime != st_mtime:
                        logger.debug("%d.%d: Modified entry midx: %d"
                                     % (idx, pid, midx)
                                     + " last_mtime: %d, mtime: %d, path: %r"
                                     % (last_snapshot_stat.st_mtime,
                                        snapshot_stat.st_mtime,
                                        backup_path))
                        modified[midx][modified_path] = modified.get(
                            modified_path, 0) + 1
                        if st_isreg:
                            dirty[bidx][backup_path] \
                                = {'fid': tfid,
                                    'size': st_size,
                                    'mtime': st_mtime,
                                   }
                        continue

                    # Modified entry: size

                    if last_st_size != st_size:
                        logger.debug("%d.%d: Modified entry midx: %d"
                                     % (idx, pid, midx)
                                     + " last_size: %d, size: %d, path: %r"
                                     % (last_snapshot_stat.st_size,
                                        snapshot_stat.st_size,
                                        backup_path))
                        modified[midx][modified_path] = modified.get(
                            modified_path, 0) + 1
                        if st_isreg:
                            dirty[bidx][backup_path] \
                                = {'fid': tfid,
                                    'size': st_size,
                                    'mtime': st_mtime,
                                   }
                        continue

                    # Modified file: dataversion

                    logger.debug("%d.%d: snapshot_stat is dir: %s : %s"
                                 % (idx, pid, abs_backup_path,
                                    st_isdir))

                    if st_isreg:
                        logger.debug("%d.%d: last_abs_backup_path: %s"
                                     % (idx, pid, type(last_abs_backup_path)))
                        (rc, last_dataversion) = lfs_data_version(
                            last_abs_backup_path.decode(), False)
                        if rc != 0:
                            last_dataversion = -1
                            logger.error("Failed to resolve"
                                         + " last_dataversion for: %r, rc: %d"
                                         % (last_abs_backup_path, rc))
                        logger.debug("%d.%d: last_abs_backup_path: %s"
                                     % (idx, pid, last_abs_backup_path)
                                     + ", last_dataversion: %d"
                                     % (last_dataversion))
                        (rc, dataversion) = lfs_data_version(
                            abs_backup_path.decode(), False)
                        if rc != 0:
                            last_dataversion = -1
                            logger.error("Failed to resolve"
                                         + " dataversion for: %r, rc: %d"
                                         % (abs_backup_path, rc))
                        logger.debug("%d.%d: abs_backup_path: %s"
                                     % (idx, pid, abs_backup_path)
                                     + ", dataversion: %d"
                                     % dataversion)
                        if last_dataversion == -1 or dataversion == -1 \
                                or last_dataversion != dataversion:
                            logger.debug("%d.%d: Modified entry:"
                                         % (idx, pid)
                                         + "last_dataversion: %d"
                                         % last_dataversion
                                         + ", dataversion: %d"
                                         % dataversion
                                         + ", path: %r"
                                         % backup_path)
                            modified[midx][modified_path] = modified.get(
                                modified_path, 0) + 1
                            logger.debug("%d.%d: Modified: midx: %d, %r: %s"
                                         % (idx, pid, midx, modified_path,
                                            modified[midx][modified_path]))
                            dirty[bidx][backup_path] \
                                = {'fid': tfid,
                                    'size': st_size,
                                    'mtime': st_mtime,
                                   }
                            logger.debug("%d.%d: Dirty: midx: %d, %r: %s"
                                         % (idx, pid, midx, backup_path,
                                            dirty[bidx][backup_path]))
                            continue
                    result['unchanged'] += 1
                    logger.debug("%d.%d: unchanged checkpoint tfid (%d/%d)"
                                 % (idx, pid,
                                    result['tfid_count'],
                                    result['unchanged'])
                                 + " tfid: %s" % tfid)

        # Check if files modified in the last backup are still dirty

        (status, dirty_result) \
            = update_dirty(configuration,
                           dirty,
                           modified,
                           last_backup_snapshot,
                           last_backup_snapshot_basepath,
                           snapshot_basepath,
                           snapshot_timestamp,
                           pid,
                           idx,
                           nprocs,)
        if status:
            result['dirty_update'] \
                = {key: val
                    for key, val in dirty_result.items()
                   if isinstance(val, int)}
        else:
            msg = "%d.%d: Failed to update_dirty map: %s" \
                % (idx, pid, dirty_result['error'])
            raise Exception(msg)

        # TODO: Create checkpoint ?

        save_idx = 0
        for i in range(nprocs):
            result['renamed'] = result.get('renamed', 0) \
                + len(list(renamed[i].keys()))
            result['modified'] = result.get('modified', 0) \
                + len(list(modified[i].keys()))
            result['missing'] = result.get('missing', 0) \
                + len(list(missing[i].keys()))
            result['dirty'] = result.get('dirty', 0) \
                + len(list(dirty[i].keys()))

            # Save renamed

            if not renamed[i]:
                logger.debug("%d.%d: Skipping save of empty rename: %d"
                             % (pid, idx, i))
            else:
                renamed_filepath = path_join(configuration,
                                             backupmap_resolved_path,
                                             "%d.%d.%d.renamed.pck"
                                             % (idx, save_idx, i),
                                             convert_utf8=False)
                status = pickle(configuration, renamed[i], renamed_filepath)
                if not status:
                    msg = "%d.%d: Failed to save %r" \
                        % (idx, pid, renamed_filepath)
                    raise Exception(msg)

            # Save modified

            if not modified[i]:
                logger.debug("%d.%d: Skipping save of empty modified: %d"
                             % (pid, idx, i))
            else:
                modified_filepath = path_join(configuration,
                                              backupmap_resolved_path,
                                              "%d.%d.%d.modified.pck"
                                              % (idx, save_idx, i),
                                              convert_utf8=False)
                status = pickle(configuration, modified[i], modified_filepath)
                if not status:
                    msg = "%d.%d: Failed to save %r" \
                        % (idx, pid, modified_filepath)
                    raise Exception(msg)

            # Save missing

            if not missing[i]:
                logger.debug("%d.%d: Skipping save of empty missing: %d"
                             % (pid, idx, i))
            else:
                missing_filepath = path_join(configuration,
                                             backupmap_resolved_path,
                                             "%d.%d.%d.missing.pck"
                                             % (idx, save_idx, i),
                                             convert_utf8=False)
                status = pickle(configuration, missing[i], missing_filepath)
                if not status:
                    msg = "%d.%d: Failed to save %r" \
                        % (idx, pid, missing_filepath)
                    raise Exception(msg)

            # Save dirty

            if not dirty[i]:
                logger.debug("%d.%d: Skipping save of empty dirty: %d"
                             % (pid, idx, i))
            else:
                dirty_filepath = path_join(configuration,
                                           backupmap_resolved_path,
                                           "%d.%d.%d.dirty.pck"
                                           % (idx, save_idx, i),
                                           convert_utf8=False)
                status = pickle(configuration, dirty[i], dirty_filepath)
                if not status:
                    msg = "%d.%d: Failed to save %r" \
                        % (idx, pid, missing_filepath)
                    raise Exception(msg)

        result['tfid_resolved'] = result.get('renamed', 0) \
            + result.get('modified', 0)

    except Exception as err:
        result['error'] = err
        logger.error("%d.%d: %s"
                     % (idx, pid, traceback.format_exc()))
        return (False, result)

    return (True, result)


def update_backupmap(configuration,
                     snapshot,
                     backupmap,
                     changelog,
                     verbose=False
                     ):
    """Map changelog changes to backup actions"""
    logger = configuration.logger
    nprocs = configuration.system_nprocs
    bm_stats = {'tfid_count': 0,
                'tfid_resolved': 0,
                'renamed': 0,
                'modified': 0,
                'missing': 0,
                'dirty': 0,
                'unchanged': 0,
                'dirty_update': {},
                'msg': ""}
    retval = True
    mounted = {'snapshots': []}
    t1 = time.time()
    snapshot_timestamp = snapshot.get('timestamp', 0)
    meta_basepath = configuration.lustre_meta_basepath

    changemap_filtered_path = path_join(configuration,
                                        meta_basepath,
                                        changelog_dirname,
                                        snapshot_timestamp,
                                        changelog_filtered_dirname,
                                        convert_utf8=False)
    backupmap_resolved_path = path_join(configuration,
                                        meta_basepath,
                                        backupmap_dirname,
                                        snapshot_timestamp,
                                        backupmap_resolved_dirname,
                                        convert_utf8=False)
    backupmap_merged_path = path_join(configuration,
                                      meta_basepath,
                                      backupmap_dirname,
                                      snapshot_timestamp,
                                      backupmap_merged_dirname,
                                      convert_utf8=False)
    last_backup_filepath = path_join(configuration,
                                     meta_basepath,
                                     last_backup_name)
    if snapshot_timestamp == 0:
        logger.error("Failed to retrieve timestamp from snapshot: %s"
                     % snapshot)
        return False
    if not os.path.isdir(meta_basepath):
        logger.error("Missing backupmeta basepath: %r"
                     % meta_basepath)
        return False
    if not os.path.isdir(changemap_filtered_path):
        logger.error("Missing changemap path: %r"
                     % changemap_filtered_path)
        return False
    if not os.path.isdir(backupmap_resolved_path):
        status = makedirs_rec(configuration, backupmap_resolved_path)
        if not status:
            logger.error("Failed to create backupmap resolve path: %r"
                         % backupmap_resolved_path)
            return False
    if not os.path.isdir(backupmap_merged_path):
        status = makedirs_rec(configuration, backupmap_merged_path)
        if not status:
            logger.error("Failed to create backupmap merge path: %r"
                         % backupmap_merged_path)
            return False

    # Mount live data

    (live_mountpoint, _) = __mount_live_data(configuration)
    if not live_mountpoint:
        logger.error("Failed to mount live data")
        __umount(configuration, mounted)
        return False

    # Extract last backup snapshot timetamp

    if os.path.exists(last_backup_filepath):
        last_backup_dict = unpickle(configuration, last_backup_filepath)
        if not last_backup_dict:
            logger.error("Failed to retreive last backup dict: %r" %
                         last_backup_filepath)
            __umount(configuration, mounted)
            retval = False
    else:
        last_backup_dict = get_empty_backupinfo(configuration)

    last_backup_snapshot_timestamp = last_backup_dict.get(
        'snapshot_timestamp', 0)
    logger.debug('last_backup_snapshot_timestamp: %d' %
                 last_backup_snapshot_timestamp)

    # Create basepaths and mount current backupmap snapshot
    # and last backup / last large backup snapshots
    # pygdb.breakpoint.set()
    (snapshot_basepath, _) = mount_snapshot(configuration,
                                            snapshot,
                                            postfix='inprogress_backupmap')
    if not snapshot_basepath:
        logger.debug("snapshot: %s" % str(snapshot))
        logger.error("Failed to resolve snapshot mountpoint for snapshot %r"
                     % snapshot.get('snapshot_name', ''))
        __umount(configuration, mounted)
        return False
    mounted['snapshots'].append(snapshot)

    # If no last backup then use changelog timestamp

    snapshots_after_timestamp = last_backup_snapshot_timestamp
    if snapshots_after_timestamp == 0:
        snapshots_after_timestamp = changelog.get('min_timestamp', 0)
    if snapshots_after_timestamp == 0:
        logger.error("Failed to resolve changelog min_timestamp from: %s"
                     % changelog)
        __umount(configuration, mounted)
        return False

    snapshots = get_snapshots(configuration,
                              before_timestamp=snapshot_timestamp+1,
                              after_timestamp=snapshots_after_timestamp-1)
    ordered_snapshot_timestamps = sorted(snapshots.keys(), reverse=True)
    backupmap['snapshot_timestamps'] = ordered_snapshot_timestamps
    ordered_snapshots = [snapshots[timestamp]
                         for timestamp in ordered_snapshot_timestamps]
    # NOTE: Snapshots are mounted by workers,
    #       potentially all gets mounted
    mounted['snapshots'].extend(ordered_snapshots)
    last_backup_snapshot = snapshots.get(last_backup_snapshot_timestamp, {})
    last_backup_snapshot_basepath = ""
    if last_backup_snapshot:
        (last_backup_snapshot_basepath, _) \
            = mount_snapshot(configuration,
                             last_backup_snapshot,
                             postfix='inprogress_backupmap')
        if not last_backup_snapshot_basepath:
            logger.error("Failed to mount last backup snapshot  %d"
                         % last_backup_snapshot_timestamp)
            __umount(configuration, mounted)
            return False
        mounted['snapshots'].append(last_backup_snapshot)

    # Switch default logger to backupmap logger

    backupmap_log_filepath = path_join(configuration,
                                       configuration.lustre_meta_basepath,
                                       backupmap_dirname,
                                       "%d.log" % snapshot_timestamp)
    backup_logger_obj = Logger(configuration.loglevel,
                               logfile=backupmap_log_filepath,
                               app=force_unicode(backupmap_log_filepath))
    main_logger = configuration.logger
    configuration.logger = logger = backup_logger_obj.logger
    main_logger.info("Logging backupmap details to: %r"
                     % backupmap_log_filepath)

    # Resolve changemap filelist

    changemap_part_re = re.compile("[0-9]*\\.[0-9]*\\.pck")
    changemap_filepaths = {}
    for idx in range(nprocs):
        changemap_filepaths[idx] = []
    with os.scandir(changemap_filtered_path) as it:
        for entry in it:
            if changemap_part_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[0]) % nprocs
                changemap_filepaths[idx].append(entry.path)

    # multiprocessing.log_to_stderr()
    pool = multiprocessing.Pool(processes=nprocs)

    # Start worker tasks
    tasks = {}
    for idx in range(nprocs):
        task = {}
        tasks[idx] = task
        # logger.debug("%d, %d, %r" % (idx, i, merge_changemap_filepaths[idx]))
        logger.info(
            "Starting __update_backupmap_worker: %d, nprocs: %d"
            % (idx, nprocs))
        task['proc'] = pool.apply_async(__update_backupmap_worker,
                                        (configuration.config_file,
                                         last_backup_snapshot_basepath,
                                         snapshot_basepath,
                                         changemap_filepaths[idx],
                                         backupmap_resolved_path,
                                         last_backup_snapshot,
                                         ordered_snapshots,
                                         snapshot_timestamp,
                                         os.getpid(),
                                         idx,
                                         nprocs,))
    # Wait for tasks to finish

    for idx in tasks:
        task = tasks[idx]
        proc = task['proc']
        logger.info("Waiting for add changes task: %d" % idx)
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            # msg = "__update_backupmap_worker: %d finished with: " \
            #    % idx \
            #    + "status: %s and message: %s " \
            #    % (worker_status, worker_result)
            if worker_status:
                logger.info("%d: %s" % (idx, worker_result))
            else:
                logger.error("%d: %s" % (idx, worker_result))
            logger.debug("%d: %s: %s" % (idx, worker_status, worker_result))
            if worker_status:
                msg = "%d: tfid_count: %d, tfid_resolved: %d, renamed: %d" \
                    % (idx,
                       worker_result['tfid_count'],
                       worker_result['tfid_resolved'],
                       worker_result['renamed']) \
                    + ", modified: %d, 'missing': %d, 'dirty': %d" \
                    % (worker_result['modified'],
                       worker_result['missing'],
                       worker_result['dirty']) \
                    + ", unchanged: %d" \
                    % (worker_result['unchanged'])
                logger.info("update_backupmap: %s" % msg)
                if verbose:
                    print(msg)
                bm_stats['tfid_count'] += worker_result['tfid_count']
                bm_stats['tfid_resolved'] += worker_result['tfid_resolved']
                bm_stats['renamed'] += worker_result['renamed']
                bm_stats['modified'] += worker_result['modified']
                bm_stats['missing'] += worker_result['missing']
                bm_stats['dirty'] += worker_result['dirty']
                bm_stats['unchanged'] += worker_result['unchanged']
                for key, value in worker_result['dirty_update'].items():
                    bm_stats['dirty_update'][key] \
                        = bm_stats['dirty_update'].get(key, 0) + value
                if worker_result.get('error', None):
                    retval = False
                    msg = "__update_backupmap_worker: %d" % idx \
                        + " failed with error: %s" % worker_result['error']
                    logger.error(msg)
                    if verbose:
                        print_stderr("ERROR: %s" % msg)
            else:
                retval = False
                msg = "__update_backupmap_worker: %d" % idx \
                    + " failed with unknown error"
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
    t2 = time.time()
    msg = "Backupmap update dirty stats: "
    for key, value in bm_stats['dirty_update'].items():
        msg += "%s: %d, " % (key, value)
    msg = msg[:-2]
    logger.info(msg)
    if verbose:
        print(msg)

    msg = "Backupmap processed %d tfids with %d resolved paths" \
        % (bm_stats['tfid_count'],
           bm_stats['tfid_resolved']) \
        + ", %d renamed paths , %d modified paths, %d dirty files" \
        % (bm_stats['renamed'],
           bm_stats['modified'],
           bm_stats['dirty'],
           ) \
        + ", %d missing paths, %d unchanged entries in %d secs" \
        % (bm_stats['missing'],
           bm_stats['unchanged'],
           t2-t1)
    logger.info(msg)
    if verbose:
        print(msg)

    pool.terminate()

    # Terminate pool before returning on error

    if retval:
        # Merge backupmaps

        (status, mrg_stats) = merge_backupmap(configuration,
                                              backupmap_resolved_path,
                                              backupmap_merged_path,
                                              snapshot_timestamp)

        if status:
            t2 = time.time()
            msg = "Backupmap merged: %d renamed entries" \
                % mrg_stats['renamed_count'] \
                + ", %d modified dirs and %d dirty files" \
                % (mrg_stats['modified_count'],
                   mrg_stats['dirty_count']) \
                + " entries in %d secs" \
                % (t2-t1)
            logger.info(msg)
            if verbose:
                print(msg)
        else:
            retval = False
            msg = "Failed to merge backupmap"
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    # Switch default logger back to main logger

    configuration.logger = logger = main_logger

    # Umount snapshots and live data mounted by this function

    (status, _) = __umount(configuration, mounted)
    if not status:
        retval = False
        msg = "Failed to unmount: %s" % mounted
        logger.error(msg)
        if verbose:
            print_stderr(msg)

    return retval


def running_backupmap(configuration,
                      do_lock=True,
                      verbose=False):
    """Check for active backupmap, if filemarker
    is set then use psutil to check if there
    are active processes"""
    logger = configuration.logger
    retval = False
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_backupmap_filepath = path_join(configuration,
                                              meta_basepath,
                                              inprogress_backupmap_name)
    if do_lock:
        lock = acquire_backupmap_lock(configuration)
        if not lock:
            logger.error("Failed to acquire backupmap lock")
            return True

    if os.path.exists(inprogress_backupmap_filepath):
        backupmap_proc_count = 0
        bin_source_map_re = re.compile(".*%s.*"
                                       % bin_source_map)
        for pid in psutil.pids():
            try:
                proc = psutil.Process(pid)
                for ent in proc.cmdline():
                    backupmap_cmd = bin_source_map_re.fullmatch(ent)
                    if backupmap_cmd:
                        backupmap_proc_count += 1
            except psutil.NoSuchProcess:
                continue
        if backupmap_proc_count > 1:
            retval = True
            logger.info("Backupmap already in progress with %d procs"
                        % backupmap_proc_count)

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            retval = True
            logger.error("Failed to release backupmap lock")

    return retval


def __create_inprogress_backupmap(configuration,
                                  snapshot,
                                  do_lock=True):
    """Check if backupmap is already in progress,
    if not then "mark inprogress".
    This is used by snapshot cleanup to spare snapshot"""
    logger = configuration.logger
    retval = True
    meta_basepath = configuration.lustre_meta_basepath
    snapshot_timestamp = snapshot.get('timestamp', -1)
    rel_snapshot_filepath = path_join(configuration,
                                      snapshot_dirname,
                                      "%s.pck" % snapshot_timestamp)
    snapshot_filepath = path_join(configuration,
                                  meta_basepath,
                                  rel_snapshot_filepath)
    if do_lock:
        lock = acquire_backupmap_lock(configuration)
        if not lock:
            logger.error("Failed to acquire backupmap lock")
            return False

    # Check if another instance is running

    status = running_backupmap(configuration, do_lock=False)
    if status:
        retval = False
        logger.error("Another backupmap process is running")

    # Mark inprogress

    if retval:
        if os.path.isfile(snapshot_filepath):
            retval = make_symlink(configuration,
                                  rel_snapshot_filepath,
                                  inprogress_backupmap_name,
                                  working_dir=meta_basepath,
                                  force=True)
            if not retval:
                logger.error("Failed to create inprogress backupmap symlink"
                             + " (%s): %s -> %s"
                             % (meta_basepath,
                                rel_snapshot_filepath,
                                inprogress_backupmap_name))
        else:
            retval = False
            logger.error("Missing snapshot: %r" % snapshot_filepath)

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            retval = False
            logger.error("Failed to release backupmap lock")

    return retval


def __remove_inprogress_backupmap(configuration,
                                  do_lock=True):
    """Remove inprogress marker"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath

    inprogress_filepath = path_join(configuration,
                                    meta_basepath,
                                    inprogress_backupmap_name)
    if do_lock:
        lock = acquire_backupmap_lock(configuration)
        if not lock:
            logger.error("Failed to acquire backupmap lock")
            return False

    status = delete_file(configuration, inprogress_filepath)
    if not status:
        logger.error("Failed to remove inprogress backupmap marker: %r"
                     % inprogress_filepath)
    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            status = False
            logger.error("Failed to release backupmap lock")

    return status


def update(configuration, verbose=False):
    """Update backupmap"""
    logger = configuration.logger
    status = True

    # Check if backup is in progress

    status = inprogress_backup(configuration, verbose=verbose)
    if status:
        msg = "Backupmap: skipping update due to running backup"
        logger.error(msg)
        if verbose:
            print_stderr(msg)
        return False

    # Define and check for backup basedir

    meta_basepath = configuration.lustre_meta_basepath

    if not os.path.isdir(meta_basepath):
        msg = "Missing backup base dir: %r" % meta_basepath
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    backupmap_basepath = path_join(configuration,
                                   meta_basepath,
                                   backupmap_dirname)
    if not os.path.isdir(backupmap_basepath):
        status = makedirs_rec(configuration, backupmap_basepath)
        if not status:
            msg = "Failed to create backupmap basepath path: %r" \
                % backupmap_basepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False

    # Retrieve last snapshot

    snapshot = get_last_snapshot(configuration)
    if snapshot is None:
        msg = "Failed to retrieve last snapshot from: %r" \
            % meta_basepath
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Try to mark inprogress

    status = __create_inprogress_backupmap(configuration, snapshot)
    if not status:
        msg = "Failed to mark backupmap inprogress"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Load last backupmap dict if it exists

    backupmap_filepath = path_join(configuration,
                                   meta_basepath,
                                   last_backupmap_name)
    if os.path.islink(backupmap_filepath):
        backupmap_filepath = path_join(configuration,
                                       meta_basepath,
                                       os.readlink(backupmap_filepath))
    if os.path.isfile(backupmap_filepath):
        backupmap = unpickle(configuration, backupmap_filepath)
        if not isinstance(backupmap, dict):
            msg = "Failed retrieve last backup map from: %r" \
                % backupmap_filepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False
    else:
        msg = "No backupmap file found: %r, using new backupmap" \
            % backupmap_filepath
        logger.warning(msg)
        if verbose:
            print_stderr("WARNING: %s" % msg)
        backupmap = __get_empty_backupmap(configuration)

    # Extract end_recno from last backup info if it exists

    last_backup_end_recno = -1
    last_backupinfo_filepath = path_join(configuration,
                                         meta_basepath,
                                         last_backup_name)
    if os.path.exists(last_backupinfo_filepath):
        backupinfo = unpickle(configuration, last_backupinfo_filepath)
        if backupinfo:
            last_backup_end_recno = backupinfo.get('end_recno', -1)+1
        else:
            msg = "Failed retrieve last backup info from: %r" \
                % last_backupinfo_filepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False

    # Return early if no new snapshot

    timestamp = snapshot.get('timestamp', -1)
    snapshot_timestamps = backupmap.get('snapshot_timestamps', [])

    if snapshot_timestamps and timestamp > 0 \
            and snapshot_timestamps[0] == timestamp:
        datestr = datetime.datetime.fromtimestamp(snapshot_timestamps[0]) \
            .strftime(date_format)
        msg = "Already processed changelog for snapshot: %s (%s)" \
            % (snapshot.get('snapshot_name', ''), datestr)
        logger.info(msg)
        if verbose:
            print(msg)
        return __remove_inprogress_backupmap(configuration)

    # Fetch and parse changelog for latest snapshot

    if status:
        t1 = time.time()
        (status, changelog) \
            = create_changemap(configuration,
                               snapshot,
                               last_backup_end_recno)
        t2 = time.time()
        msg = "Created changemap in %f secs" % (t2-t1)
        logger.info(msg)
        if verbose:
            print(msg)

    # Create backupmap for latest snapshot

    if status:
        backupmap['start_recno'] \
            = changelog.get('min_recno', -1)
        backupmap['end_recno'] \
            = changelog.get('max_recno', -1)
        t1 = time.time()
        status = update_backupmap(configuration,
                                  snapshot,
                                  backupmap,
                                  changelog,
                                  verbose=verbose)
        t2 = time.time()
        msg = "Updated backupmap in %f secs" % (t2-t1)
        logger.info(msg)
        if verbose:
            print(msg)
    else:
        msg = "Failed to resolve changelog for snapshot: %r" \
            % snapshot.get('snapshot_name', '')
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    # Write new backupmap to disk

    if status:
        # Store largefile_size for history and for backup use
        backupmap['largefile_size'] = configuration.lustre_largefile_size
        backupmap['hugefile_size'] = configuration.lustre_hugefile_size
        backupmap_pck_relpath = path_join(configuration,
                                          backupmap_dirname,
                                          "%s.pck" % timestamp)
        backupmap_filepath = path_join(configuration,
                                       meta_basepath,
                                       backupmap_pck_relpath)
        status = pickle(configuration, backupmap, backupmap_filepath)
        if not status:
            msg = "Failed to pickle backupmap to: %r" \
                % backupmap_filepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

        # Save as json (mostly for debug)

        backupmap_filepath_json = path_join(configuration,
                                            meta_basepath,
                                            backupmap_dirname,
                                            "%s.json" % timestamp)
        status = save_json(configuration, backupmap, backupmap_filepath_json)
        if not status:
            msg = "Failed to save file: %r" \
                % backupmap_filepath_json
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Link last_backupmap to new file

    if status:
        last_backupmap_destpath = path_join(configuration,
                                            meta_basepath,
                                            last_backupmap_name)
        status = make_symlink(configuration,
                              backupmap_pck_relpath,
                              last_backupmap_destpath,
                              force=True)
        if not status:
            msg = "Failed to create link %r -> %r" \
                % (backupmap_pck_relpath,
                   last_backupmap_destpath)
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Remove running marker

    if not __remove_inprogress_backupmap(configuration):
        status = False

    return status
