#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# source - lustre backup helpers
# Copyright (C) 2020-2025  The lustrebackup Project by the Science HPC Center at UCPH
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

"""This module contains various lustre backup source helpers"""

import os
import time
import datetime

from lustrebackup.shared.base import force_utf8, force_unicode, \
    print_stderr
from lustrebackup.shared.backup import get_empty_backupinfo, \
    inprogress_backup
from lustrebackup.shared.defaults import backup_dirname, \
    inprogress_backup_name, last_backup_name, last_backupmap_name, \
    date_format, last_snapshot_name, tmp_dirname
from lustrebackup.shared.fileio import path_join, unpickle, \
    pickle, save_json, makedirs_rec, make_symlink, release_file_lock, \
    delete_symlink, delete_file
from lustrebackup.shared.lock import acquire_backupmap_lock
from lustrebackup.shared.shell import shellexec
from lustrebackup.snapshot.client import get_snapshots, mount_snapshot, \
    umount_snapshot


def init_backup(configuration,
                verbose=False,
                ):
    """Initialize backup:, this includes:
    1) Checks if backup is already inprogress
    2) Resolve rename chains from last backup to current snapshot
    3) Mark backup inprogress
    4) mount snapshot with snapshot_timestamp
    Returns snapshot
    """
    logger = configuration.logger
    mountpoint = None
    snapshot = None
    backupinfo_filepath = None
    rel_backupinfo_filepath = None
    status = True
    backupinfo = get_empty_backupinfo(configuration)
    backupinfo['start_timestamp'] = int(time.time())
    backupinfo['status'] = 'RUNNING'
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_filepath = path_join(configuration,
                                    meta_basepath,
                                    inprogress_backup_name)
    last_backupmap_filepath = path_join(configuration,
                                        meta_basepath,
                                        last_backupmap_name)
    last_backup_filepath = path_join(configuration,
                                     meta_basepath,
                                     last_backup_name)
    backup_basepath = path_join(configuration,
                                meta_basepath,
                                backup_dirname)

    if not os.path.isdir(backup_basepath):
        status = makedirs_rec(configuration, backup_basepath)
        if not status:
            msg = "Failed to create backup basepath path: %r" \
                % backup_basepath
            logger.error(msg)
            if verbose:
                print_stderr(msg)
            return (False, None)

    lock = acquire_backupmap_lock(configuration)
    if not lock:
        msg = "Failed to acquire backupmap lock"
        logger.error(msg)
        if verbose:
            print_stderr(msg)
        return (False, None)

    retval = inprogress_backup(configuration,
                               verbose=verbose)
    if retval:
        msg = "Backup already in progress"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (False, None)

    # Check if we already backed up from newest backupmap

    if status \
            and os.path.exists(last_backupmap_filepath) \
            and os.path.exists(last_backup_filepath):
        last_backupmap_timestamp \
            = int(os.path.basename(
                force_unicode(os.readlink(last_backupmap_filepath)))
                .replace('.pck', ''))
        last_backup_timestamp \
            = int(os.path.basename(
                force_unicode(os.readlink(last_backup_filepath)))
                .replace('.pck', ''))
        if last_backupmap_timestamp == last_backup_timestamp:
            status = False
            msg = "No new backupmap found, latest: %s" \
                % last_backup_timestamp
            logger.info(msg)
            if verbose:
                print_stderr(msg)

    # Load backupmap

    if status:
        backupmap = unpickle(configuration, last_backupmap_filepath)
        if not backupmap:
            status = False
            msg = "Failed to load last backupmap from: %r" \
                % last_backupmap_filepath
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    # Resolve snapshot timestamp

    if status:
        bm_snapshot_timestamps = backupmap.get('snapshot_timestamps', [])
        if bm_snapshot_timestamps:
            # Use newest snapshot timestamp
            snapshot_timestamp = bm_snapshot_timestamps[0]
            snapshot_datestr \
                = datetime.datetime.fromtimestamp(snapshot_timestamp) \
                .strftime(date_format)
            logger.debug("Using snapshot timestamp: %d (%s)"
                         % (snapshot_timestamp, snapshot_datestr))
        else:
            status = False
            msg = "Failed to resolve backupmap snapshot timestamps from: %r" \
                % last_backupmap_filepath
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    # Resolve snapshot

    if status:
        snapshots = get_snapshots(configuration,
                                  snapshot_filename=last_snapshot_name,
                                  before_timestamp=snapshot_timestamp+1,
                                  after_timestamp=snapshot_timestamp-1)
        snapshot = snapshots.get(snapshot_timestamp, {})
        if snapshot:
            backupinfo['snapshot_timestamp'] = snapshot_timestamp
        else:
            status = False
            msg = "Failed to resolve snapshot %d (%s): %s" \
                % (snapshot_timestamp, snapshot_datestr, snapshots)
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    if status:
        # NOTE: umount is performed by set_backup_done
        (mountpoint, _) = mount_snapshot(configuration,
                                         snapshot,
                                         postfix='inprogress_backup')
        if mountpoint:
            backupinfo['snapshot_mount'] = mountpoint
        else:
            status = False
            msg = "Failed to mount snapshot: %d (%s)" \
                % (snapshot_timestamp, snapshot_datestr)
            logger.error(msg)
            if verbose:
                print_stderr(msg)
            logger.debug("Failed to mount snapshot: %s" % snapshot)

    # Fill backupinfo dict

    if status:
        backupinfo['start_recno'] = backupmap.get('start_recno', -1)
        backupinfo['end_recno'] = backupmap.get('end_recno', -1)
        backupinfo['largefile_size'] = backupmap.get('largefile_size', -1)
        backupinfo['hugefile_size'] = backupmap.get('hugefile_size', -1)

    # Save pickled backup info

    if status:
        backupinfo_filename = "%s.pck" % snapshot_timestamp
        backupinfo_filepath = path_join(configuration,
                                        backup_basepath,
                                        backupinfo_filename)
        status = pickle(configuration,
                        backupinfo,
                        backupinfo_filepath)
        if not status:
            msg = "Failed to save backup info: %r" \
                % backupinfo_filepath
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    # Create inprogress symlink to pickled backup info

    if status:
        rel_backupinfo_filepath = path_join(configuration,
                                            backup_dirname,
                                            backupinfo_filename)
        status = make_symlink(configuration,
                              rel_backupinfo_filepath,
                              inprogress_filepath,
                              working_dir=meta_basepath,
                              force=True)
        if not status:
            msg = "Failed to create link %r -> %r" \
                % (rel_backupinfo_filepath,
                   backupinfo_filepath)
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    # Save pickled backup info to json

    if status:
        backupinfo_filepath_json = path_join(configuration,
                                             backup_basepath,
                                             "%s.json" % snapshot_timestamp)
        status = save_json(configuration,
                           backupinfo,
                           backupinfo_filepath_json)
        if not status:
            msg = "Failed to save json file: %r" \
                % backupinfo_filepath_json
            logger.error(msg)
            if verbose:
                print_stderr(msg)

    # On fail umount snapshot if we mounted it

    if not status and mountpoint:
        umount_snapshot(configuration,
                        snapshot,
                        postfix='inprogress_backup')

    # Release lock

    lock_status = release_file_lock(configuration, lock)
    if not lock_status:
        status = False
        msg = "Failed to release backupmap lock"
        logger.error(msg)
        if verbose:
            print_stderr(msg)

    return (status,
            force_unicode(backupinfo_filepath))


def abort_backup(configuration):
    """Aborts backup in progress, update last_backupmap
    with backupmap from in-progress-backup to take the backupmap
    for the aborted backup into account.
    Unmounts active snapshot"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_filepath = path_join(configuration,
                                    meta_basepath,
                                    inprogress_backup_name)
    status = True
    abort_snapshots = {}

    # Acquire lock

    lock = acquire_backupmap_lock(configuration)
    if not lock:
        logger.error("Failed to acquire backupmap lock")
        return False

    # Load inprogress backup info

    if os.path.exists(inprogress_filepath):
        backupinfo = unpickle(configuration,
                              inprogress_filepath)
        if not backupinfo:
            status = False
            logger.error("Failed to load backup info from: %r"
                         % inprogress_filepath)
        bi_snapshot_timestamp = backupinfo.get('snapshot_timestamp', -1)
        if bi_snapshot_timestamp == -1:
            status = False
            logger.error("Missing timestamp in backupinfo: %r"
                         % inprogress_filepath)

        snapshots = get_snapshots(configuration,
                                  snapshot_filename=last_snapshot_name,
                                  before_timestamp=bi_snapshot_timestamp+1,
                                  after_timestamp=bi_snapshot_timestamp-1)
        abort_snapshots[bi_snapshot_timestamp] \
            = snapshots.get(bi_snapshot_timestamp, {})
        if not abort_snapshots[bi_snapshot_timestamp]:
            status = False
            logger.error("Failed to extract snapshot from: %r"
                         % inprogress_filepath)
        if status:
            if backupinfo.get('status', '') == 'RUNNING':
                backupinfo['status'] = 'ABORTED'
            status = pickle(configuration, backupinfo, inprogress_filepath)
            if not status:
                logger.error("Failed to save backup info: %r"
                             % inprogress_filepath)

    if status and not abort_snapshots:
        logger.info("No backup in progress")

    # Umount active snapshot(s)

    if status:
        for snapshot in abort_snapshots.values():
            status = umount_snapshot(configuration,
                                     snapshot,
                                     postfix='inprogress_backup',
                                     force=True)
            if not status:
                logger.warning("Failed to umount snapshot: %s"
                               % snapshot)

    # Remove inprogress link

    if status:
        if os.path.exists(inprogress_filepath):
            status = delete_symlink(
                configuration,
                inprogress_filepath,
                allow_broken_symlink=False)
            if not status:
                logger.error("Failed to remove inprogress link: %r"
                             % inprogress_filepath)

    # Release lock

    lock_status = release_file_lock(configuration, lock)
    if not lock_status:
        status = False
        logger.error("Failed to release backupmap lock")

    return status


def backup_done(configuration,
                end_timestamp=-1):
    """Mark backup as done and create latest_backup link"""
    logger = configuration.logger
    status = True
    rel_backup_filepath = ''
    last_backup_filepath = ''
    if end_timestamp == -1:
        end_timestamp = int(time.time())

    meta_basepath = configuration.lustre_meta_basepath
    inprogress_filepath = path_join(configuration,
                                    meta_basepath,
                                    inprogress_backup_name)
    last_backup_linkdest = path_join(configuration,
                                     meta_basepath,
                                     last_backup_name)
    backup_snapshot = None
    lock = acquire_backupmap_lock(configuration)
    if not lock:
        logger.error("Failed to acquire backupmap lock")
        return False

    # Resolve backupinfo file from inprogress link

    if os.path.islink(inprogress_filepath):
        rel_backup_filepath = os.readlink(inprogress_filepath)
        last_backup_filepath = path_join(configuration,
                                         meta_basepath,
                                         rel_backup_filepath)
    else:
        status = False
        logger.info("backup not in progress")

    # Load backup info dict

    if status:
        backupinfo = unpickle(configuration, inprogress_filepath)
        if not backupinfo:
            status = False
            logger.error("Failed to load backup info from: %r"
                         % inprogress_filepath)
        backupinfo['end_timestamp'] = end_timestamp
        backupinfo['status'] = 'FINISHED'

    if status \
            and backupinfo.get('status', '') == 'FINISHED':
        snapshot_timestamp = backupinfo.get('snapshot_timestamp', -1)
        snapshots = get_snapshots(configuration,
                                  snapshot_filename=last_snapshot_name,
                                  before_timestamp=snapshot_timestamp+1,
                                  after_timestamp=snapshot_timestamp-1)
        backup_snapshot = snapshots.get(snapshot_timestamp, -1)
        if not backup_snapshot:
            status = False
            logger.error("Failed to find snapshot with timestamp: %d"
                         % snapshot_timestamp)

    # Update backup info dict

    if status:
        status = pickle(configuration, backupinfo, last_backup_filepath)
        if not status:
            logger.error("Failed to save backup info: %r"
                         % last_backup_filepath)

        last_backup_filepath_json = last_backup_filepath.replace(
            force_utf8(".pck"),
            force_utf8(".json"))
        status = save_json(configuration, backupinfo,
                           last_backup_filepath_json)
        if not status:
            logger.error("Failed to save backup info json: %r"
                         % last_backup_filepath_json)

    # Create last backup link

    if status:
        status = make_symlink(configuration,
                              rel_backup_filepath,
                              last_backup_linkdest,
                              working_dir=meta_basepath,
                              force=True)
        if not status:
            logger.error("Failed to create link %r -> %r"
                         % (rel_backup_filepath,
                            last_backup_linkdest))

    if status:
        end_recno = backupinfo.get('end_recno', 0)
        # Clear changelog up till processed end recno
        # NOTE: We currently do not allow a complete clear (end_recno=0)
        if end_recno > 0:
            command = "lfs changelog_clear %s-%s %s %d" \
                % (configuration.lustre_fsname, configuration.lustre_mdt,
                    configuration.lustre_changelog_user,
                    end_recno)
            t1 = time.time()
            (rc, _, err) = shellexec(configuration, command)
            t2 = time.time()
            if rc == 0:
                logger.info("Cleared changelog for fs: %r"
                            % configuration.lustre_fsname
                            + ", user: %r, in %d secs"
                            % (configuration.lustre_changelog_user,
                               t2-t1))
            else:
                status = False
                logger.info("Failed clear changelog for fs: %r"
                            % configuration.lustre_fsname
                            + ", user: %r, err: %s"
                            % (configuration.lustre_changelog_user,
                               err))

    # Cleanup tempdir

    if status:
        tmp_filepath = path_join(configuration,
                                 meta_basepath,
                                 tmp_dirname,
                                 convert_utf8=False)
        if os.path.isdir(tmp_filepath):
            with os.scandir(tmp_filepath) as it:
                for entry in it:
                    if entry.name.startswith("filediff.attr."):
                        status = delete_file(configuration, entry.path)
                        if not status:
                            break

    # Remove inprogress symlink

    if status:
        status = delete_symlink(configuration,
                                inprogress_filepath,
                                allow_broken_symlink=False)

    # Umount backup_snapshot if possible
    # NOTE: 'cleanup_snapshot_mounts' is done separately
    #       as this is a slow task
    if backup_snapshot:
        umount_snapshot(configuration,
                        backup_snapshot,
                        postfix='inprogress_backup')

    # Release lock

    lock_status = release_file_lock(configuration, lock)
    if not lock_status:
        status = False
        logger.error("Failed to release backupmap lock")

    return status
