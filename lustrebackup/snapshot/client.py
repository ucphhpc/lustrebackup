#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# client - lustre backup helpers
# Copyright (C) 2020-2025 The lustrebackup Project by the Science HPC Center at UCPH
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

"""This module contains various lustre snapshots helpers
used for creating, listing and mounting snapshots on the client"""

import os
import time
import datetime
import re
import psutil


from lustrebackup.shared.base import print_stderr, force_unicode
from lustrebackup.shared.defaults import last_snapshot_name, \
    snapshot_dirname, lock_dirname, last_verified_name, date_format, \
    backup_verify_dirname
from lustrebackup.shared.fileio import pickle, unpickle, \
    path_join, makedirs_rec, make_symlink, remove_dir, \
    acquire_file_lock, release_file_lock, delete_file, \
    make_temp_file
from lustrebackup.shared.lock import acquire_backupmap_lock
from lustrebackup.shared.shell import shellexec
from lustrebackup.snapshot.mgs import snapshot_list, \
    mount_snapshot_mgs, umount_snapshot_mgs, destroy_snapshot


def __add_snapshot_dict(configuration,
                        snapshot,
                        snapshot_dict):
    """Add snapshot to snapshot dict with timestamp as key"""
    logger = configuration.logger
    result = False

    snapshot_name = snapshot.get('snapshot_name', '')
    # logger.debug("snapshot_name: %s" % snapshot_name)
    timestamp_re = re.compile(".*([0-9]{10}).*")
    timestamp_ent = timestamp_re.fullmatch(snapshot_name)
    if timestamp_ent:
        timestamp = int(timestamp_ent.group(1))
        snapshot['timestamp'] = timestamp
        snapshot_dict[timestamp] = snapshot

    # If target snapshot then extract source information from comment
    source_re = re.compile("^source_fsname: ([a-z|0-9|._-]+)"
                           + ", source_snapshot: ([0-9]{10})"
                           + ", source_start_recno: ([0-9]+)"
                           + ", source_end_recno: ([0-9]+)"
                           + ", source_largefile_size: ([0-9]+)"
                           + ", source_hugefile_size: ([0-9]+)$")
    source = source_re.fullmatch(snapshot.get('comment', ''))
    if source and len(source.groups()) == 6:
        snapshot['source'] = {'fsname': source.group(1),
                              'snapshot': source.group(2),
                              'start_recno': source.group(3),
                              'end_recno': source.group(4),
                              'largefile_size': source.group(5),
                              'hugefile_size': source.group(6),
                              }

    return result


def create_snapshots_dict(configuration,
                          timestamp=None,
                          snapshot_name=None,
                          verbose=False):
    """Retrieve snapshot list from MGS and create/save snapshots dict
    if *timestamp is None then dict is returned,
    otherwise dict is pickled to disk and filename is returned"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    temp_file_fd = None
    snapshot_raw_filepath = None
    snapshot_pck_filepath = None
    snapshot_path = path_join(configuration,
                              meta_basepath,
                              snapshot_dirname,
                              convert_utf8=False)

    # Create snapshot path if it doesn't exists

    if not os.path.isdir(snapshot_path):
        status = makedirs_rec(configuration, snapshot_path)
        if not status:
            msg = "Failed to create snapshot_path: %r" \
                % snapshot_path
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return None

    # Use tempfile if no specific save timestamp were provided
    if timestamp is None:
        (temp_file_fd, snapshot_raw_filepath) \
            = make_temp_file(dir=snapshot_path)
    else:
        snapshot_raw_filepath = path_join(configuration,
                                          snapshot_path,
                                          "%d.raw"
                                          % timestamp)
        snapshot_pck_filepath = path_join(configuration,
                                          snapshot_path,
                                          "%d.pck"
                                          % timestamp)

    # Fetch snapshot list from MGS

    snapshot_info = snapshot_list(configuration,
                                  snapshot_name=snapshot_name,
                                  snapshot_list_filepath=snapshot_raw_filepath,
                                  verbose=verbose)
    if not snapshot_info:
        msg = "Failed to fetch snapshot list from MGS"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    # Create snapshots dict
    snapshots_dict = {}
    try:
        fh = open(snapshot_raw_filepath, 'r')
        # Parse raw MGS snapshot list and create dict of key/value pairs
        # Each snapshot is added to snapshots_dict with timestamp as key
        snapshot = {}
        line = fh.readline()
        while line:
            s_line = line.rstrip()
            # logger.debug("%s" % s_line)
            if not s_line:
                __add_snapshot_dict(configuration,
                                    snapshot,
                                    snapshots_dict)
                snapshot = {}
            else:
                entry = s_line.split(": ")
                snapshot[entry[0]] = ": ".join(entry[1:])
            line = fh.readline()
        __add_snapshot_dict(configuration,
                            snapshot,
                            snapshots_dict)
        fh.close()
        if temp_file_fd is not None:
            os.close(temp_file_fd)
    except Exception as err:
        msg = "Failed to parse snapshot list: %r, error: %s" \
            % (snapshot_raw_filepath, err)
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    # Save snapshots_dict if requested

    if snapshot_pck_filepath:
        retval = pickle(configuration,
                        snapshots_dict,
                        snapshot_pck_filepath)
        if not retval:
            msg = "Failed to save snapshots dict to: %r" \
                % snapshot_pck_filepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return None

        # Create symlink to last_snapshot_name

        if retval:
            rel_snapshot_info_path \
                = path_join(configuration,
                            snapshot_dirname,
                            os.path.basename(snapshot_pck_filepath))
            retval = make_symlink(configuration,
                                  rel_snapshot_info_path,
                                  last_snapshot_name,
                                  working_dir=meta_basepath,
                                  force=True)
        if not retval:
            msg = "Failed to create last snapshot symlink (%r -> %r) in %r" \
                % (rel_snapshot_info_path,
                   snapshot_pck_filepath,
                   meta_basepath)
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return None

    if snapshot_pck_filepath:
        result = snapshot_pck_filepath
    else:
        result = snapshots_dict

    return result


def get_inprogress_snapshots(configuration,
                             snapshots=None,
                             do_lock=True):
    """Return inprogress snapshots"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    if not snapshots:
        snapshots = get_snapshots(configuration)
    if do_lock:
        lock = acquire_backupmap_lock(configuration)
        if not lock:
            logger.error("Failed to acquire backupmap lock")
            return (False, None)

    # Resolve inprogress snapshots
    inprogress_source_re = re.compile("^inprogress_(.*)")
    inprogress_target_re = re.compile("^([a-z]*)/([0-9]*)\\.pck")

    retval = True
    result = {}
    with os.scandir(meta_basepath) as it:
        for entry in it:
            inprogress_source_ent = inprogress_source_re.fullmatch(entry.name)
            if inprogress_source_ent:
                inprogress_type = inprogress_source_ent.group(1)
                inprogress_target_filepath = os.readlink(entry.path)
                inprogress_target_ent \
                    = inprogress_target_re.fullmatch(
                        inprogress_target_filepath)
                if not inprogress_target_ent:
                    retval = False
                    logger.error("Malformed inprogress entry: %r"
                                 % entry.name
                                 + "type: %s, src: %r, dest: %r"
                                 % (inprogress_type,
                                    entry.path,
                                    inprogress_target_filepath))
                    break
                inprogress_timestamp = int(inprogress_target_ent.group(2))
                inprogress_snapshot = snapshots.get(inprogress_timestamp, None)
                # NOTE: If target backup is in progress,
                #       then there is no inprogress snapshot
                if inprogress_snapshot is not None:
                    result[inprogress_timestamp] = inprogress_snapshot
                else:
                    logger.warning("No inprogress snapshot found for: %r"
                                   % entry.name
                                   + "type: %s, src: %r, dest: %r"
                                   % (inprogress_type,
                                      entry.path,
                                      inprogress_target_filepath))

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            retval = False
            logger.error("Failed to release backupmap lock")

    return (retval, result)


def get_snapshots(configuration,
                  snapshot_filename=last_snapshot_name,
                  before_timestamp=int(time.time()),
                  after_timestamp=0,
                  verbose=False):
    """Return dict (stored on backupmeta client) with snapshots info"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    if snapshot_filename == last_snapshot_name:
        snapshots_filepath = path_join(configuration,
                                       meta_basepath,
                                       last_snapshot_name)
    else:
        snapshots_filepath = path_join(configuration,
                                       meta_basepath,
                                       snapshot_dirname,
                                       snapshot_filename)
    if not os.path.isfile(snapshots_filepath):
        msg = "Missing snapshots file: %r" % snapshots_filepath
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    snapshots = unpickle(configuration, snapshots_filepath)
    result = {timestamp: snapshot
              for timestamp, snapshot in snapshots.items()
              if timestamp > after_timestamp
              and timestamp < before_timestamp}

    return result


def get_last_snapshot(configuration):
    """Return last snapshot dict"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    snapshots = get_snapshots(configuration)
    if snapshots is None:
        logger.error("Failed to retrieve last snapshot from basepath: %r"
                     % meta_basepath)
        return None
    if not snapshots:
        logger.warning("No snapshots found in basepath: %r"
                       % meta_basepath)
        return None

    sorted_timestamps = sorted(snapshots.keys())
    newest_timestamp = sorted_timestamps[-1]
    snapshot = snapshots.get(newest_timestamp, None)

    return snapshot


def get_mountpoints(configuration, snapshot, postfix=os.getpid()):
    """Returns a list of active mountpoints for *snapshot* with *postfix*"""
    logger = configuration.logger
    snapshot_fsname = snapshot.get('snapshot_fsname', '')
    if not snapshot_fsname:
        logger.error("Missing snapshot_fsname in snapshot: %s"
                     % snapshot)
        return (None, False)

    result = []
    os_mounts = psutil.disk_partitions(all=True)
    for mount in os_mounts:
        if mount.fstype == "lustre" \
                and mount.device.find(snapshot_fsname) > -1:
            if postfix and mount.mountpoint.endswith(str(postfix)):
                result.append(mount.mountpoint)
            elif not postfix:
                result.append(mount.mountpoint)

    return result


def mount_snapshot(configuration, snapshot, postfix=os.getpid()):
    """Mount snapshot and return a tuple:
    (mountpoint, umount), where umount is a bool telling
    if caller is responsible for umount
    (mount point didn't exist in advance)"""

    logger = configuration.logger
    result = (None, False)

    # If MGS mount failed the return early
    if snapshot.get('client', '') == 'failed':
        logger.debug("Previous mount failed: %s" % snapshot)
        return (None, False)
    snapshot_fsname = snapshot.get('snapshot_fsname', '')
    if not snapshot_fsname:
        logger.error("Missing snapshot_fsname in snapshot: %s"
                     % snapshot)
        return (None, False)
    snapshot_name = snapshot.get('snapshot_name', '')
    if not snapshot_name:
        logger.error("Missing snapshot_name in snapshot: %s"
                     % snapshot)
        return (None, False)

    # Add postfix (default PID) to mountpouint to enable mount/umount
    # from different processes

    mountpoint = path_join(configuration,
                           configuration.lustre_snapshot_home,
                           "%s.%s"
                           % (snapshot_name,
                              postfix)).decode()
    if os.path.ismount(mountpoint):
        return (mountpoint, False)

    # Get lock before mounting

    lock_path = path_join(configuration,
                          configuration.lustre_meta_basepath,
                          lock_dirname)
    if not os.path.exists(lock_path):
        retval = makedirs_rec(configuration, lock_path)
        if not retval:
            logger.error("Failed to create lock path: %r"
                         % lock_path)
            result = (None, False)
    lock_filepath = path_join(configuration,
                              lock_path,
                              "%s.lock" % snapshot_fsname)
    try:
        lock = acquire_file_lock(configuration,
                                 lock_filepath)
        logger.debug("%d: acquired lock: %r"
                     % (os.getpid(), lock_filepath))
    except Exception as err:
        logger.error("Failed to acquire file lock: %r, err: %s"
                     % (lock_filepath, err))
        return (None, False)

    # Check if snapshot was mounted while waiting for lock

    if os.path.ismount(mountpoint):
        snapshot['status'] = 'mounted'
        snapshot['client'] = 'mounted'
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            logger.error("Failed to release lock: %r"
                         % lock_filepath)
        return (mountpoint, False)

    # Mount on MGS if needed

    if snapshot.get('status', '') != 'mount':
        mgs_retval = mount_snapshot_mgs(configuration,
                                        snapshot_name)
        if mgs_retval:
            snapshot['status'] = 'mounted'
        else:
            snapshot['status'] = 'not mount'
            snapshot['client'] = 'failed'

    # mount snapshot locally

    if snapshot.get('client', '') != 'failed':
        status = makedirs_rec(configuration, mountpoint)
        if not status:
            snapshot['client'] = 'failed'
            logger.error("Failed to create local mountpoint: %r"
                         % mountpoint)
            result = (None, False)
    if snapshot.get('client', '') != 'failed':
        mount_opts = "-o ro,noatime"
        if configuration.lustre_snapshot_mount_opts:
            mount_opts += ",%s" % configuration.lustre_snapshot_mount_opts
        mount_cmd = "mount -t lustre %s %s:/%s %s" \
            % (mount_opts,
               configuration.lustre_nid,
               snapshot_fsname,
               mountpoint)
        # logger.debug(mount_cmd)
        (mount_rc, _, err) = shellexec(configuration, mount_cmd)
        if mount_rc == 0:
            result = (mountpoint, True)
        else:
            snapshot['client'] = 'failed'
            logger.error("Failed to mount snapshot: %r, error: %s"
                         % (snapshot_fsname, err))

        # Disable Lazy Size on MDT (LSoM)
        # NOTE: LSoM updates on (RO) snapshots stalls MDT
        # Disable xattr
        # NOTE: xattr_cache=0 is experimental,
        #       Check if client xattr is actually causing
        #       mdd_attr_set calls on MDT?
        if mount_rc == 0:
            lsom_off_cmd = "lctl set_param mdc.%s-%s-*.mdc_lsom=off" \
                % (snapshot_fsname, configuration.lustre_mdt)
            (lsom_off_rc, _, lsom_off_err) = shellexec(
                configuration, lsom_off_cmd)
            logger.debug("%r: %d" % (lsom_off_cmd, lsom_off_rc))

            xattr_off_cmd = "lctl set_param llite.%s-*.xattr_cache=0" \
                % snapshot_fsname
            (xattr_off_rc, _, xattr_off_err) \
                = shellexec(configuration, xattr_off_cmd)
            logger.debug("%r: %d" % (xattr_off_cmd, xattr_off_rc))

            if lsom_off_rc == 0 and xattr_off_rc == 0:
                snapshot['client'] = 'mounted'
            else:
                snapshot['client'] = 'failed'
                if lsom_off_rc != 0:
                    logger.error("Failed %r: %d, error: %s"
                                 % (lsom_off_cmd,
                                    lsom_off_rc,
                                    lsom_off_err))
                if xattr_off_rc != 0:
                    logger.error("Failed %r: %d, error: %s"
                                 % (xattr_off_cmd,
                                    xattr_off_rc,
                                    xattr_off_err))

    lock_status = release_file_lock(configuration, lock)
    logger.debug("%d: release lock: %r, status: %s"
                 % (os.getpid(), lock_filepath, lock_status))
    if not lock_status:
        logger.error("Failed to release lock: %r"
                     % lock_filepath)

    return result


def umount_snapshot(configuration,
                    snapshot,
                    postfix=os.getpid(),
                    force=False):
    """Umount local snapshots
    and on MGS server (if required)"""
    logger = configuration.logger
    retval = True
    umounted = []

    snapshot_fsname = snapshot.get('snapshot_fsname', '')
    if not snapshot_fsname:
        logger.error("Missing snapshot_name in snapshot: %s"
                     % snapshot)
        return (False, None)
    snapshot_name = snapshot.get('snapshot_name', '')
    if not snapshot_name:
        logger.error("Missing snapshot_name in snapshot: %s"
                     % snapshot)
        return (False, None)

    mountpoints = get_mountpoints(configuration,
                                  snapshot,
                                  postfix=postfix)

    # If not mounted then return early

    if not mountpoints:
        return (True, [])

    for mountpoint in mountpoints:
        # Kill processes that has open files in mount
        if force:
            for proc in psutil.process_iter(['pid', 'open_files']):
                for open_file in proc.info['open_files']:
                    if open_file.path.startswith(mountpoint):
                        logger.debug("Trying to kill process: %d, openfile: %r"
                                     % (proc.pid, open_file.path))
                        try:
                            process = psutil.Process(proc.pid)
                            process.kill()
                            process.wait()
                        except psutil.NoSuchProcess:
                            logger.debug("no such process pid: %d"
                                         % proc.pid)
                        except Exception as err:
                            logger.error("umount_snapshot: "
                                         + " Failed to kill %d, error: %s"
                                         % (proc.pid, err))
        # umount through shell
        umount_cmd = "umount %s" % mountpoint
        (umount_rc, _, err) = shellexec(configuration, umount_cmd)
        if umount_rc == 0:
            umounted.append(mountpoint)
        elif umount_rc != 0:
            retval = False
            logger.error("Failed to umount lustre: %r snapshot: %r"
                         % (snapshot_fsname,
                            snapshot_name)
                         + ", mountpoint: %r, error: %s"
                         % (mountpoint, err))
        # remove mount dir
        status = remove_dir(configuration, mountpoint)
        if not status:
            retval = False
            logger.error("Failed to remove lustre: %r snapshot: %r"
                         % (snapshot_fsname,
                            snapshot_name)
                         + ", mountpoint: %r"
                         % mountpoint)

    # Umount snapshot on MGS if no more mountpoints on this client

    remaining_mounts = get_mountpoints(configuration,
                                       snapshot,
                                       postfix=None)
    if not remaining_mounts:
        retval = umount_snapshot_mgs(configuration,
                                     snapshot)
        if not retval:
            logger.error("Failed to MGS umount snapshot: %s"
                         % snapshot_name)
        snapshot['status'] = 'not mount'
        snapshot['client'] = 'not mount'
    else:
        logger.info("safe_umount_snapshot_mgs:"
                    + " Skipping MGS umount for %s"
                    % (snapshot_fsname)
                    + ", Found remaining snapshot mounts (%d): %s"
                    % (len(remaining_mounts),
                       remaining_mounts))

    return (retval, umounted)


def cleanup_snapshot_mounts(configuration,
                            do_lock=True,
                            verbose=False):
    """Find unused mounted snapshots and unmount them"""
    logger = configuration.logger
    retval = True
    result = {'client': [],
              'MGS': []}
    skip_timestamps = []
    current_snapshots = get_snapshots(configuration)
    if not current_snapshots:
        msg = "cleanup_snapshot_mounts: " \
            + "Failed to resolve current_snapshots"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (False, [])
    if do_lock:
        lock = acquire_backupmap_lock(configuration)
        if not lock:
            msg = "cleanup_snapshot_mounts: " \
                + "Failed to acquire backupmap lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return (False, [])
    (retval, inprogress_snapshots) \
        = get_inprogress_snapshots(configuration,
                                   snapshots=current_snapshots,
                                   do_lock=False)
    if retval:
        skip_timestamps = set(list(inprogress_snapshots.keys()))
    else:
        msg = "cleanup_snapshot_mounts: " \
            + "Failed to resolve inprogress_snapshots"
        logger.error(msg)
        if verbose:
            print_stderr(msg)

    # First umount client snapshots
    # NOTE: MGS is umounted by 'umount_snapshot' when there are no more
    # client mounts

    if retval:
        for timestamp, snapshot in current_snapshots.items():
            if timestamp not in skip_timestamps:
                (status, umounted) = umount_snapshot(configuration,
                                                     snapshot,
                                                     postfix=None)
                if umounted:
                    result['client'].extend(umounted)
                if not status:
                    retval = False
                    msg = "cleanup_snapshot_mounts: " \
                        + "failed to umount snapshot: %r: %r" \
                        % (snapshot.get('fsname', ''),
                           snapshot.get('snapshot_name', ''))
                    logger.error(msg)
                    if verbose:
                        print_stderr("ERROR: %s" % msg)

    # Finally cleanup stale MGS snapshot mounts
    # NOTE: Fetch new snapshot list from MGS
    # as umount of non-stale MGS snapshots is handled by 'umount_snapshot'

    if retval:
        mgs_snapshots = create_snapshots_dict(configuration,
                                              verbose=verbose)
        if not mgs_snapshots:
            msg = "cleanup_snapshot_mounts: " \
                + "failed to retreive MGS snapshot list"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            retval = False

    if retval:
        for timestamp, snapshot in mgs_snapshots.items():
            if timestamp not in skip_timestamps \
                    and snapshot.get('status') == 'mounted':
                logger.debug("Umounting slate MGS snapshot: %r : %r"
                             % (snapshot.get('snapshot_fsname', ''),
                                snapshot.get('snapshot_name')))
                status = umount_snapshot_mgs(configuration, snapshot)
                if status:
                    result['MGS'].append(snapshot.get('timestamp', -1))
                else:
                    retval = False

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            msg = "cleanup_snapshot_mounts: " \
                + "Failed to release backupmap lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            retval = False

    return (retval, result)


def cleanup_snapshots(configuration,
                      cleanup_timestamp=int(time.time()),
                      keep_all_days=7,
                      keep_days=31,
                      keep_weeks=4,
                      keep_months=12,
                      keep_years=10,
                      preserve_verified=True,
                      dry_run=True,
                      verbose=False,
                      ):
    """Cleanup all lustre snapshots created before *timestamp*
    Keep all snapshots for timestamp - (keep_all_days)
    Keep daily snapshots for timestamp - (keep_days)
    Keep montly snapshots for timestamp - (keep_months)
    Keep yearly snapshots for timestamp - (keep_years)
    Preserve verified snapshots unless explicitly asked not to
    Remove snapshot lists for deleted snapshots
    umount inactive MGS mounts
    Exclude timestamps in active backupmaps:
    (last_backupmap, inprogress_backupmap and inprogress_backup)
    and non-verified backups
    """
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    retval = True
    destroyed_snapshots = []
    hour_interval_secs = 3600
    day_interval_secs = 86400
    week_interval_secs = 7 * day_interval_secs
    month_interval_secs = 31 * day_interval_secs
    year_interval_secs = 365 * day_interval_secs
    keep_all_secs = day_interval_secs * keep_all_days
    # NOTE: Put a bit of slack on day interval
    #       to compsensate for variantion in snapshot time
    day_interval_slack_secs = hour_interval_secs
    week_interval_slack_secs = day_interval_secs
    month_interval_slack_secs = week_interval_secs
    year_interval_slack_secs = month_interval_secs
    kept_all = 0
    kept_days = 0
    kept_weeks = 0
    kept_months = 0
    kept_years = 0
    cleanup_datestr = datetime.datetime.fromtimestamp(cleanup_timestamp) \
        .strftime(date_format)
    msg = "cleanup_snapshots: cleanup_timestamp: %d (%s), keep_all_days: %d" \
        % (cleanup_timestamp, cleanup_datestr, keep_all_days) \
        + ", keep_days: %d, keep_weeks: %d, keep_months: %d, keep_years: %d" \
        % (keep_days, keep_weeks, keep_months, keep_years) \
        + ", dry_run: %s" % dry_run
    logger.info(msg)
    if verbose:
        print(msg)

    # NOTE: Do not cleanup snapshots before verification is completed

    last_verified_filepath = path_join(configuration,
                                       meta_basepath,
                                       last_verified_name)
    if os.path.exists(last_verified_filepath):
        last_verified = unpickle(configuration, last_verified_filepath)
        if not last_verified:
            msg = "Failed to retreive last verified info: %r" \
                % last_verified_filepath
            logger.error(msg)
            if verbose:
                print_stderr(msg)
            return False
        lv_snapshot_timestamp \
            = last_verified.get('snapshot_timestamps', [0])[-1]
        if cleanup_timestamp > lv_snapshot_timestamp:
            cleanup_timestamp = lv_snapshot_timestamp
            msg = "Cleanup snapshots using last verified timestamp: %d (%s)" \
                % (cleanup_timestamp, cleanup_datestr)
            logger.info(msg)
            if verbose:
                print(msg)

    # Check snapshots

    snapshots = get_snapshots(configuration,
                              before_timestamp=cleanup_timestamp)
    (status, inprogress_snapshots) \
        = get_inprogress_snapshots(configuration,
                                   snapshots=snapshots)
    if status:
        skip_timestamps = set(list(inprogress_snapshots.keys()))
    else:
        msg = "cleanup_snapshots: " \
            + "Failed to resolve inprogress_snapshots"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (False, [])

    sorted_timestamps = sorted(snapshots.keys(), reverse=True)
    destroy_candidates = []
    curr_timestamp = sorted_timestamps[0]
    # NOTE: Do not destroy oldest snapshot
    for idx in range(0, len(sorted_timestamps)-1):
        snapshot_timestamp = sorted_timestamps[idx]
        next_snapshot_timestamp = sorted_timestamps[idx+1]
        if snapshot_timestamp in skip_timestamps:
            msg = "cleanup_snapshots: skipping inprogess snapshot: %d" \
                % snapshot_timestamp
            logger.info(msg)
            if verbose:
                print(msg)
            continue
        datestr = datetime.datetime.fromtimestamp(snapshot_timestamp) \
            .strftime(date_format)
        curr_datestr = datetime.datetime.fromtimestamp(curr_timestamp) \
            .strftime(date_format)
        msg = "Checkpoint: " \
            + "cleanup_timestamp - snapshot_timestamp: %d" \
            % (cleanup_timestamp - snapshot_timestamp)
        logger.debug(msg)
        if kept_all < cleanup_timestamp - snapshot_timestamp < keep_all_secs:
            msg = "Keep all (%d): %s / %s" \
                % (snapshot_timestamp, datestr, curr_datestr)
            logger.info(msg)
            if verbose:
                print(msg)
            curr_timestamp = snapshot_timestamp
            kept_all += 1
        elif kept_days < keep_days:
            msg = "Checkpoint days (%d / %d): %s / %s" \
                % (snapshot_timestamp, curr_timestamp, datestr, curr_datestr)
            logger.debug(msg)
            if (curr_timestamp - snapshot_timestamp
                    < day_interval_secs - day_interval_slack_secs) \
                    and (curr_timestamp - next_snapshot_timestamp
                         < day_interval_secs - day_interval_slack_secs):
                msg = "Remove days snapshot: %s" % datestr \
                    + ", snapshot_timestamp: %d" % snapshot_timestamp \
                    + ", curr_timestamp: %d" % curr_timestamp \
                    + ", curr_timestamp + day_interval_secs: %d" \
                    % (curr_timestamp + day_interval_secs)
                logger.info(msg)
                if verbose:
                    print(msg)
                destroy_candidates.append(snapshot_timestamp)
            else:
                msg = "Keep days (%d): %s " \
                    % (snapshot_timestamp, datestr)
                logger.info(msg)
                if verbose:
                    print(msg)
                curr_timestamp = snapshot_timestamp
                kept_days += 1
        elif kept_weeks < keep_weeks and kept_days == keep_days:
            msg = "Checkpoint week (%d / %d): %s / %s" \
                % (snapshot_timestamp, curr_timestamp, datestr, curr_datestr)
            logger.debug(msg)
            if (curr_timestamp - snapshot_timestamp
                    < week_interval_secs - week_interval_slack_secs) \
                    and (curr_timestamp - next_snapshot_timestamp
                         < week_interval_secs - week_interval_slack_secs):
                msg = "Remove months snapshot: %s" % datestr \
                    + ", snapshot_timestamp: %d" % snapshot_timestamp \
                    + ", curr_timestamp: %d" % curr_timestamp \
                    + ", curr_timestamp + week_interval_secs: %d" \
                    % (curr_timestamp + week_interval_secs)
                logger.info(msg)
                if verbose:
                    print(msg)
                destroy_candidates.append(snapshot_timestamp)
            else:
                msg = "Keep week (%d): %s " % (snapshot_timestamp, datestr)
                logger.info(msg)
                if verbose:
                    print(msg)
                curr_timestamp = snapshot_timestamp
                kept_weeks += 1
        elif kept_months < keep_months and kept_weeks == keep_weeks:
            msg = "Checkpoint months (%d / %d): %s / %s" \
                % (snapshot_timestamp, curr_timestamp, datestr, curr_datestr)
            logger.debug(msg)
            if (curr_timestamp - snapshot_timestamp
                    < month_interval_secs - month_interval_slack_secs) \
                    and (curr_timestamp - next_snapshot_timestamp
                         < month_interval_secs - month_interval_slack_secs):
                msg = "Remove months snapshot: %s" % datestr \
                    + ", snapshot_timestamp: %d" % snapshot_timestamp \
                    + ", curr_timestamp: %d" % curr_timestamp \
                    + ", curr_timestamp + month_interval_secs: %d" \
                    % (curr_timestamp + month_interval_secs)
                logger.info(msg)
                if verbose:
                    print(msg)
                destroy_candidates.append(snapshot_timestamp)
            else:
                msg = "Keep month (%d): %s " % (snapshot_timestamp, datestr)
                logger.info(msg)
                if verbose:
                    print(msg)
                curr_timestamp = snapshot_timestamp
                kept_months += 1
        elif kept_years < keep_years and kept_months == keep_months:
            msg = "Checkpoint years (%d / %d): %s / %s" \
                % (snapshot_timestamp, curr_timestamp, datestr, curr_datestr)
            logger.debug(msg)
            if (curr_timestamp - snapshot_timestamp
                    < year_interval_secs - year_interval_slack_secs) \
                    and (curr_timestamp - next_snapshot_timestamp
                         < year_interval_secs - year_interval_slack_secs):
                msg = "Remove year snapshot: %s" % datestr \
                    + ", snapshot_timestamp: %d" % snapshot_timestamp \
                    + ", curr_timestamp: %d" % curr_timestamp  \
                    + ", curr_timestamp + year_interval_secs: %d" \
                    % (curr_timestamp + year_interval_secs)
                logger.info(msg)
                if verbose:
                    print(msg)
                destroy_candidates.append(snapshot_timestamp)
            else:
                msg = "Keep year (%d): %s " % (snapshot_timestamp, datestr)
                logger.debug(msg)
                if verbose:
                    print(msg)
                curr_timestamp = snapshot_timestamp
                kept_years += 1

    # Preserve verified
    # TODO: Should we take 'preserve_verified' into account during
    #       the requested time span filtering above ?

    if preserve_verified:
        preserve_candidates = []
        verify_basepath = path_join(configuration,
                                    meta_basepath,
                                    backup_verify_dirname)

        verify_pck_re = re.compile("([0-9]+)[-]?([0-9]*)\\.pck")
        with os.scandir(verify_basepath) as it:
            for entry in it:
                verify_ent = verify_pck_re.search(force_unicode(entry.name))
                if verify_ent:
                    # NOTE: target verification got both source
                    #       and target snapshot timestamp.
                    #       target snapshot timestamp is last.
                    if verify_ent.group(2):
                        timestamp = int(verify_ent.group(2))
                    elif verify_ent.group(1):
                        timestamp = int(verify_ent.group(1))
                    if timestamp in destroy_candidates:
                        preserve_candidates.append(timestamp)
                        # msg = "Preserved verified snapshot: %d" % timestamp
                        # if verbose:
                        #     print(msg)
                        # logger.debug(msg)
                # TODO: Remove this legacy target check at some point
                # NOTE: old verify format was: 'source_timestamp.pck'
                #       new verify format is:
                #       'source_timestamp-target_timestamp.pck'
                # NOTE: Using the old format we need to match
                #       source_timestamp in target snapshot comment
                if verify_ent and not verify_ent.group(2):
                    verify_timestamp = int(verify_ent.group(1))
                    source_timestamp_re = re.compile(
                        "source_snapshot: ([0-9]+)")
                    for target_timestamp, snapshot in snapshots.items():
                        snapshot_comment = snapshot.get('comment', '')
                        source_timestamp_ent \
                            = source_timestamp_re.search(snapshot_comment)
                        if source_timestamp_ent:
                            source_timestamp \
                                = int(source_timestamp_ent.group(1))
                            if source_timestamp == verify_timestamp \
                                    and target_timestamp in destroy_candidates:
                                preserve_candidates.append(target_timestamp)
                                # msg = "Preserved verified snapshot: %d" \
                                #     % target_timestamp
                                # if verbose:
                                #     print(msg)
                                #     logger.debug(msg)

        # Remove 'preserve_candidates' from 'destroy_candidates'
        preserve_candidates = sorted(preserve_candidates, reverse=True)
        msg = "Preserving: %d verified snapshot(s):\n" \
            % len(preserve_candidates)
        for timestamp in preserve_candidates:
            datestr = datetime.datetime.fromtimestamp(timestamp) \
                .strftime(date_format)
            msg += "%d (%s)\n" % (timestamp, datestr)
        logger.info(msg)
        if verbose:
            print(msg)

        destroy_candidates = [timestamp for timestamp in destroy_candidates
                              if not timestamp in preserve_candidates]

    # Destroy all snapshots in destroy_candidates list

    if not dry_run and destroy_candidates:
        for timestamp in destroy_candidates:
            datestr = datetime.datetime.fromtimestamp(timestamp) \
                .strftime(date_format)
            snapshot = snapshots.get(timestamp, {})
            if not snapshot:
                retval = False
                msg = "No snapshot found for destroy timestamp: %d" \
                    % timestamp
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
                continue
            snapshot_name = snapshot.get('snapshot_name', '')
            if not snapshot_name:
                retval = False
                msg = "Failed to extract destroy snapshot name: %s" \
                    % snapshot
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
                continue
            destroy_retval = destroy_snapshot(configuration,
                                              snapshot_name,
                                              verbose=verbose)
            if destroy_retval:
                destroyed_snapshots.append(timestamp)
                msg = "Removed old snapshot: %r from %s (%d)" \
                    % (snapshot_name, datestr, timestamp)
                logger.info(msg)
                if verbose:
                    print(msg)
            else:
                retval = False
                msg = "Failed to remove snapshot: %r from %s (%d)" \
                    % (snapshot_name, datestr, timestamp)
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)

        # Remove old snapshot lists
        # NOTE: Newest file will contain deleted snapshots,
        # but that shouldn't be a problem as all active snapshots
        # snapshots targeted for backup arn't deleted

        # Remove snapshot lists associated with destroyed snapshots

        snapshot_path = path_join(configuration,
                                  meta_basepath,
                                  snapshot_dirname)
        for destroyed_snapshot in destroyed_snapshots:
            snapshot_list_raw_filepath = path_join(configuration,
                                                   snapshot_path,
                                                   "%d.raw"
                                                   % destroyed_snapshot)
            snapshot_list_pck_filepath = path_join(configuration,
                                                   snapshot_path,
                                                   "%d.pck"
                                                   % destroyed_snapshot)
            if os.path.isfile(snapshot_list_raw_filepath):
                status = delete_file(configuration, snapshot_list_raw_filepath)
                if not status:
                    retval = False
                    msg = "Failed remove snapshots list raw: %r" \
                        % snapshot_list_raw_filepath
                    logger.error(msg)
                    if verbose:
                        print_stderr("ERROR: %s" % msg)
            if os.path.isfile(snapshot_list_raw_filepath):
                status = delete_file(configuration, snapshot_list_pck_filepath)
                if not status:
                    retval = False
                    msg = "Failed remove snapshots list raw: %r" \
                        % snapshot_list_raw_filepath
                    logger.error(msg)
                    if verbose:
                        print_stderr("ERROR: %s" % msg)

    # If dry run *pretent* that all destroy_candidates
    # was destroyed

    if dry_run:
        destroyed_snapshots = destroy_candidates

    remaining_snapshots = [timestamp for timestamp in sorted_timestamps
                           if timestamp not in destroyed_snapshots]
    return (retval,
            destroyed_snapshots,
            remaining_snapshots)
