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
import datetime
import time
import re
import tempfile
import psutil


from lustrebackup.shared.base import print_stderr
from lustrebackup.shared.defaults import last_snapshot_name, \
    snapshot_dirname, snapshot_name_format, snapshot_created_format
from lustrebackup.shared.fileio import pickle, unpickle, \
    path_join, makedirs_rec, make_symlink, remove_dir, \
    release_file_lock, make_temp_file, copy
from lustrebackup.shared.lock import acquire_snapshot_lock
from lustrebackup.shared.shell import shellexec
from lustrebackup.snapshot.mgs import snapshot_list_mgs, \
    mount_snapshot_mgs, umount_snapshot_mgs


def __add_snapshot_dict(configuration,
                        snapshot,
                        snapshot_dict):
    """Add snapshot to snapshot dict with timestamp as key"""
    logger = configuration.logger
    result = False
    snapshot_name = snapshot.get('snapshot_name', '')
    # logger.debug("snapshot_name: %s" % snapshot_name)
    # Return early if no 'snapshot_name' found
    if not snapshot_name:
        return False
    timestamp_re = re.compile(".*([0-9]{10}).*")
    timestamp_ent = timestamp_re.fullmatch(snapshot_name)
    timestamp = 0
    if timestamp_ent:
        lustrebackup_snapshot = True
        timestamp = int(timestamp_ent.group(1))
    else:
        lustrebackup_snapshot = False
        # For snapshots NOT created by lustrebackup use 'create_time'
        create_time = snapshot.get('create_time', '').strip()
        if create_time:
            datetime_elm \
                = datetime.datetime.strptime(create_time,
                                             snapshot_created_format)
            timestamp = int(time.mktime(datetime_elm.timetuple()))
    if timestamp != 0:
        snapshot['timestamp'] = timestamp
        snapshot['lustrebackup'] = lustrebackup_snapshot
        snapshot_dict[timestamp] = snapshot
    else:
        logger.error("Failed to resolve timestamp for snapshot: %s" % snapshot)
        return False

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
                          update_timestamp=None,
                          snapshot_timestamp=None,
                          snapshot_name=None,
                          update_last=False,
                          do_lock=True,
                          verbose=False):
    """Retrieve snapshot list from MGS and create/save snapshots dict
    if *timestamp* is None then dict is returned,
    otherwise dict is pickled to disk and filename is returned
    if *snapshot_name* is None and *snapshot_timestamp* is set
    then *snapshot_name* is resolved from *snapshot_timestamp*
    """
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    temp_file_fd = None
    snapshot_raw_filepath = None
    snapshot_pck_filepath = None
    snapshot_path = path_join(configuration,
                              meta_basepath,
                              snapshot_dirname,
                              convert_utf8=False)
    # Acquire snapshot lock

    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            logger.error("Failed to acquire snapshot lock")
            return None

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

    if update_timestamp is None:
        (temp_file_fd, temp_file_name) \
            = make_temp_file(dir=snapshot_path)
        snapshot_raw_filepath = temp_file_name
    else:
        snapshot_raw_filepath = path_join(configuration,
                                          snapshot_path,
                                          "%d.raw" % update_timestamp,
                                          convert_utf8=False)
        snapshot_pck_filepath = path_join(configuration,
                                          snapshot_path,
                                          "%d.pck" % update_timestamp,
                                          convert_utf8=False)
        # Make a copy of existing files for traceability
        filetmp = next(tempfile._get_candidate_names())
        if os.path.exists(snapshot_raw_filepath):
            dstfile = "%s.%s" % (snapshot_raw_filepath, filetmp)
            status = copy(configuration, snapshot_raw_filepath, dstfile)
            if not status:
                return None
        if os.path.exists(snapshot_pck_filepath):
            dstfile = "%s.%s" % (snapshot_pck_filepath, filetmp)
            status = copy(configuration, snapshot_pck_filepath, dstfile)
            if not status:
                return None

    # Fetch snapshot list from MGS
    # resolve snapshot_name from snapshot_timestamp
    if snapshot_timestamp and snapshot_name is None:
        snapshot_name = snapshot_name_format \
            % {'fsname': configuration.lustre_fsname,
               'timestamp': snapshot_timestamp}
    # For a specific snapshot we allow missing on updates
    # NOTE: This occur if the snapshot was destroyed
    allow_missing_snapshot = False
    if snapshot_name is not None and update_last:
        allow_missing_snapshot = True
    (retval, _) \
        = snapshot_list_mgs(configuration,
                            snapshot_name=snapshot_name,
                            snapshot_list_filepath=snapshot_raw_filepath,
                            allow_missing_snapshot=allow_missing_snapshot,
                            verbose=verbose)
    if not retval:
        msg = "Failed to fetch snapshot list from MGS, snapshot_name: %s" \
            % snapshot_name \
            + ", snapshot_timestamp: %s" \
            % snapshot_timestamp
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
            os.remove(temp_file_name)
    except Exception as err:
        msg = "Failed to parse snapshot list: %r, error: %s" \
            % (snapshot_raw_filepath, err)
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    # Update last snapshot dict if requested
    # NOTE: If 'snapshot_name' is unset then a complete list was fetched
    #       into 'snapshots_dict' and therefore we do not update
    #       with 'last_snapshots_dict'
    if update_last and snapshot_name:
        last_snapshots_dict = get_snapshots(configuration, do_lock=False)
        # Resolve snapshot_timestamp if not provided
        if not snapshot_timestamp and snapshot_name:
            for timestamp, snapshot in last_snapshots_dict.items():
                if snapshot.get('snapshot_name', '') == snapshot_name:
                    snapshot_timestamp = timestamp
        # Update last snapshots dict with new values
        if snapshots_dict:
            last_snapshots_dict.update(snapshots_dict)
            # check if snapshot with 'snapshot_timestamp' was removed
            if snapshot_timestamp \
                    and snapshot_timestamp not in snapshots_dict.keys() \
                    and snapshot_timestamp in last_snapshots_dict.keys():
                del last_snapshots_dict[snapshot_timestamp]
        snapshots_dict = last_snapshots_dict

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

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            retval = False
            logger.error("Failed to release snapshot lock")

    return result


def get_inprogress_snapshots(configuration,
                             snapshots=None,
                             do_lock=True):
    """Return inprogress snapshots"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    # Acquire snapshot lock
    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            logger.error("Failed to acquire snapshot lock")
            return (False, None)
    if not snapshots:
        snapshots = get_snapshots(configuration, do_lock=False)
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
            logger.error("Failed to release snapshot lock")

    return (retval, result)


def get_snapshots(configuration,
                  snapshot_filename=last_snapshot_name,
                  before_timestamp=int(time.time()),
                  after_timestamp=0,
                  do_lock=True,
                  verbose=False):
    """Return dict (stored on backupmeta client) with snapshots info"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath

    # Acquire snapshot lock

    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            msg = "get_snapshots: " \
                + "Failed to acquire snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return None

    #
    if snapshot_filename == last_snapshot_name:
        snapshots_filepath = path_join(configuration,
                                       meta_basepath,
                                       last_snapshot_name)
    else:
        snapshots_filepath = path_join(configuration,
                                       meta_basepath,
                                       snapshot_dirname,
                                       snapshot_filename)
    snapshots = unpickle(configuration, snapshots_filepath)
    if snapshots is None:
        result = None
        msg = "Missing or malformed snapshot file: %r" % snapshots_filepath
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
    else:
        result = {timestamp: snapshot
                  for timestamp, snapshot in snapshots.items()
                  if timestamp > after_timestamp
                  and timestamp < before_timestamp}

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            msg = "get_snapshots: " \
                + "Failed to release snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    return result


def get_last_snapshot(configuration, do_lock=True):
    """Return last snapshot dict"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    # Acquire snapshot lock
    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            logger.error("Failed to acquire snapshot lock")
            return None

    snapshots = get_snapshots(configuration, do_lock=False)
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

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            logger.error("Failed to release snapshot lock")

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


def mount_snapshot(configuration,
                   snapshot,
                   postfix=os.getpid(),
                   do_lock=True):
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

    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            logger.error("Failed to acquire snapshot lock")
            return (None, False)

    # Check if snapshot was mounted while waiting for lock

    if os.path.ismount(mountpoint):
        snapshot['status'] = 'mounted'
        snapshot['client'] = 'mounted'
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            logger.error("Failed to release lock")
        return (True, mountpoint)

    # Mount on MGS if needed

    if snapshot.get('status', '') != 'mounted':
        mgs_retval = mount_snapshot_mgs(configuration,
                                        snapshot_name)
        if mgs_retval:
            snapshot['status'] = 'mounted'
        else:
            snapshot['status'] = 'not mount'
            snapshot['client'] = 'failed'
        # Update snapshot list after MGS mount
        create_snapshots_dict(configuration,
                              update_timestamp=time.time(),
                              snapshot_name=snapshot_name,
                              update_last=True,
                              do_lock=False,)

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

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            result = (mountpoint, False)
            logger.error("Failed to release snapshot lock")

    return result


def umount_snapshot(configuration,
                    snapshot,
                    postfix=os.getpid(),
                    force=False,
                    update_snapshot_list=True,
                    do_lock=True):
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

    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            logger.error("Failed to acquire snapshot lock")
            return (False, None)

    mountpoints = get_mountpoints(configuration,
                                  snapshot,
                                  postfix=postfix)

    # If not mounted then return early

    if not mountpoints:
        if do_lock:
            lock_status = release_file_lock(configuration, lock)
            if not lock_status:
                logger.error("Failed to release lock")
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
        # Update snapshot list after MGS mount
        if update_snapshot_list:
            create_snapshots_dict(configuration,
                                  update_timestamp=time.time(),
                                  snapshot_name=snapshot_name,
                                  update_last=True,
                                  do_lock=False)
    else:
        logger.info("safe_umount_snapshot_mgs:"
                    + " Skipping MGS umount for %s"
                    % (snapshot_fsname)
                    + ", Found remaining snapshot mounts (%d): %s"
                    % (len(remaining_mounts),
                       remaining_mounts))

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            retval = False
            logger.error("Failed to release snapshot lock")

    return (retval, umounted)
