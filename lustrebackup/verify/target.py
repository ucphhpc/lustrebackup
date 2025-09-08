#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# target - lustre backup verify helpers
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

"""This module contains various lustre backup verify target helpers"""


import os
import time
import datetime
import stat

from lustrebackup.shared.base import print_stderr, force_unicode, \
    human_readable_filesize
from lustrebackup.shared.defaults import last_verified_name, \
    backup_verify_dirname, bin_source_verify_list, bin_source_verify_init, \
    date_format
from lustrebackup.shared.fileio import pickle, unpickle, \
    make_symlink, path_join, makedirs_rec, delete_file
from lustrebackup.shared.logger import Logger
from lustrebackup.shared.serial import loads
from lustrebackup.shared.shell import shellexec
from lustrebackup.shared.verify import create_inprogress_verify, \
    remove_inprogress_verify, create_checksum, get_last_verified_timestamp
from lustrebackup.snapshot.client import mount_snapshot, \
    umount_snapshot, get_snapshots


def __init_verify(configuration,
                  source_timestamp=0,
                  target_timestamp=0,
                  resume=False,
                  verbose=False):
    """Fetch source backup verification dict
    and initialize verify logger (vlogger)"""
    # Open ssh connection to backupmap server
    logger = configuration.logger
    verify_result = None
    meta_basepath = configuration.lustre_meta_basepath
    verify_basepath = path_join(configuration,
                                meta_basepath,
                                backup_verify_dirname,
                                convert_utf8=False)

    # Fetch source verify data

    ssh_cmd = "ssh %s" % configuration.source_host
    command = bin_source_verify_init
    if configuration.source_conf:
        command += " --config %s" % configuration.source_conf
    if verbose:
        command += " --verbose"
    if source_timestamp > 0:
        command += " --timestamp=%d" % source_timestamp
    logger.debug("command: %s" % command)
    (command_rc,
     stdout,
     stderr) = shellexec(configuration,
                         ssh_cmd,
                         args=[command])
    if command_rc == 0:
        verify_result = loads(stdout,
                              serializer='json',
                              parse_int=int,
                              parse_float=float)
    else:
        msg = "Backup verify init: ssh host: %r, cmd: %r, rc: %s, error: %s" \
            % (configuration.source_host,
               command,
               command_rc,
               stderr)
        logger.error(msg)
        if verbose:
            print_stderr(msg)
        return (None, None, None)

    # For backwards compatibility
    # TODO: Can be removed in the future

    if 'files' in verify_result.keys():
        verify_result['fs'] = verify_result['files']

    # Get verify source snapshot timestamp

    verify_timestamp = verify_result.get('snapshot_timestamp',
                                         source_timestamp)
    if source_timestamp > 0 \
            and verify_timestamp != source_timestamp:
        msg = "verify_timestamp: %d != %d :source_timestamp" \
            % (verify_timestamp, source_timestamp)
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (None, None, None)

    # Log verification details to designated verification log file

    verify_log_idx = 1
    verify_logpath = path_join(configuration,
                               verify_basepath,
                               "%d.log" % verify_timestamp)
    while os.path.exists(verify_logpath):
        verify_logpath = path_join(configuration,
                                   verify_basepath,
                                   "%d.log.%d"
                                   % (verify_timestamp,
                                      verify_log_idx))
        verify_log_idx += 1

    vlogger_obj = Logger(configuration.loglevel,
                         logfile=verify_logpath,
                         app=force_unicode(verify_logpath))
    vlogger = vlogger_obj.logger

    # Find target snapshot mathing source snapshot,
    # if no target_timestamp is provided
    snapshots = get_snapshots(configuration)
    target_snapshot = None
    if target_timestamp == 0:
        source_snapshot_str = "source_snapshot: %d" % source_timestamp
        for snapshot_timestamp, snapshot in snapshots.items():
            if source_snapshot_str in snapshot.get('comment', ""):
                target_snapshot = snapshot
                break
    else:
        target_snapshot = snapshots.get(target_timestamp, None)

    # Return if no target snapshot or resume not requested

    if not target_snapshot or not resume:
        return (verify_result,
                target_snapshot,
                vlogger)

    # Resume from checkpoint if it exists

    snapshot_target_timestamp = target_snapshot.get('timestamp', 0)
    checkpoint_filepath = path_join(configuration,
                                    meta_basepath,
                                    backup_verify_dirname,
                                    "%d-%d.pck"
                                    % (verify_timestamp,
                                       snapshot_target_timestamp),
                                    convert_utf8=False,
                                    logger=vlogger)

    checkpoint = unpickle(configuration, checkpoint_filepath, logger=vlogger)
    if not checkpoint and os.path.exists(checkpoint_filepath):
        msg = "Failed to load checkpoint: %r" % checkpoint_filepath
        vlogger.error(msg)
        if verbose:
            print_stderr(msg)
        return (None, None, None)
    elif checkpoint:
        # For backwards compatibility
        # TODO: Can be removed in the future
        if 'files' in checkpoint.keys():
            checkpoint['fs'] = checkpoint['files']
        verified_files = 0
        verified_bytes = 0
        result_files = len(list(verify_result['fs'].keys()))
        for path in checkpoint['fs'].keys():
            # If file was succesfully verified in checkpoint
            # then apply checkpoint result
            target = checkpoint['fs'][path].get('target', {})
            if target and target.get('status', False):
                verify_result['fs'][path]['target'] \
                    = target
                verified_files += 1
                verified_bytes += target.get('size', 0)

        # Check of checkpoint timestamp and target timestamp matches

        checkpoint_target_timestamp \
            = checkpoint.get('target_snapshot_timestamp', 0)
        if snapshot_target_timestamp != checkpoint_target_timestamp:
            msg = "snapshot_target_timestamp: %d" \
                % snapshot_target_timestamp \
                + " != %d checkpoint_target_timestamp" \
                % checkpoint_target_timestamp
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return (None, None, None)
        msg = "Using checkpoint: verified: %s, %d/%d files: %r" \
            % (human_readable_filesize(verified_bytes),
               verified_files,
               result_files,
               checkpoint_filepath)
        vlogger.info(msg)
        if verbose:
            print_stderr(msg)
        # Free checkpoint memory
        checkpoint.clear()

    return (verify_result,
            target_snapshot,
            vlogger)


def __create_stats(configuration,
                   vlogger,
                   verified,
                   ):
    """Create verification stats from result"""
    result = {'total': 0,
              'total_pending': 0,
              'total_success': 0,
              'total_failed': 0,
              'dirs': 0,
              'dirs_success': 0,
              'dirs_failed': 0,
              'dirs_pending': 0,
              'files': 0,
              'files_pending': 0,
              'files_success': 0,
              'files_failed': 0,
              'bytes': 0,
              'bytes_pending': 0,
              'bytes_success': 0,
              'bytes_failed': 0,
              'other': 0,
              'other_pending': 0,
              'other_success': 0,
              'other_failed': 0,
              'deleted': 0,
              'renamed': 0,
              }
    result['deleted'] = len(list(verified['deleted'].keys()))
    result['renamed'] = len(list(verified['renamed'].keys()))
    for _, values in verified['fs'].items():
        result['total'] += 1
        if values.get('checksum', None):
            result['bytes'] += values.get('size', 0)
        if not 'mode' in values:
            # For backwards compatibility
            # TODO: Can be removed in the future
            st_reg = True
            st_dir = False
        else:
            st_mode = values['mode']
            st_dir = stat.S_ISDIR(st_mode)
            st_reg = stat.S_ISREG(st_mode)
        if st_reg:
            result['files'] += 1
        elif st_dir:
            result['dirs'] += 1
        else:
            result['other'] += 1
        target_result = values.get('target', {})
        target_status = target_result.get('status', False)
        if target_status:
            result['total_success'] += 1
            if st_reg:
                result['files_success'] += 1
                if target_result.get('checksum', None):
                    result['bytes_success'] += values.get('size', 0)
            elif st_dir:
                result['dirs_success'] += 1
            else:
                result['other_success'] += 1
        elif target_result:
            result['total_failed'] += 1
            if st_reg:
                result['files_failed'] += 1
                if values.get('checksum', None):
                    result['bytes_failed'] += values.get('size', 0)
            elif st_dir:
                result['dirs_failed'] += 1
            else:
                result['other_failed'] += 1
        else:
            result['total_pending'] += 1
            if st_reg:
                result['files_pending'] += 1
                if values.get('checksum', None):
                    result['bytes_pending'] += values.get('size', 0)
            elif st_dir:
                result['dirs_pending'] += 1
            else:
                result['other_pending'] += 1

    return result


def __checkpoint(configuration,
                 vlogger,
                 starttime,
                 result,
                 verify_timestamp,
                 target_timestamp,
                 last_checkpoint=None,
                 verbose=False,
                 ):
    """Create checkpoint"""
    retval = True
    meta_basepath = configuration.lustre_meta_basepath
    verify_basepath = path_join(configuration,
                                meta_basepath,
                                backup_verify_dirname,
                                convert_utf8=False,
                                logger=vlogger)

    # Save result as checkpoint

    checkpoint_name = "%d-%d.checkpoint.%d.pck" \
        % (verify_timestamp,
           target_timestamp,
           time.time())
    checkpoint_path = path_join(configuration,
                                verify_basepath,
                                checkpoint_name,
                                logger=vlogger)
    status = pickle(configuration, result, checkpoint_path, logger=vlogger)
    if not status:
        retval = False
        msg = "Failed to create checkpoint: %r" \
            % checkpoint_path
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
    t2 = time.time()

    # Show summary

    stats = __create_stats(configuration, vlogger, result)
    msg = "Checkpoint: size: %s/%s, entries: %d/%d, success: %d, failed: %d" \
        % (human_readable_filesize(stats['bytes'] - stats['bytes_pending']),
           human_readable_filesize(stats['bytes']),
           (stats['total'] - stats['total_pending']),
           stats['total'],
           stats['total_success'],
           stats['total_failed']) \
        + ", pending: %d\n" % stats['total_pending']
    msg += "Success: size: %s/%s, files: %d/%d, dirs: %d/%d, other: %d/%d\n" \
        % (human_readable_filesize(stats['bytes_success']),
            human_readable_filesize(stats['bytes']),
            stats['files_success'],
            stats['files'],
            stats['dirs_success'],
            stats['dirs'],
            stats['other_success'],
            stats['other'],)
    msg += "Failed: size: %s, files: %d, dirs: %d, other: %d\n" \
        % (human_readable_filesize(stats['bytes_failed']),
           stats['files_failed'],
           stats['dirs_failed'],
           stats['other_failed']) \
        + "Runtime %d secs" % int(t2-starttime)
    vlogger.info(msg)
    if verbose:
        print_stderr(msg)

    # Make result symlink to latest checkpoint

    result_name = "%d-%d.pck" % (verify_timestamp, target_timestamp)
    status = make_symlink(configuration,
                          checkpoint_name,
                          result_name,
                          working_dir=verify_basepath,
                          force=True,
                          logger=vlogger)
    if not status:
        retval = False
        msg = "Failed to create verified checkpoint symlink: %s -> %s in %r" \
            % (checkpoint_name,
               result_name,
               verify_basepath)
        vlogger.error(msg)
        if verbose:
            print_stderr(msg)

    # Delete last checkpoint to avoid filling up the disk

    if retval and last_checkpoint is not None \
            and last_checkpoint != checkpoint_path:
        delete_file(configuration, last_checkpoint, logger=vlogger)

    return (retval, checkpoint_path)


def list_verify(configuration,
                start_timestamp=0,
                end_timestamp=0,
                verbose=False):
    """Fetch source backup verification list"""
    logger = configuration.logger

    # Resolve snapshot_timestamp from last verified if requested

    if start_timestamp == 0:
        # Use last verified as start timestamp
        start_timestamp = get_last_verified_timestamp(configuration,
                                                      logger,
                                                      verbose=verbose)
        if start_timestamp is None:
            msg = "Failed to resolve start timestamp"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return None
        # NOTE: Add 1 to start from 'next' source timestamp
        start_timestamp += 1

    # Fetch verification list from source

    ssh_cmd = "ssh %s" % configuration.source_host
    command = bin_source_verify_list
    if configuration.source_conf:
        command += " --config %s" % configuration.source_conf
    if verbose:
        command += " --verbose"
    if start_timestamp > 0:
        command += " --start=%d" % start_timestamp
    if end_timestamp > 0:
        command += " --end=%d" % end_timestamp
    logger.debug("command: %s" % command)
    (command_rc,
     stdout,
     stderr) = shellexec(configuration,
                         ssh_cmd,
                         args=[command])
    if command_rc == 0:
        result = loads(stdout,
                       serializer='json',
                       parse_int=int,
                       parse_float=float)
    else:
        msg = "Backup verify list: ssh host: %r, cmd: %r, rc: %s, error: %s" \
            % (configuration.source_host,
               command,
               command_rc,
               stderr)
        logger.error(msg)
        if verbose:
            print_stderr(msg)
        return None

    return result


def verify(configuration,
           source_timestamp=0,
           target_timestamp=0,
           checkpoint_interval=3600,
           resume=False,
           verbose=False):
    """Create backup source verification info"""
    retval = True
    logger = configuration.logger
    total_t1 = time.time()
    last_checkpoint_time = total_t1
    last_checkpoint = None
    target_snapshot = None
    meta_basepath = configuration.lustre_meta_basepath
    verify_basepath = path_join(configuration,
                                meta_basepath,
                                backup_verify_dirname,
                                convert_utf8=False)

    # Create verify path if needed

    if not os.path.isdir(verify_basepath):
        status = makedirs_rec(configuration, verify_basepath)
        if not status:
            msg = "Failed to create backup verify basepath: %r" \
                % verify_basepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False

    # Initialize using source backup verification and checkpoints on resume

    (result,
     target_snapshot,
     vlogger) = __init_verify(configuration,
                              source_timestamp=source_timestamp,
                              target_timestamp=target_timestamp,
                              resume=resume,
                              verbose=verbose)
    if not result:
        msg = "Failed to retrieve source backup verification"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    verify_timestamp = result.get('snapshot_timestamp',
                                  source_timestamp)
    verify_datestr = datetime.datetime.fromtimestamp(verify_timestamp) \
        .strftime(date_format)

    if target_snapshot:
        target_timestamp = target_snapshot.get('timestamp', 0)
        result['target_snapshot_timestamp'] \
            = target_timestamp
        target_datestr = datetime.datetime.fromtimestamp(
            target_timestamp).strftime(date_format)
    else:
        msg = "Found no target snapshot (%d) for: %d (%s)" \
            % (target_timestamp,
               verify_timestamp,
               verify_datestr)
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Mark verify inprogress

    status = create_inprogress_verify(configuration,
                                      vlogger,
                                      verify_timestamp,
                                      target_timestamp)
    if not status:
        msg = "verify: Failed to mark inprogress"
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Mount target snapshot

    (mountpoint, _) = mount_snapshot(configuration,
                                     target_snapshot,
                                     postfix='inprogress_verify')
    if not mountpoint:
        msg = "Failed to mount target snapshot: %d (%s)" \
            % (target_timestamp,
               target_datestr)
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Verify snapshot target files

    target_datestr = datetime.datetime.fromtimestamp(target_timestamp) \
        .strftime(date_format)
    msg = "Verifying snapshot source: %d (%s), target: %d (%s), files: %d" \
        % (verify_timestamp,
           verify_datestr,
           target_timestamp,
           target_datestr,
           len(list(result['fs'].keys())))
    vlogger.info(msg)
    if verbose:
        print_stderr(msg)

    for path, values in result['fs'].items():
        # Make checkpoint if time is up
        curr_time = time.time()
        if last_checkpoint_time \
                < curr_time - checkpoint_interval:
            (status, last_checkpoint) \
                = __checkpoint(configuration,
                               vlogger,
                               total_t1,
                               result,
                               verify_timestamp,
                               target_timestamp,
                               last_checkpoint=last_checkpoint,
                               verbose=verbose)
            if not status:
                retval = False
                msg = "Checkpointing failed"
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
                break
            last_checkpoint_time = curr_time

        # Init target result dict

        target_result = result['fs'][path].get('target', {})
        if target_result:
            # vlogger.debug("Skipping already processed: %r" % path)
            continue
        target_result['status'] = False
        result['fs'][path]['target'] = target_result
        target_path = path_join(configuration,
                                mountpoint,
                                configuration.lustre_data_path,
                                path,
                                convert_utf8=False,
                                logger=vlogger)
        # File exists ?
        # NOTE: Dead links are allowed,
        #       they might point to entries located on other FS'
        #       or mount binds
        if not os.path.exists(target_path) \
                and not os.path.islink(target_path):
            retval = False
            msg = "Missing target entry: %r" % target_path
            target_result['error'] = msg
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            continue

        target_stat = os.lstat(target_path)
        st_mode = int(target_stat.st_mode)
        st_size = int(target_stat.st_size)
        st_mtime = int(target_stat.st_mtime)
        target_result['mode'] = st_mode
        target_result['size'] = st_size
        target_result['mtime'] = st_mtime

        # Extract source mode and resolve if
        # 1) file
        # 2) dir
        # 3) other
        if not 'mode' in values:
            # For backwards compatibility
            # TODO: Can be removed in the future

            # For backwards compatibility
            # TODO: Can be removed in the future
            source_st_reg = True
            source_st_dir = False
        else:
            source_st_mode = values['mode']
            source_st_dir = stat.S_ISDIR(source_st_mode)
            source_st_reg = stat.S_ISREG(source_st_mode)
        if source_st_reg:
            entry_type = "file"
        elif source_st_dir:
            entry_type = "dir"
        else:
            entry_type = "other"
        # mode mismatch ?
        # NOTE: 'mode' is new and therefore skipped if 0
        #       for backwards compatibility
        # TODO: Don't allow 'mode' == 0 in the future
        if 'mode' in values and st_mode != values.get('mode', 0):
            retval = False
            msg = "mode mismatch, source: %d, target: %d, entry(%s): %r" \
                % (values.get('mode', 0),
                   st_mode,
                   entry_type,
                   target_path)
            target_result['error'] = "msg"
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            continue

        # size mismatch ?
        # Only check size if source entry is a regular file
        # NOTE: 'dirs' and 'other' may differ in size
        #       between source and target as source and target FS'
        #       are not identical

        if source_st_reg and st_size != values.get('size', 0):
            retval = False
            msg = "size mismatch, source: %d, target: %d, entry(%s): %r" \
                % (values.get('size', 0),
                   st_size,
                   entry_type,
                   target_path)
            target_result['error'] = "msg"
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            continue

        # mtime mismatch ?
        # Only check mtime if source entry is a regular file
        # NOTE: 'dirs' and 'other' may differ in mtime
        #       as local changes such as our 'filediff' changes
        #       local dir mtime out of sync with source dir mtime

        if source_st_reg and st_mtime != values.get('mtime', 0):
            retval = False
            msg = "mtime mismatch, source: %d, target: %d, entry(%s): %r" \
                % (values.get('mtime', 0),
                   st_mtime,
                   entry_type,
                   target_path)
            target_result['error'] = "msg"
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            continue

        # checksum mismatch ?
        # NOTE: source checksum is None if skipped eg. hugefile and links/dirs

        if values['checksum']:
            retval = False
            (status, checksum) = create_checksum(configuration,
                                                 vlogger,
                                                 target_path,
                                                 verbose=verbose)
            target_result['checksum'] = checksum
            if status and checksum == values['checksum']:
                target_result['status'] = True
            elif status:
                msg = "checksum mismatch: source: %s, target: %s, file %r" \
                    % (values['checksum'],
                       checksum,
                       target_path)
                target_result['error'] = msg
                vlogger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
            elif not status:
                msg = "Verify checksum failed for: %r" \
                    % target_path
                target_result['error'] = msg
                vlogger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
        else:
            target_result['checksum'] = None
            target_result['status'] = True
            msg = "Skipping checksum for entry(%s): %r" \
                % (entry_type, path)
            vlogger.debug(msg)

    # Save result

    (status, last_checkpoint) = __checkpoint(configuration,
                                             vlogger,
                                             total_t1,
                                             result,
                                             verify_timestamp,
                                             target_timestamp,
                                             last_checkpoint=last_checkpoint,
                                             verbose=verbose)
    if not status:
        retval = False
        msg = "Checkpointing failed"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    # Unmount snapshot

    (status, _) = umount_snapshot(configuration,
                                  target_snapshot,
                                  postfix='inprogress_verify')

    # Create last verified symlink

    if retval:
        # Update last_verified if verified timestamp is newer than
        # existing last verified timestamp
        # NOTE: verified timestamp might be older than last_verified
        #       on re-runs
        last_verified_timestamp = get_last_verified_timestamp(configuration,
                                                              vlogger,
                                                              verbose=verbose)
        if last_verified_timestamp is None:
            msg = "Failed to resolve last verified timestamp"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False

        if last_verified_timestamp < verify_timestamp:
            rel_verify_filepath = path_join(configuration,
                                            backup_verify_dirname,
                                            "%d-%d.pck"
                                            % (verify_timestamp,
                                               target_timestamp),
                                            logger=vlogger)
            status = make_symlink(configuration,
                                  rel_verify_filepath,
                                  last_verified_name,
                                  working_dir=meta_basepath,
                                  force=True,
                                  logger=vlogger)
            if not status:
                retval = False
                msg = "Failed to create last verified symlink:" \
                    + " %s -> %s in %r" \
                    % (rel_verify_filepath,
                       last_verified_name,
                       meta_basepath)
                vlogger.error(msg)
                if verbose:
                    print_stderr(msg)

    # Remove inprogress marker

    status = remove_inprogress_verify(configuration,
                                      vlogger,
                                      verify_timestamp,
                                      target_timestamp)
    if not status:
        retval = False
        msg = "verify: Failed to remove inprogress marker"
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Show summary

    total_t2 = time.time()
    stats = __create_stats(configuration, vlogger, result)
    snapshot_timestamps = result.get('snapshot_timestamps', [])
    msg = "Verified source snapshot: %d (%s) using %d source changelog(s):\n" \
        % (verify_timestamp,
           verify_datestr,
           len(snapshot_timestamps))
    for snapshot_timestamp in snapshot_timestamps:
        snapshot_datestr = datetime.datetime.fromtimestamp(
            snapshot_timestamp).strftime(date_format)
        msg += "%d (%s)\n" % (snapshot_timestamp, snapshot_datestr)
    msg += "Total size: %s/%s, entries: %d/%d, success: %d, failed: %d" \
        % (human_readable_filesize(stats['bytes'] - stats['bytes_pending']),
           human_readable_filesize(stats['bytes']),
           (stats['total'] - stats['total_pending']),
           stats['total'],
           stats['total_success'],
           stats['total_failed']) \
        + ", pending: %d\n" % stats['total_pending']
    msg += "Success: size: %s/%s, files: %d/%d, dirs: %d/%d, other: %d/%d\n" \
        % (human_readable_filesize(stats['bytes_success']),
            human_readable_filesize(stats['bytes']),
            stats['files_success'],
            stats['files'],
            stats['dirs_success'],
            stats['dirs'],
            stats['other_success'],
            stats['other'],)
    msg += "Failed: size: %s, files: %d, dirs: %d, other: %d\n" \
        % (human_readable_filesize(stats['bytes_failed']),
           stats['files_failed'],
           stats['dirs_failed'],
           stats['other_failed']) \
        + "Runtime %d secs" % int(total_t2-total_t1)
    vlogger.info(msg)
    if verbose:
        print_stderr(msg)

    return retval
