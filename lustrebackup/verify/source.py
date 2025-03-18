#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# source - lustre backup verify helpers
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

"""This module contains various lustre backup verify source helpers"""


import os
import time
import copy
import datetime
import re
import stat

from lustrebackup.shared.base import print_stderr, force_unicode, \
    human_readable_filesize
from lustrebackup.shared.defaults import last_backup_name, \
    last_verified_name, backup_verify_dirname, changelog_dirname, \
    backupmap_dirname, backupmap_merged_dirname, backupmeta_dirname, \
    date_format
from lustrebackup.shared.fileio import pickle, unpickle, \
    make_symlink, path_join, makedirs_rec, delete_file
from lustrebackup.shared.logger import Logger
from lustrebackup.shared.lustre import lfs_fid2path
from lustrebackup.shared.shell import shellexec
from lustrebackup.shared.verify import create_inprogress_verify, \
    remove_inprogress_verify, create_checksum, get_last_verified_timestamp, \
    running_verify
from lustrebackup.snapshot.client import mount_snapshot, \
    umount_snapshot, get_snapshots


def __init_verify(configuration,
                  verify_timestamp,
                  checkpoint_timestamp,
                  resume=False,
                  verbose=False):
    """Resume from *checkpoint_timestamp*
    if checkpoint exists and resume is requested.
    Initialize verify logger (vlogger)"""
    meta_basepath = configuration.lustre_meta_basepath
    verify_basepath = path_join(configuration,
                                meta_basepath,
                                backup_verify_dirname,
                                convert_utf8=False)

    # Log verification details to designated verification log file

    verify_log_idx = 1
    verify_logpath = path_join(configuration,
                               verify_basepath,
                               "%s.log" % verify_timestamp)
    while os.path.exists(verify_logpath):
        verify_logpath = path_join(configuration,
                                   verify_basepath,
                                   "%s.log.%d"
                                   % (verify_timestamp,
                                      verify_log_idx))
        verify_log_idx += 1

    vlogger_obj = Logger(configuration.loglevel,
                         logfile=verify_logpath,
                         app=force_unicode(verify_logpath))
    vlogger = vlogger_obj.logger

    # Initialize result

    result = {'snapshot_timestamp': verify_timestamp,
              'start_recno': 0,
              'end_recno': 0,
              'snapshot_timestamps': [],
              'fs': {},
              'checksum_choice': configuration.backup_checksum_choice,
              'deleted': {},
              'renamed': {},
              }
    resolved_fids = {}
    skipped = {'resolved': {},
               'nids': {},
               'mtime': {},
               'dirty': {}}

    # Return if resume is not requested

    if not resume:
        return (result, resolved_fids, skipped, vlogger)

    # Load checkpoint it exists and resume is requested

    verify_datestr = datetime.datetime.fromtimestamp(verify_timestamp) \
        .strftime(date_format)
    checkpoint_datestr = datetime.datetime.fromtimestamp(
        checkpoint_timestamp).strftime(date_format)
    meta_basepath = configuration.lustre_meta_basepath
    checkpoint = None
    checkpoint_path = path_join(configuration,
                                verify_basepath,
                                "%d.checkpoint.%d.pck"
                                % (verify_timestamp,
                                   checkpoint_timestamp),
                                logger=vlogger)
    checkpoint = unpickle(configuration, checkpoint_path, logger=vlogger)
    if not checkpoint and os.path.exists(checkpoint_path):
        msg = "Failed to load checkpoint: %r" % checkpoint_path
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (None, None)
    if checkpoint:
        result = checkpoint
        # Fill resolved_fids with known resolved files
        for _, values in checkpoint.get('fs', {}).items():
            resolved_fids[values['fid']] = True

        msg = "Resuming verify of snapshot %d (%s) from checkpoint %d (%s)" \
            % (verify_timestamp,
               verify_datestr,
               checkpoint_timestamp,
               checkpoint_datestr) \
            + ", files: %d (%r)" \
            % (len(list(resolved_fids.keys())),
                checkpoint_path)
        vlogger.info(msg)
        if verbose:
            print_stderr(msg)

    return (result, resolved_fids, skipped, vlogger)


def __log_rename_stats(configuration,
                       vlogger,
                       verified,
                       verbose=False):
    """Log renamed statistics"""
    active_msg = ""
    deleted_count = 0
    for fid, values in verified['renamed'].items():
        count = values.get('count', 0)
        dest = values.get('dest', '')
        if dest:
            active_msg += "%r %r %d\n" % (fid, dest, count)
        else:
            deleted_count += count
    msg = ""
    if active_msg:
        msg += "Active renames (fid dest count)\n"
        msg += active_msg
    if deleted_count > 0:
        msg += "Deleted renames: %d" % deleted_count
    if not msg:
        msg = "No renames found"
    vlogger.info(msg)
    if verbose:
        print(msg)


def __create_stats(configuration,
                   vlogger,
                   verified,
                   resolved_fids,
                   skipped,
                   ):
    """Create verification stats from result"""
    result = {'total': 0,
              'dirs': 0,
              'files': 0,
              'bytes': 0,
              'other': 0,
              'skipped': 0,
              'deleted': 0,
              'resolved': 0,
              'renamed': 0,
              }
    result['deleted'] = len(list(verified['deleted'].keys()))
    result['resolved'] = len(list(resolved_fids.keys()))

    # Skipped

    for _, values in skipped.items():
        for _, count in values.items():
            result['skipped'] += count

    # Renamed

    renamed = verified.get('renamed', {})
    for _, values in renamed.items():
        result['renamed'] += values.get('count', 0)

    # Modified

    for _, values in verified['fs'].items():
        result['total'] += 1
        st_mode = values['mode']
        st_dir = stat.S_ISDIR(st_mode)
        st_reg = stat.S_ISREG(st_mode)
        if st_reg:
            result['files'] += 1
            if values.get('checksum', None):
                result['bytes'] += values.get('size', 0)
        elif st_dir:
            result['dirs'] += 1
        else:
            result['other'] += 1

    return result


def __checkpoint(configuration,
                 vlogger,
                 starttime,
                 curr_changelog,
                 total_changelogs,
                 curr_line,
                 total_lines,
                 result,
                 snapshot_result,
                 checkpoint_result,
                 verify_timestamp,
                 checkpoint_timestamp,
                 resolved_fids,
                 skipped,
                 last_checkpoint=None,
                 renamed_only=False,
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
    checkpoint_datestr = datetime.datetime.fromtimestamp(
        checkpoint_timestamp).strftime(date_format)

    # Update snapshot result and total result
    # NOTE: checkpoint_result start_recno might be zero
    #       if no live data entries were resolved
    if checkpoint_result.get('start_recno', 0) > 0:
        if snapshot_result.get('start_recno', 0) == 0:
            snapshot_result['start_recno'] = checkpoint_result['start_recno']
        else:
            snapshot_result['start_recno'] \
                = min(snapshot_result['start_recno'],
                      checkpoint_result['start_recno'])
        if result.get('start_recno', 0) == 0:
            result['start_recno'] = checkpoint_result['start_recno']
        else:
            result['start_recno'] = min(result['start_recno'],
                                        checkpoint_result['start_recno'])
    snapshot_result['end_recno'] = max(snapshot_result['end_recno'],
                                       checkpoint_result['end_recno'])
    result['end_recno'] = max(result['end_recno'],
                              checkpoint_result['end_recno'])
    snapshot_result['fs'].update(checkpoint_result['fs'])
    result['fs'].update(checkpoint_result['fs'])

    # Update deleted

    checkpoint_deleted = checkpoint_result['deleted']
    snapshot_deleted = snapshot_result['deleted']
    result_deleted = result['deleted']
    for fid in checkpoint_deleted.keys():
        snapshot_deleted[fid] \
            = snapshot_deleted.get('fid', 0) \
            + checkpoint_deleted.get('fid', 0)
        result_deleted[fid] \
            = result_deleted.get('fid', 0) \
            + checkpoint_deleted.get('fid', 0)

    # Update renamed

    checkpoint_renamed = checkpoint_result['renamed']
    snapshot_renamed = snapshot_result['renamed']
    result_renamed = result['renamed']

    for fid in checkpoint_renamed.keys():
        if not fid in snapshot_renamed.keys():
            snapshot_renamed[fid] = copy.deepcopy(checkpoint_renamed[fid])
        else:
            snapshot_renamed[fid]['count'] \
                = snapshot_renamed[fid]['count'] \
                + checkpoint_renamed[fid]['count']
            if 'dest' in checkpoint_renamed[fid].keys():
                snapshot_renamed[fid]['dest'] = checkpoint_renamed[fid]['dest']
        if not fid in result_renamed.keys():
            result_renamed[fid] = copy.deepcopy(checkpoint_renamed[fid])
        else:
            result_renamed[fid]['count'] \
                = result_renamed[fid]['count'] \
                + checkpoint_renamed[fid]['count']
            if 'dest' in checkpoint_renamed[fid].keys():
                result_renamed[fid]['dest'] = checkpoint_renamed[fid]['dest']

    # Reset checkpoint_result

    checkpoint_result['start_recno'] = 0
    checkpoint_result['end_recno'] = 0
    checkpoint_result['fs'] = {}
    checkpoint_result['deleted'] = {}
    checkpoint_result['renamed'] = {}

    # Save result as checkpoint

    checkpoint_name = "%d.checkpoint.%d.pck" \
        % (verify_timestamp,
           checkpoint_timestamp)
    checkpoint_path = path_join(configuration,
                                verify_basepath,
                                checkpoint_name,
                                logger=vlogger)
    status = pickle(configuration, result, checkpoint_path)
    if not status:
        retval = False
        msg = "Failed to create checkpoint: %r" \
            % checkpoint_path
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    # Show summary

    t2 = time.time()
    stats = __create_stats(configuration,
                           vlogger,
                           result,
                           resolved_fids,
                           skipped)
    msg = "Checkpoint result: changelog: %d/%d, snapshot: %d (%s)" \
        % (curr_changelog,
           total_changelogs,
           checkpoint_timestamp,
           checkpoint_datestr) \
        + ", lines: %d/%d, start_recno: %d, end_recno: %d" \
        % (curr_line,
           total_lines,
           result['start_recno'],
           result['end_recno']) \
        + ", total: %d, resolved: %d, skipped: %d, deleted: %d, renamed: %d" \
        % (stats['total'],
           stats['resolved'],
           stats['skipped'],
           stats['deleted'],
           stats['renamed']) \
        + ", size: %s, files: %d, dirs: %d, other: %d" \
        % (human_readable_filesize(stats['bytes']),
           stats['files'],
           stats['dirs'],
           stats['other']) \
        + " in %d secs" % int(t2-starttime)
    vlogger.info(msg)
    if verbose:
        print_stderr(msg)

    if renamed_only:
        __log_rename_stats(configuration, vlogger, result, verbose=verbose)

    # Make result symlink to latest checkpoint

    result_name = "%d.pck" % verify_timestamp
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


def __fid2result(configuration,
                 vlogger,
                 mountpoint,
                 fid,
                 result,
                 skipped,
                 verify_mtime=0,
                 verbose=False):
    """Create result entry from fid"""
    retval = True
    checksum = None

    (rc, path) = lfs_fid2path(mountpoint, fid)
    # vlogger.debug("lfs_fid2path: %r, %r, rc: %d" \
    #        % (mountpoint, fid, rc)) \
    #        + ", path %r" % path
    if rc == 0:
        filepath = path_join(configuration,
                             mountpoint,
                             path,
                             convert_utf8=False,
                             logger=vlogger)
        # vlogger.debug("filepath: %r" % filepath)
        snapshot_stat = os.lstat(filepath)
        st_mode = int(snapshot_stat.st_mode)
        st_isreg = stat.S_ISREG(st_mode)
        st_size = int(snapshot_stat.st_size)
        st_mtime = int(snapshot_stat.st_mtime)
        if st_mtime > verify_mtime:
            if st_isreg:
                if st_size < configuration.lustre_hugefile_size:
                    (status, checksum) = create_checksum(configuration,
                                                         vlogger,
                                                         filepath,
                                                         verbose=verbose)
                    if not status:
                        msg = "Verify checksum failed for: %r" \
                            % filepath
                        vlogger.error(msg)
                        if verbose:
                            print_stderr("ERROR: %s" % msg)
                        retval = False
                else:
                    msg = "Skipping checksum for hugefile: (%d/%d) %r" \
                        % (st_size,
                            configuration.lustre_hugefile_size,
                            filepath)
                    vlogger.info(msg)
                    if verbose:
                        print_stderr(msg)

            result['fs'][path] = \
                {'fid': fid,
                 'size': st_size,
                 'mtime': st_mtime,
                 'mode': st_mode,
                 'checksum': checksum,
                 }
            # TODO: Only do this if renamed_only ?
            renamed = result['renamed'].get(fid, {})
            if renamed:
                renamed['dest'] = path
            # vlogger.debug("%d (%d/%d): %r: %s" \
            #    % (recno,
            #    result['start_recno'],
            #    result['end_recno'],
            #    path,
            #    result['fs'][path]))
        else:
            skipped['mtime'][fid] = skipped['mtime'].get(fid, 0) + 1
        #   vlogger.debug("Skipping non file or non modified entry:" \
        #        %d (%d/%d): %r" \
        #        % (recno,
        #        result['start_recno'],
        #        result['end_recno'],
        #        path))
    elif rc == -2:
        result['deleted'][fid] \
            = result['deleted'].get('fid', 0) + 1
    else:
        retval = False
        msg = "Failed lfs_fid2path: %r, %r, rc: %d" \
            % (mountpoint, fid, rc)
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def list_verify(configuration,
                start_timestamp=0,
                end_timestamp=0,
                verbose=False):
    """Returns sorted list of source verfications completed between
    *start_timestamp* and *end_timestamp"""
    logger = configuration.logger
    meta_basepath = configuration.lustre_meta_basepath
    result = {}
    verify_timestamps = []
    verify_basepath = path_join(configuration,
                                meta_basepath,
                                backup_verify_dirname,
                                convert_utf8=False)
    if end_timestamp == 0:
        # Use last verified as end timestamp
        end_timestamp = get_last_verified_timestamp(configuration,
                                                    logger,
                                                    verbose=verbose)
        if end_timestamp is None:
            msg = "Failed to resolve end timestamp"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False

    # Search for verfications made between start and end timestamp

    result['start_timestamp'] = start_timestamp
    result['end_timestamp'] = end_timestamp
    msg = "Searching "
    verify_pck_re = re.compile("([0-9]+)\\.pck")
    with os.scandir(verify_basepath) as it:
        for entry in it:
            verify_ent = verify_pck_re.fullmatch(entry.name)
            if verify_ent:
                timestamp = int(verify_ent.group(1))
                # NOTE: Only return completed verifications
                #       between start and end
                if timestamp >= start_timestamp \
                        and timestamp <= end_timestamp \
                        and not running_verify(configuration,
                                               logger,
                                               timestamp,
                                               verbose=verbose):
                    verify_timestamps.append(timestamp)
    result['verify_timestamps'] = sorted(verify_timestamps)

    return result


def get_verification(configuration,
                     snapshot_timestamp=0,
                     verbose=False):
    """Returns source backup verify result for
    *snapshot_timestamp*"
    """
    logger = configuration.logger
    result = {}
    meta_basepath = configuration.lustre_meta_basepath
    verify_basepath = path_join(configuration,
                                meta_basepath,
                                backup_verify_dirname,
                                convert_utf8=False)

    # Resolve snapshot_timestamp from last verified if requested

    if snapshot_timestamp == 0:
        snapshot_timestamp = get_last_verified_timestamp(configuration,
                                                         logger,
                                                         verbose=verbose)
        if snapshot_timestamp is None:
            msg = "Failed to resolve snapshot timestamp"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return None

    # Load source verification result

    source_verify_filepath = path_join(configuration,
                                       verify_basepath,
                                       "%d.pck" % snapshot_timestamp)
    result = unpickle(configuration, source_verify_filepath)
    if not result:
        msg = "Failed to load source verify file: %r" \
            % source_verify_filepath
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    return result


def verify(configuration,
           start_timestamp=0,
           end_timestamp=0,
           checkpoint_interval=3600,
           modified_timestamp=None,
           resume=False,
           renamed_only=False,
           verbose=False):
    """Create backup source verification info"""
    logger = configuration.logger
    update_last_verified = False
    total_t1 = time.time()
    last_checkpoint_time = total_t1
    last_checkpoint = None
    meta_basepath = configuration.lustre_meta_basepath
    changelog_basepath = path_join(configuration,
                                   meta_basepath,
                                   changelog_dirname,
                                   convert_utf8=False)
    last_backup_filepath = path_join(configuration,
                                     meta_basepath,
                                     last_backup_name)
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

    if start_timestamp == 0 and end_timestamp == 0:
        update_last_verified = True
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
            return False

    if end_timestamp == 0:
        # Use last backup as end timestamp
        last_backup = unpickle(configuration,
                               last_backup_filepath)
        if isinstance(last_backup, dict):
            end_timestamp = last_backup.get('snapshot_timestamp', 0)
        if end_timestamp == 0:
            msg = "Failed to resolve last backup snapshot timestamp: %r" \
                % last_backup_filepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return False

    # Set verify timestamp and datestr

    verify_timestamp = end_timestamp
    verify_datestr = datetime.datetime.fromtimestamp(verify_timestamp) \
        .strftime(date_format)

    # Initialize using checkpoints on resume

    (result,
     resolved_fids,
     skipped,
     vlogger) = __init_verify(configuration,
                              verify_timestamp,
                              start_timestamp,
                              resume=resume,
                              verbose=verbose)

    # Get nid of verify client

    command = "lctl list_nids"
    self_nids = []
    (rc, stdout, stderr) = shellexec(configuration,
                                     command,
                                     logger=vlogger)
    if rc == 0:
        self_nids = force_unicode(stdout.split('\n'))
    else:
        msg = "Failed to resolve lustre nid: rc: %d, error: %s" \
            % (rc, stderr)
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    start_datestr = datetime.datetime.fromtimestamp(start_timestamp) \
        .strftime(date_format)
    end_datestr = datetime.datetime.fromtimestamp(end_timestamp) \
        .strftime(date_format)
    verify_datestr = datetime.datetime.fromtimestamp(end_timestamp) \
        .strftime(date_format)
    msg = "Starting backup source verify using start timestamp: %d (%s)" \
        % (start_timestamp, start_datestr) \
        + ", end timestamp: %d (%s), verify_timestamp: %d (%s)" \
        % (end_timestamp, end_datestr,
           verify_timestamp, verify_datestr)
    vlogger.info(msg)
    if verbose:
        print_stderr(msg)

    # Use latest backup snapshot

    snapshots = get_snapshots(configuration,
                              before_timestamp=end_timestamp+1,
                              after_timestamp=start_timestamp-1)
    snapshot = snapshots.get(verify_timestamp, None)
    if not snapshot:
        msg = "verify: No snapshot found with timestamp: %d" \
            % verify_timestamp
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Mark verify inprogress

    status = create_inprogress_verify(configuration,
                                      vlogger,
                                      verify_timestamp)
    if not status:
        msg = "verify: Failed to mark inprogress"
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Mount snapshot

    (mountpoint, _) = mount_snapshot(configuration,
                                     snapshot,
                                     postfix='inprogress_verify')
    if not mountpoint:
        msg = "Failed to mount snapshot: %d" % verify_timestamp
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Find raw changelogs between start_timestamp and end_timestamp

    changelogs = {}
    changelog_raw_re = re.compile("([0-9]+)\\.raw")
    with os.scandir(changelog_basepath) as it:
        for entry in it:
            changelog_ent = changelog_raw_re.fullmatch(entry.name)
            if changelog_ent:
                timestamp = int(changelog_ent.group(1))
                if timestamp >= start_timestamp \
                        and timestamp <= end_timestamp:
                    changelogs[timestamp] = entry.path

    # Parse raw changelogs

    sfid_re = re.compile("s=\\[(.*?)\\]")
    tfid_re = re.compile("t=\\[(.*?)\\]")
    nid_re = re.compile("nid=([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+[@a-z]+)")
    date_re = re.compile(" ([0-9]{4}\\.[0-1]{1}[0-9]{1}\\.[0-3]{1}[0-9]{1}) ")
    sorted_timestamps = sorted(changelogs.keys())
    total_changelogs = len(sorted_timestamps)
    retval = True
    curr_changelog = 0
    snapshot_template = {
        'start_recno': 0,
        'end_recno': 0,
        'fs': {},
        'deleted': {},
        'renamed': {},
    }
    for timestamp in sorted_timestamps:
        snapshot_result = copy.deepcopy(snapshot_template)
        checkpoint_result = copy.deepcopy(snapshot_template)
        result['snapshot_timestamps'].append(timestamp)
        changelog_filepath = changelogs[timestamp]
        datestr = datetime.datetime.fromtimestamp(timestamp) \
            .strftime(date_format)
        (rc, stdout, stderr) = shellexec(configuration, "wc -l %s"
                                         % changelog_filepath,
                                         logger=vlogger)
        total_lines = -1
        if rc == 0:
            total_lines = int(stdout.split(' ')[0])
        else:
            msg = "Failed to retrieve #lines for: %r, error: %s" \
                % (changelog_filepath, stderr)
            vlogger.warning(msg)
            if verbose:
                print_stderr("WARNING: %s" % msg)
        msg = "Parsing changelog %d/%d, snapshot: %d (%s), file: %r" \
            % (curr_changelog,
               total_changelogs,
               timestamp,
               datestr,
               changelog_filepath) \
            + ", lines: %s" \
            % total_lines
        vlogger.info(msg)
        if verbose:
            print_stderr(msg)
        curr_line = 0
        changelog_t1 = time.time()
        fh = open(changelog_filepath, 'r')
        line = fh.readline()

        # If modified_timestamp is None resolve timestamp
        # from first line in first snapshot changelog

        if modified_timestamp is None:
            verify_mtime = 0
            date_ent = date_re.search(line)
            if date_ent:
                verify_mtime = int(time.mktime(
                    datetime.datetime.strptime(date_ent.group(1),
                                               "%Y.%m.%d").timetuple()))
            else:
                retval = False
                msg = "No valid date found in %r, line (%d): %r" \
                    % (changelog_filepath,
                       curr_line,
                       line)
                vlogger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)
        else:
            verify_mtime = modified_timestamp

        verify_mtime_str = datetime.datetime.fromtimestamp(
            verify_mtime).strftime('%d/%m/%Y-%H:%M:%S')
        msg = "Using verify_mtime: %d (%s)" \
            % (verify_mtime,
               verify_mtime_str)
        vlogger.info(msg)
        if verbose:
            print_stderr(msg)

        msg = "Using renamed_only: %s" \
            % renamed_only
        vlogger.info(msg)
        if verbose:
            print_stderr(msg)

        # Parse changelog

        while line and retval:
            # Create snapshot if needed
            fid_mtime = verify_mtime
            curr_time = time.time()
            if last_checkpoint_time \
                    < curr_time - checkpoint_interval:
                (retval, last_checkpoint) \
                    = __checkpoint(configuration,
                                   vlogger,
                                   total_t1,
                                   curr_changelog,
                                   total_changelogs,
                                   curr_line,
                                   total_lines,
                                   result,
                                   snapshot_result,
                                   checkpoint_result,
                                   verify_timestamp,
                                   timestamp,
                                   resolved_fids,
                                   skipped,
                                   last_checkpoint=last_checkpoint,
                                   renamed_only=renamed_only,
                                   verbose=verbose)
                if retval:
                    last_checkpoint_time = curr_time
                else:
                    break

            # Process changelog line

            curr_line += 1
            line = line.rstrip('\r\n')

            # Resolve lustre nid
            # NOTE: Skip changelog entries created by verify client
            #       as verify in itself creates a changelog entry
            #       and therefore verifying the entire backup metadata
            #       will cascade.

            nid = None
            nid_ent = nid_re.search(line)
            if nid_ent:
                nid = nid_ent.group(1)
            else:
                msg = "No valid nid found in %r, line (%d): %r" \
                    % (changelog_filepath,
                       curr_line,
                       line)
                vlogger.warning(msg)
                if verbose:
                    print_stderr("WARNING: %s" % msg)

            if nid and nid in self_nids:
                skipped['nids'][nid] = skipped['nids'].get(nid, 0) + 1
                # vlogger.debug("Skipping backup metadata entry: %s: %r" \
                #    % (fid, path))
                line = fh.readline()
                continue

            # Get target fid (tfid)

            tfid_ent = tfid_re.search(line)
            if not tfid_ent:
                msg = "No valid tfid found in %r, line (%d): %r" \
                    % (changelog_filepath,
                       curr_line,
                       line)
                vlogger.warning(msg)
                if verbose:
                    print_stderr("WARNING: %s" % msg)
                line = fh.readline()
                continue
            tfid_idx = tfid_ent.span()[0]
            basearr = line[:tfid_idx].split(" ")
            recno = int(basearr[0])
            tfid = tfid_ent.group(1)
            # tfid == "0:0x0:0x0" is rename,
            # use source fid (sfid) as source and target fid
            # are the same before and after rename
            if tfid == "0:0x0:0x0":
                # NOTE: Always verify renamed entries
                fid_mtime = 0
                sfid_ent = sfid_re.search(line)
                fid = sfid_ent.group(1)
                renamed = checkpoint_result['renamed'].get(fid, {})
                renamed['count'] = renamed.get('renamed', 0) + 1
                checkpoint_result['renamed'][fid] = renamed
                # vlogger.debug("Using sfid: %r" % fid)
            elif renamed_only:
                fid = tfid
                resolved_fids[fid] = True
            else:
                fid = tfid
                # vlogger.debug("Using tfid from: %r" % fid)

            if checkpoint_result.get('start_recno', 0) == 0:
                checkpoint_result['start_recno'] = recno
            checkpoint_result['end_recno'] = recno

            if resolved_fids.get(fid, False):
                skipped['resolved'][fid] = skipped['resolved'].get(fid, 0) + 1
                # vlogger.debug("Skipping %d (%d/%d): %s: %r" \
                #    % (recno,
                #    checkpoint_result['start_recno'],
                #    checkpoint_result['end_recno'],
                #    fid, changelog_filepath))
                line = fh.readline()
                continue

            retval = __fid2result(configuration,
                                  vlogger,
                                  mountpoint,
                                  fid,
                                  checkpoint_result,
                                  skipped,
                                  verify_mtime=fid_mtime,
                                  verbose=verbose)
            resolved_fids[fid] = True
            line = fh.readline()
        fh.close()
        curr_changelog += 1

        # Don't check dirty in renamed_only mode
        # TODO: Move dirty check to it's own function

        if not renamed_only:
            # Process backupmap dirty files for active entries
            # NOTE: A file can be opened before 'start_timestamp' changelog
            #       and closed after 'end_timestamp' changlog
            #       and therefore not taken into account though
            #       changelog parsing
            # NOTE: We can't rely merely on dirty file parsing
            #       as a crusial part of the verfication is checking if
            #       the backupmap generator and hereby
            #       the dirty file detection is valid.
            dirty_filepath = path_join(configuration,
                                       meta_basepath,
                                       backupmap_dirname,
                                       timestamp,
                                       backupmap_merged_dirname,
                                       convert_utf8=False,
                                       logger=vlogger)
            # NOTE: Dirty filepath might be missing if backupmap failed
            if not os.path.isdir(dirty_filepath):
                msg = "Skipping dirty due to missing: %r" % dirty_filepath
                logger.warning(msg)
                if verbose:
                    print_stderr("WARNING: %s" % msg)
            else:
                dirty_re = re.compile("[0-9]+\\.[0-9]+\\.dirty\\.pck")
                dirty_filelist = []
                with os.scandir(dirty_filepath) as it:
                    for entry in it:
                        dirty_ent = dirty_re.fullmatch(entry.name)
                        if dirty_ent:
                            dirty_filelist.append(entry.path)
                for dirty_filepath in dirty_filelist:
                    dirty_diana = unpickle(configuration,
                                           dirty_filepath,
                                           logger=vlogger)
                    if not dirty_diana:
                        retval = False
                        msg = "Failed to load dirty: %r" % dirty_filepath
                        vlogger.error(msg)
                        if verbose:
                            print_stderr("ERROR: %s" % msg)
                        break
                    for path, values in dirty_diana.items():
                        # Skip backup meta data
                        if path.startswith(backupmeta_dirname + os.sep):
                            # msg = "Skipping dirty metadata: %r" \
                            #    % path
                            # vlogger.debug(msg)
                            # if verbose and configuration.loglevel == 'debug':
                            #    print_stderr(msg)
                            continue
                        if not isinstance(values, dict):
                            msg = "Skipping malformed dirty format for: %r" \
                                  % path
                            vlogger.warning(msg)
                            if verbose:
                                print_stderr("WARNING: %s" % msg)
                            continue
                        # NOTE: Dirty use: "[FID]"
                        dirty_fid = values.get(
                            'fid', '').lstrip('[').rstrip(']')
                        if not dirty_fid:
                            msg = "No fid's found in %r" \
                                % dirty_filepath
                            vlogger.warning(msg)
                            if verbose:
                                print_stderr("WARNING: %s" % msg)
                            break
                        if resolved_fids.get(dirty_fid, False):
                            skipped['dirty'][fid] = skipped['dirty'].get(
                                fid, 0) + 1
                            msg = "Skipping dirty resolved fid: %s" \
                                % dirty_fid
                            vlogger.debug(msg)
                            # if verbose and configuration.loglevel == 'debug':
                            #    print_stderr(msg)
                            # NOTE: Do not count this in 'skipped'
                            #       as that is for changelog entries
                            continue
                        msg = "Resolving dirty entry: %s (%r)" \
                            % (dirty_fid,
                               dirty_filepath)
                        vlogger.debug(msg)
                        # if verbose and configuration.loglevel == 'debug':
                        #    print_stderr(msg)
                        retval = __fid2result(configuration,
                                              vlogger,
                                              mountpoint,
                                              dirty_fid,
                                              checkpoint_result,
                                              skipped,
                                              verbose=verbose)
                        resolved_fids[dirty_fid] = True
                        if not retval:
                            break

        # Save checkpoint
        # incuding result and snapshot_result update

        (status, last_checkpoint) \
            = __checkpoint(configuration,
                           vlogger,
                           total_t1,
                           curr_changelog,
                           total_changelogs,
                           curr_line,
                           total_lines,
                           result,
                           snapshot_result,
                           checkpoint_result,
                           verify_timestamp,
                           timestamp,
                           resolved_fids,
                           skipped,
                           last_checkpoint=last_checkpoint,
                           verbose=verbose)
        if not status:
            retval = False

        # Show summary

        snapshot_files_count = 0
        snapshot_bytes_count = 0
        for _, value in snapshot_result['fs'].items():
            snapshot_files_count += 1
            if value.get('checksum', None):
                snapshot_bytes_count += value.get('size', 0)

        changelog_t2 = time.time()
        stats = __create_stats(configuration,
                               vlogger,
                               snapshot_result,
                               resolved_fids,
                               skipped)
        msg = "Parsed changelog %d/%d, snapshot: %d (%s), lines: %d" \
            % (curr_changelog,
                total_changelogs,
                timestamp,
                datestr,
                total_lines) \
            + ", start_recno: %d, end_recno: %d" \
            % (snapshot_result['start_recno'],
               snapshot_result['end_recno']) \
            + ", resolved: %d, skipped: %d, deleted: %d, renamed: %d" \
            % (stats['resolved'],
               stats['skipped'],
               stats['deleted'],
               stats['renamed']) \
            + ", size: %s, files: %d, dirs: %d, other: %d" \
            % (human_readable_filesize(stats['bytes']),
               stats['files'],
               stats['dirs'],
               stats['other']) \
            + " in %d secs" % int(changelog_t2-changelog_t1)
        vlogger.info(msg)
        if verbose:
            print_stderr(msg)

        if renamed_only:
            __log_rename_stats(configuration,
                               vlogger,
                               snapshot_result,
                               verbose=verbose)

        if not retval:
            break

    # Unmount snapshot

    (status, _) = umount_snapshot(configuration,
                                  snapshot,
                                  postfix='inprogress_verify')

    # Create last verified symlink

    if retval and update_last_verified:
        rel_verify_filepath = path_join(configuration,
                                        backup_verify_dirname,
                                        "%d.pck" % verify_timestamp,
                                        logger=vlogger)
        status = make_symlink(configuration,
                              rel_verify_filepath,
                              last_verified_name,
                              working_dir=meta_basepath,
                              force=True,
                              logger=vlogger)
        if not status:
            retval = False
            msg = "Failed to create last verified symlink: %s -> %s in %r" \
                % (rel_verify_filepath,
                   last_verified_name,
                   meta_basepath)
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Remove inprogress marker

    status = remove_inprogress_verify(configuration,
                                      vlogger,
                                      verify_timestamp)
    if not status:
        retval = False
        msg = "verify: Failed to remove inprogress marker"
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Show summary

    stats = __create_stats(configuration,
                           vlogger,
                           result,
                           resolved_fids,
                           skipped)
    total_t2 = time.time()
    msg = "Verified source snapshot: %d (%s) using %d source changelog(s):\n" \
        % (verify_timestamp,
           verify_datestr,
           total_changelogs)
    for source_timestamp in result.get('snapshot_timestamps', []):
        source_timestamp_datestr = datetime.datetime.fromtimestamp(
            source_timestamp).strftime(date_format)
        msg += "%d (%s)\n" % (source_timestamp, source_timestamp_datestr)
    msg += "start_recno: %d, end_recno: %d" \
        % (result['start_recno'],
           result['end_recno']) \
        + ", resolved: %d, skipped: %d, deleted: %d, renamed: %d\n" \
        % (stats['resolved'],
           stats['skipped'],
           stats['deleted'],
           stats['renamed'])
    msg += "Verified entries: %d, size: %s, files: %d, dirs: %d, other: %d" \
        % (stats['total'],
           human_readable_filesize(stats['bytes']),
           stats['files'],
           stats['dirs'],
           stats['other']) \
        + " in %d secs" % int(total_t2-total_t1)
    vlogger.info(msg)
    if verbose:
        print_stderr(msg)

    if renamed_only:
        __log_rename_stats(configuration, vlogger, result, verbose=verbose)

    return retval
