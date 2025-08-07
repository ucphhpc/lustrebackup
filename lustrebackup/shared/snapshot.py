#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# snapshot - lustre backup helpers
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

"""Backup snapshot helpers"""

import os
import time
import datetime
import re

from lustrebackup.shared.base import print_stderr, force_unicode
from lustrebackup.shared.defaults import last_verified_name, \
    date_format, backup_verify_dirname
from lustrebackup.snapshot.mgs import create_snapshot_mgs, \
    destroy_snapshot_mgs, umount_snapshot_mgs
from lustrebackup.shared.lock import acquire_snapshot_lock
from lustrebackup.snapshot.client import umount_snapshot
from lustrebackup.snapshot.client import create_snapshots_dict,\
    get_snapshots, get_inprogress_snapshots
from lustrebackup.shared.fileio import path_join, unpickle, \
    release_file_lock


def __cleanup_snapshots(configuration,
                        cleanup_timestamp=int(time.time()),
                        keep_all_days=7,
                        keep_days=31,
                        keep_weeks=4,
                        keep_months=12,
                        keep_years=10,
                        preserve_verified=True,
                        dry_run=True,
                        do_lock=True,
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
    # Acquire snapshot log
    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            msg = "cleanup_snapshots: " \
                + "Failed to acquire snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return (False, None, None)
    # Generate cleanup date string
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
                              before_timestamp=cleanup_timestamp,
                              do_lock=False)
    # Don't cleanup snapshots inprogress
    (status, inprogress_snapshots) \
        = get_inprogress_snapshots(configuration,
                                   snapshots=snapshots,
                                   do_lock=False)
    if status:
        skip_timestamps = set(list(inprogress_snapshots.keys()))
    else:
        msg = "cleanup_snapshots: " \
            + "Failed to resolve inprogress_snapshots"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (False, [])

    # Only cleanup snapshots made by lustrebackup

    for timestamp, snapshot in snapshots.items():
        if not snapshot.get('lustrebackup', False):
            skip_timestamps.add(timestamp)

    # Find cleanup candidates

    sorted_timestamps = sorted(snapshots.keys(), reverse=True)
    destroy_candidates = []
    curr_timestamp = sorted_timestamps[0]
    # NOTE: Do not destroy oldest snapshot
    for idx in range(0, len(sorted_timestamps)-1):
        snapshot_timestamp = sorted_timestamps[idx]
        next_snapshot_timestamp = sorted_timestamps[idx+1]
        if snapshot_timestamp in skip_timestamps:
            msg = "cleanup_snapshots: skipping protected     snapshot: %d" \
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
                              if timestamp not in preserve_candidates]

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
            destroy_retval = destroy_snapshot_mgs(configuration,
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

    # TODO: Cleanup all snapshot lists (raw/pck) before last full fetch

    # If dry run *pretent* that all destroy_candidates
    # was destroyed

    if dry_run:
        destroyed_snapshots = destroy_candidates

    remaining_snapshots = [timestamp for timestamp in sorted_timestamps
                           if timestamp not in destroyed_snapshots]
    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            msg = "cleanup_snapshots: " \
                + "Failed to release snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            retval = False

    return (retval,
            destroyed_snapshots,
            remaining_snapshots)


def create_snapshot(configuration,
                    snapshot_name=None,
                    snapshot_timestamp=int(time.time()),
                    comment='Auto generated snapshot',
                    verbose=False):
    """Create lustre snapshot on MGS and update client snapshot list"""
    # Create MGS snapshot
    logger = configuration.logger
    retval = True
    snapshot_timestamp \
        = create_snapshot_mgs(configuration,
                              snapshot_name=snapshot_name,
                              snapshot_timestamp=snapshot_timestamp,
                              comment=comment,
                              verbose=verbose)
    if snapshot_timestamp:
        msg = "Created %r snapshot with timestamp: %d" \
            % (configuration.lustre_fsname,
               snapshot_timestamp)
        logger.info(msg)
        if verbose:
            print_stderr(msg)
    else:
        msg = "Failed to create new snapshot for %r" \
            % configuration.lustre_fsname
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Update client snapshot list

    snapshots_dict_filepath \
        = create_snapshots_dict(configuration,
                                update_timestamp=snapshot_timestamp,
                                snapshot_timestamp=snapshot_timestamp,
                                snapshot_name=snapshot_name,
                                update_last=True,
                                verbose=verbose)
    if snapshots_dict_filepath:
        msg = "Updated %r snapshots info: %r" \
            % (configuration.lustre_fsname,
               snapshots_dict_filepath)
        logger.info(msg)
        if verbose:
            print_stderr(msg)
    else:
        retval = False
        msg = "Falied to update %r snapshots info" \
            % configuration.lustre_fsname
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def destroy_snapshot(configuration,
                     snapshot_name,
                     snapshot_timestamp=None,
                     verbose=False):
    """Destroy lustre snapshot on MGS and update client snapshot list"""
    # Destroy MGS snapshot
    logger = configuration.logger
    retval = True
    status = destroy_snapshot_mgs(configuration,
                                  snapshot_name,
                                  verbose=False)
    if status:
        msg = "Destroyed snapshot: %r" % snapshot_name
        logger.info(msg)
        if verbose:
            print_stderr(msg)
    else:
        msg = "Failed to destroy snapshot: %r" % snapshot_name
        logger.info(msg)
        if verbose:
            print_stderr(msg)
        return False

    # Update client snapshot list
    # NOTE: save_timestamp is used as updated list filename

    save_timestamp = time.time()
    snapshots_dict_filepath \
        = create_snapshots_dict(configuration,
                                update_timestamp=save_timestamp,
                                snapshot_name=snapshot_name,
                                snapshot_timestamp=snapshot_timestamp,
                                update_last=True,
                                verbose=verbose)
    if not snapshots_dict_filepath:
        retval = False
        msg = "Failed to update snapshot list for destroyed snapshot: %d" \
            % snapshot_timestamp
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def cleanup_snapshots(configuration,
                      cleanup_timestamp=int(time.time()),
                      keep_all_days=7,
                      keep_days=31,
                      keep_weeks=4,
                      keep_months=12,
                      keep_years=10,
                      preserve_verified=True,
                      update_snapshot_list=True,
                      dry_run=True,
                      do_lock=True,
                      verbose=False,
                      ):
    """Cleanup lustre snapshot on MGS and update client snapshot list"""
    # Cleanup MGS snapshot
    logger = configuration.logger
    # Acquire snapshot log
    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            msg = "cleanup_snapshots: " \
                + "Failed to acquire snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return (False, [])
    (status,
     destroyed,
     remaining) = __cleanup_snapshots(configuration,
                                      cleanup_timestamp=cleanup_timestamp,
                                      keep_all_days=keep_all_days,
                                      keep_days=keep_days,
                                      keep_weeks=keep_weeks,
                                      keep_months=keep_months,
                                      keep_years=keep_years,
                                      preserve_verified=preserve_verified,
                                      dry_run=dry_run,
                                      do_lock=False,
                                      verbose=verbose,)
    retval = status
    if status and not dry_run and update_snapshot_list:
        # Update client snapshot list
        # NOTE: save_timestamp is used as updated list filename
        save_timestamp = time.time()
        retval = status
        for snapshot_timestamp in destroyed:
            snapshots_dict_filepath \
                = create_snapshots_dict(configuration,
                                        update_timestamp=save_timestamp,
                                        snapshot_timestamp=snapshot_timestamp,
                                        update_last=True,
                                        do_lock=False,
                                        verbose=verbose)
            if not snapshots_dict_filepath:
                retval = False
                msg = "Failed to update snapshot list" \
                    + " for destroyed snapshot: %d" \
                    % snapshot_timestamp
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            msg = "cleanup_snapshots: " \
                + "Failed to release snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            retval = False

    return (retval, destroyed, remaining)


def cleanup_snapshot_mounts(configuration,
                            update_snapshot_list=True,
                            force=False,
                            do_lock=True,
                            verbose=False):
    """Find unused mounted snapshots and unmount them"""
    logger = configuration.logger
    retval = True
    result = {'client': [],
              'MGS': []}
    skip_timestamps = []
    # Acquire snapshot lock
    if do_lock:
        lock = acquire_snapshot_lock(configuration)
        if not lock:
            msg = "cleanup_snapshot_mounts: " \
                + "Failed to acquire snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return (False, [])

    # Get snapshot list

    current_snapshots = get_snapshots(configuration,
                                      do_lock=False)
    if not current_snapshots:
        msg = "cleanup_snapshot_mounts: " \
            + "Failed to resolve current_snapshots"
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
                                                     postfix=None,
                                                     update_snapshot_list=False,
                                                     do_lock=False)
                if umounted:
                    result['client'].append(snapshot.get('timestamp', -1))
                if not status:
                    retval = False
                    msg = "cleanup_snapshot_mounts: " \
                        + "failed to umount snapshot: %r: %r" \
                        % (snapshot.get('fsname', ''),
                           snapshot.get('snapshot_name', ''))
                    logger.error(msg)
                    if verbose:
                        print_stderr("ERROR: %s" % msg)

    # cleanup stale MGS snapshot mounts

    if retval:
        for timestamp, snapshot in current_snapshots.items():
            if timestamp not in skip_timestamps:
                if force or snapshot.get('status', '') == 'mounted':
                    status = umount_snapshot_mgs(configuration,
                                                 snapshot,
                                                 force=force)
                    if status:
                        result['MGS'].append(snapshot.get('timestamp', -1))
                    elif not force:
                        retval = False

    # Finally update snapshot list if requested

    if update_snapshot_list:
        for timestamp in result['client'] + result['MGS']:
            snapshots_dict_filepath \
                = create_snapshots_dict(configuration,
                                        update_timestamp=time.time(),
                                        snapshot_timestamp=timestamp,
                                        update_last=True,
                                        verbose=verbose,
                                        do_lock=False)
            if not snapshots_dict_filepath:
                retval = False
                msg = "Failed to update snapshot list for" \
                    + "umounted MGS snapshot: %d" \
                    % timestamp
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)

    # Release lock

    if do_lock:
        lock_status = release_file_lock(configuration, lock)
        if not lock_status:
            msg = "cleanup_snapshot_mounts: " \
                + "Failed to release snapshot lock"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            retval = False

    return (retval, result)
