#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# changelog - lustre backup helpers
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

"""This module contains various helpers used to generate and parse
lustre snapshot changelogs and resolve the corresponding fids
to paths

Changelog must be enabled on the MGS using the following commands from:
https://doc.lustre.org/lustre_manual.xhtml#lustre_changelogs
$> lctl --device fsname-MDTnumber changelog_register
$> lctl set_param -P mdd.FSNAME-MDT.changelog_mask="CREAT MKDIR HLINK SLINK MKNOD UNLNK RMDIR RENME RNMTO OPEN CLOSE LYOUT TRUNC SATTR XATTR HSM MTIME CTIME MIGRT FLRW RESYNC"
"""

import os
import sys
import re
import time
import multiprocessing
import traceback
import psutil

from lustrebackup.shared.base import __hash, force_unicode
from lustrebackup.shared.configuration import get_configuration_object
from lustrebackup.shared.defaults import changelog_dirname, \
    changelog_parsed_dirname, changelog_merged_dirname, \
    changelog_filtered_dirname
from lustrebackup.shared.fileio import pickle, path_join, unpickle, \
    makedirs_rec, make_symlink
from lustrebackup.shared.logger import Logger
from lustrebackup.shared.shell import shellexec
from lustrebackup.snapshot.client import mount_snapshot, \
    umount_snapshot
# import pygdb.breakpoint


def __create_changemap_worker(conf_file,
                              raw_changelog_filepath,
                              changelog_parsed_path,
                              start_recno,
                              start_fpos,
                              end_fpos,
                              snapshot_timestamp,
                              idx,
                              nprocs,):
    """Generate lustre changemap  by parsing raw lustre changelog.
    The changemap datastructure dictionaries with lustre file identifiers (FID)
    as keys and list of operations as values.
    Example:
    {'[0x200001bae:0xd476:0x0']:
        [{'ops':
            {'10OPEN': [1412396152, 1412397075],
            '11CLOSE': [1412396153, 1412397076]},
            'pfid': {},
            'sfid': {},
            'spfid': {},
            'sfile': {},
            'tfile': {}}
        ]
    }
    The file with tfid 0x200001bae:0xd476:0x0 was opened and closed twice.
    The open operations was recorded with changelog record number:
    1412396152 and 1412397075.
    The close operations ware recorded with changelog record number":
    1412396153 and 1412397076.
    There were no information about:
    pfid: parent FID
    sfid: source FID
    spfid: source parent FID
    sfile: source file
    tfile: target file

    The changemaps are divided into buckets by each worker process
    saving the result to disk as:
    'WPI.CPI.BHI.SP.EP.pck'
    where:
    WPI: Index of this worker
    CPI: Checkpoint index
    BI: Bucket hash index
    SP: Start changelog record number (for debug)
    EP: End changelog record number (for debug)

    FOPS related to a single FID will (most likely) end up in
    several changemap files due to either checkpointing
    within a single worker process or due to FOPS for the FID
    being scattered all over the raw changelog file.
    Calling __merge_changemap after __create_changemap will
    merge all FOPS related to a single FID and ensure that every FID
    is only presented once in the overall changamap.
    """
    status = True
    checkpoint_interval = 0
    skipped_start_count = 0
    skipped_zero_count = 0
    skipped_processed_count = 0
    processed = 0
    result = {'msg': "",
              'min_recno': sys.maxsize,
              'max_recno': 0,
              'records': 0,
              'min_date': '',
              'max_date': '',
              'min_timestamp': 0,
              'max_timestamp': 0,
              }
    try:
        # Use separate log file for changes worker
        configuration = get_configuration_object(conf_file=conf_file,
                                                 skip_log=True)
        # User local_logger to log path resolves for each timestamp
        worker_log_filepath = path_join(configuration,
                                        configuration.lustre_meta_basepath,
                                        changelog_dirname,
                                        "%d.log" % snapshot_timestamp)
        worker_logger_obj = Logger(configuration.loglevel,
                                   logfile=worker_log_filepath,
                                   app='__create_changemap_worker.%d.%d'
                                   % (snapshot_timestamp, idx))
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result['msg'] = err
        return (False, result)
    try:
        pid = os.getpid()
        process = psutil.Process(pid)
        available_memory = psutil.virtual_memory().available
        # Reserve memory for system
        sys_memory_factor = configuration.system_sys_memory_factor
        # Only use half of user memory to be able to have
        # two datastructures in memory at once
        user_memory_factor = configuration.system_user_memory_factor/2
        max_proc_memory = (available_memory
                           * sys_memory_factor
                           * user_memory_factor) \
            / (nprocs)
        max_proc_memory_mb = int(max_proc_memory/1024**2)
        logger.debug("%d.%d: Using max proc memory: %d bytes %d MB"
                     % (idx, pid, max_proc_memory, max_proc_memory_mb))

        # Distribute the tfids in nproc buckets
        # These are used by __merge_changemap
        changelogmap = {}
        for i in range(nprocs):
            changelogmap[i] = {}

        tfid_re = re.compile("t=\\[(.*?)\\]")
        pfid_re = re.compile("p=\\[(.*?)\\]")
        sfid_re = re.compile("s=\\[(.*?)\\]")
        spfid_re = re.compile("sp=\\[(.*?)\\]")
        date_re = re.compile("([0-9]{2}:[0-9]{2}:[0-9]{2}).[0-9]{9}"
                             + " ([0-9]{4}\\.[0-9]{2}\\.[0-9]{2})")
        mode_re = re.compile("m=([r|-][w|-][x|-])")
        t1 = time.time()
        fh = open(raw_changelog_filepath, 'r')

        # Seek to posistion processed by this worker

        if start_fpos > 0:
            # logger.debug("%d: checkpount" % idx)
            fh.seek(start_fpos)
            line = fh.readline()

        pickle_idx = 0
        checkpoint_interval = 0
        line = fh.readline()
        while line:
            line = line.rstrip('\r\n')
            fpos = fh.tell()
            linelen = len(line)
            tfid_ent = tfid_re.search(line)
            tfid_idx = tfid_ent.span()[0]
            basearr = line[:tfid_idx].split(" ")
            recno = int(basearr[0])
            # logger.warning("%d.%d: checkpoint recno: %d, line: %s" \
            #       % (idx, pid, recno, line) \
            #       + ", tfid_ent: %s, tfid_idx: %s, bassarr: %s" \
            #       % (tfid_ent, tfid_idx, basearr))
            if recno < start_recno:
                checkpoint_t2 = time.time()
                # logger.warning("%d.%d checkpoint" \
                #    % (idx, pid) \
                #    + " Skipped recno %d < start_recno: %d (%d secs)" \
                #    % (recno, start_recno, checkpoint_t2-t1))
                skipped_start_count += 1
                if fpos > end_fpos:
                    break
                line = fh.readline()
                continue

            # Update min and max recno
            if recno < result['min_recno']:
                date_ent = date_re.search(line)
                result['min_recno'] = recno
                result['min_date'] = "%s" \
                    % date_ent.group(0)
                result['min_timestamp'] = \
                    int(time.mktime(time.strptime("%s %s"
                                                  % (date_ent.group(1),
                                                     date_ent.group(2)),
                                                  '%H:%M:%S %Y.%m.%d')))
            if recno > result['max_recno']:
                date_ent = date_re.search(line)
                result['max_recno'] = recno
                result['max_date'] = "%s" \
                    % date_ent.group(0)
                result['max_timestamp'] = \
                    int(time.mktime(time.strptime("%s %s"
                                                  % (date_ent.group(1),
                                                     date_ent.group(2)),
                                                  '%H:%M:%S %Y.%m.%d')))

            fsop = basearr[1]
            pfid_ent = pfid_re.search(line)
            sfid_ent = sfid_re.search(line)
            spfid_ent = spfid_re.search(line)
            mode_ent = mode_re.search(line)
            # logger.debug("%d.%d: checkpoint recno: %d, fsop: %s" \
            #    % (idx, pid, recno, fsop) \
            #    + ", pfid_ent: %s, sfid_ent: %s, spfid_ent: %s" \
            #    % ( pfid_ent, sfid_ent, spfid_ent))
            if not tfid_ent.group():
                # logger.warning("%d.%d: checkpoint: recno: %d" \
                #                % (idx, pid, recno))
                status = False
                result['msg'] = "Malformed changelog entry: %s" % line
                logger.error("%d.%d: %s" % (idx, pid, result['msg']))
                break

            tfid = "[%s]" % tfid_ent.group(1)

            # Split tfid in nproc buckets,
            # these are used by __merge_changemap
            tidx = __hash(tfid) % nprocs
            # logger.warning("%d.%d: checkpoint: recno: %d" \
            #      % (idx, pid, recno) \
            #      + ", tfid: %s, tidx: %d" \
            #      % (tfid, tidx))

            # Rename ops have FID [0:0x0:0x0]
            # Ops for those are listed

            if tfid != "[0:0x0:0x0]" \
                    and tfid in changelogmap[tidx]:
                fop = changelogmap[tidx][tfid][0]
            else:
                fop = {'ops': {},
                       'pfid': {},
                       'sfid': {},
                       'spfid': {},
                       'sfile': {},
                       'tfile': {},
                       'modes': {},
                       }

            # Store recno for each operation,
            # used for ordering eg. rename ops
            fsop_recno = fop['ops'].get(fsop, [])

            # On resume we might hit same recno
            if recno not in fsop_recno:
                if not fsop_recno:
                    fop['ops'][fsop] = fsop_recno
                fsop_recno.append(recno)

                tfile_idx1 = -1
                tfile_idx2 = -1
                sfile_idx1 = -1
                sfile_idx2 = -1
                if mode_ent:
                    key = "%s" % mode_ent.group(1)
                    value = fop['modes'].get(key, [])
                    value.append(recno)
                    fop['modes'][key] = value
                if pfid_ent:
                    key = "[%s]" % pfid_ent.group(1)
                    value = fop['pfid'].get(key, [])
                    value.append(recno)
                    fop['pfid'][key] = value
                    tfile_idx1 = pfid_ent.span()[1]+1
                    tfile_idx2 = linelen
                if sfid_ent:
                    key = "[%s]" % sfid_ent.group(1)
                    value = fop['sfid'].get(key, [])
                    value.append(recno)
                    fop['sfid'][key] = value
                    tfile_idx2 = sfid_ent.span()[0]-1
                if spfid_ent:
                    key = "[%s]" % spfid_ent.group(1)
                    value = fop['spfid'].get(key, [])
                    value.append(recno)
                    fop['spfid'][key] = value
                    sfile_idx1 = spfid_ent.span()[1]+1
                    sfile_idx2 = linelen
                if tfile_idx1 > -1 and tfile_idx2 > -1:
                    key = "%s" % line[tfile_idx1:tfile_idx2]
                    value = fop['tfile'].get(key, [])
                    value.append(recno)
                    fop['tfile'][key] = value
                if sfile_idx1 > -1 and sfile_idx2 > -1:
                    key = "%s" % line[sfile_idx1:sfile_idx2]
                    value = fop['sfile'].get(key, [])
                    value.append(recno)
                    fop['sfile'][key] = value
                if tfid == "[0:0x0:0x0]":
                    temp = changelogmap[tidx].get(tfid, [])
                    temp.append(fop)
                    changelogmap[tidx][tfid] = temp
                else:
                    changelogmap[tidx][tfid] = [fop]
                processed += 1
                # logger.debug("%d.%d: checkpoint: recno: %d" \
                #    % (idx, pid, recno) \
                #    + ", tfid: %s, tidx: %d, changelogmap: %s" \
                #    % (tfid, tidx, changelogmap[tidx][tfid]))
                # logger.debug("%d: %d: %s: %s" \
                # % (idx, recno, tfid, fopsmap[tfid]))
            else:
                skipped_processed_count += 1
                # logger.debug("%d.%d: checkpoint: recno: %d" \
                #    % (idx, pid, recno) \
                #    + ", tfid: %s, tidx: %d, skipped" \
                #    % (tfid, tidx))
            result['records'] += 1

            # Log progress and create checkpoint

            if checkpoint_interval == 0:
                rss_bytes = process.memory_info().rss
                if rss_bytes >= max_proc_memory:
                    checkpoint_interval = result['records']
                    logger.info("%d.%d new checkpoint_interval: %d"
                                % (idx, pid, checkpoint_interval)
                                + ", current memory usage: "
                                + "%d > max_proc_memory %d"
                                % (rss_bytes, max_proc_memory))
            if checkpoint_interval > 0 \
                    and result['records'] % checkpoint_interval == 0:
                rss_bytes = process.memory_info().rss
                for i in range(nprocs):
                    changelogmap_file = "%d.%d.%d.%d.%d.pck" \
                                        % (idx, pickle_idx, i,
                                           start_fpos, end_fpos)
                    changelogmap_filepath = path_join(configuration,
                                                      changelog_parsed_path,
                                                      changelogmap_file,
                                                      convert_utf8=False)
                    status = pickle(
                        configuration, changelogmap[i], changelogmap_filepath)
                    # logger.debug("%d.%d: pickle status: %s" \
                    #               % (idx, pid, status))
                    if status:
                        changelogmap[i] = {}
                    else:
                        result['msg'] = "%d.%d: Failed to save %r" % (
                            idx, pid, changelogmap_filepath)
                        break
                pickle_idx += 1
                checkpoint_t2 = time.time()
                progress = ((float(fpos)-float(start_fpos)) /
                            (float(end_fpos)-float(start_fpos)))*100
                logger.info("%d.%d ckeckpoint reached (%d): %d records"
                            % (idx, pid, checkpoint_interval, result['records'])
                            + ", processed: %d, skipped_processed: %d"
                            % (processed, skipped_processed_count)
                            + ", skipped_zero: %d, skipped_start: %d"
                            % (skipped_zero_count, skipped_start_count)
                            + ", min_recno: %d, max_recno: %d, progress: %d"
                            % (result['min_recno'], result['max_recno'], progress)
                            + ", (%d/%d/%d) in %d secs"
                            % (start_fpos, fpos, end_fpos, checkpoint_t2-t1))
            # Process one line after end_fpos and then break
            # NOTE: Each worker skip first line after 'seek'
            # to ensure that a full line is read
            if fpos > end_fpos:
                break
            line = fh.readline()
        fpos = fh.tell()
        fh.close()
        # Save final changelog map
        for i in range(nprocs):
            changelogmap_file = "%d.%d.%d.%d.%d.pck" \
                % (idx, pickle_idx, i, start_fpos, end_fpos)
            changelogmap_filepath = path_join(configuration,
                                              changelog_parsed_path,
                                              changelogmap_file,
                                              convert_utf8=False)
            status = pickle(
                configuration, changelogmap[i], changelogmap_filepath)
            # logger.debug("%d.%d: pickle status: %s" % (idx, pid, status))
            if not status:
                result['msg'] = "%d.%d: Failed to save %r" % (
                    idx, pid, changelogmap_filepath)
                break
    except Exception:
        status = False
        result['msg'] = str(traceback.format_exc())

    return (status, result)


def __create_changemap(configuration,
                       changelog_basepath,
                       snapshot,
                       start_recno):
    """Generate lustre changemap using multiprocessing to parse
    raw lustre changelog.
    Each worker process parses a part of the raw changelog
    """

    logger = configuration.logger

    result = {'msg': "",
              'min_recno': sys.maxsize,
              'max_recno': 0,
              'records': 0,
              'min_date': '',
              'max_date': '',
              'min_timestamp': 0,
              'max_timestamp': 0,
              'parse_time': 0,
              }
    raw_changelog_filepath = fetch_raw_changelog(configuration, snapshot)
    if raw_changelog_filepath is None:
        msg = "Failed to fetch raw changelog for snapshot: %s" \
            % snapshot
        logger.error(msg)
        result['msg'] = msg
        return (False, result)

    snapshot_timestamp = snapshot.get('timestamp', '')
    if not snapshot_timestamp:
        msg = "Missing timestamp from snapshot: %s" % str(snapshot)
        logger.error(msg)
        result['msg'] = msg
        return (False, result)

    changelog_parsed_path = path_join(configuration,
                                      changelog_basepath,
                                      snapshot_timestamp,
                                      changelog_parsed_dirname,
                                      convert_utf8=False)

    status = makedirs_rec(configuration, changelog_parsed_path)
    if not status:
        msg = "%d.%d Failed to create changelogmap path: %r" \
            % changelog_parsed_path
        logger.error(msg)
        result['msg'] = msg
        return (False, result)

    nprocs = configuration.system_nprocs
    pool = multiprocessing.Pool(processes=nprocs)
    raw_changelog_filesize = os.path.getsize(raw_changelog_filepath)
    worker_raw_filerange = raw_changelog_filesize/nprocs

    t1 = time.time()
    tasks = {}
    for idx in range(nprocs):
        task = {}
        tasks[idx] = task
        start_fpos = idx * worker_raw_filerange
        if idx == nprocs-1:
            end_fpos = raw_changelog_filesize
        else:
            end_fpos = start_fpos + worker_raw_filerange
        task['start_fpos'] = start_fpos
        task['end_fpos'] = end_fpos
        logger.info("Starting __create_changemap_worker: %d (%d, %d)" %
                    (idx, start_fpos, end_fpos))
        task['proc'] = pool.apply_async(__create_changemap_worker,
                                        (configuration.config_file,
                                         raw_changelog_filepath,
                                         changelog_parsed_path,
                                         start_recno,
                                         start_fpos,
                                         end_fpos,
                                         snapshot_timestamp,
                                         idx,
                                         nprocs,))
    # Wait for tasks to finish

    status = True
    for idx in tasks:
        task = tasks[idx]
        start_fpos = task['start_fpos']
        end_fpos = task['end_fpos']
        proc = task['proc']
        logger.info("Waiting for parse_changelog task: %d (%d,%d)" %
                    (idx, start_fpos, end_fpos))
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            msg = "__create_changemap_worker: %d (%d,%d) finished with: " \
                % (idx, start_fpos, end_fpos) \
                + "status: %s and message: %s " \
                % (worker_status, worker_result)
            if worker_status:
                logger.debug("%d: %s" % (idx, msg))
                result['records'] += worker_result['records']
                if worker_result['min_recno'] < result['min_recno']:
                    result['min_recno'] = worker_result['min_recno']
                    result['min_date'] = worker_result['min_date']
                    result['min_timestamp'] = worker_result['min_timestamp']
                if worker_result['max_recno'] > result['max_recno']:
                    result['max_recno'] = worker_result['max_recno']
                    result['max_date'] = worker_result['max_date']
                    result['max_timestamp'] = worker_result['max_timestamp']
            else:
                status = False
                logger.error("%d: %s" % (idx, msg))
        else:
            status = False
            logger.error("__create_changemap_worker (%d,%d)"
                         % (start_fpos, end_fpos)
                         + " failed with unknown error")

    t2 = time.time()

    # Save parse result
    result['parse_time'] = t2-t1

    changelog_result_path = path_join(configuration,
                                      changelog_basepath,
                                      "%s.pck" % snapshot_timestamp,
                                      convert_utf8=False)

    status = pickle(configuration,
                    result,
                    changelog_result_path)
    # logger.debug("%d.%d: pickle status: %s" % (idx, pid, status))
    if not status:
        logger.error("Failed to save changelog parse result to: %r"
                     % changelog_result_path)

    logger.info("Parsed %s entries in %d secs" % (result, t2-t1))
    pool.terminate()

    return (status, result)


def __merge_changemap_worker(conf_file,
                             changelog_parse_filepaths,
                             changemap_merged_path,
                             snapshot_timestamp,
                             idx,
                             nprocs):
    """Worker process merging changemap files
    generated by __create_changemap_worker
    """
    status = True
    result = {'msg': "",
              'tfid_count': 0,
              }
    try:
        # Use separate log file for changes worker
        configuration = get_configuration_object(conf_file=conf_file,
                                                 skip_log=True)
        # User local_logger to log path resolves for each timestamp
        worker_log_filepath = path_join(configuration,
                                        configuration.lustre_meta_basepath,
                                        changelog_dirname,
                                        "%d.log" % snapshot_timestamp)
        worker_logger_obj = Logger(configuration.loglevel,
                                   logfile=worker_log_filepath,
                                   app='__merge_changemap_worker.%d.%d'
                                   % (snapshot_timestamp, idx))
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result['msg'] = err
        return (False, result)
    try:
        t1 = time.time()
        pid = os.getpid()
        process = psutil.Process(pid)
        available_memory = psutil.virtual_memory().available
        # Reserve memory for system
        sys_memory_factor = configuration.system_sys_memory_factor
        # Only use halfof user memory
        # to be able to have two datastructures in memory at once
        user_memory_factor = configuration.system_user_memory_factor/2
        max_proc_memory = (available_memory
                           * sys_memory_factor
                           * user_memory_factor) \
            / (nprocs)
        max_proc_memory_mb = int(max_proc_memory/1024**2)
        logger.debug("%d.%d: Using max proc memory: %d bytes %d mb"
                     % (idx, pid, max_proc_memory, max_proc_memory_mb))
        changemap = {}
        pickle_idx = 0
        checkpoint_interval = 0
        changelogmap_files_cnt = len(changelog_parse_filepaths)
        processed_files = 0
        for changelogmap_file in changelog_parse_filepaths:
            changelogmap = unpickle(
                configuration, changelogmap_file, allow_missing=False)
            if not changelogmap:
                logger.info("%d.%d: Skipping empty changelogmap: %r"
                            % (idx, pid, changelogmap_file))
                continue

            # Merge all operations for each TFID,
            # distribute TFIDs among workers using key hash

            for tfid in changelogmap.keys():
                # Verify tfid hash
                hashval = __hash(tfid)
                if hashval % nprocs != idx:
                    raise ValueError("Invalid TFID for changelogmap_file: %r"
                                     % changelogmap_file
                                     + ", tfid: %s, hashval %s, nprocs: %d"
                                     % (tfid, hashval, nprocs)
                                     + ", hashval %% nprocs: %d"
                                     % (hashval % nprocs)
                                     + " should match idx: %d"
                                     % idx)
                __merge_parsed_changelog_entries(configuration,
                                                 changelogmap,
                                                 changemap,
                                                 tfid,)
                result['tfid_count'] += 1
                if checkpoint_interval == 0:
                    rss_bytes = process.memory_info().rss
                    rss_mb = int(rss_bytes/1024**2)
                    if rss_bytes >= max_proc_memory:
                        checkpoint_interval = result['tfid_count']
                        logger.info("%d.%d new checkpoint_interval: %d"
                                    % (idx, pid, checkpoint_interval)
                                    + ", current memory usage: "
                                    + "%d > max_proc_memory %d"
                                    % (rss_bytes, max_proc_memory))
                if checkpoint_interval > 0 \
                        and result['tfid_count'] % checkpoint_interval == 0:
                    rss_bytes = process.memory_info().rss
                    rss_mb = int(rss_bytes/1024**2)
                    logger.info("%d.%d ckeckpoint reached: (%d) %d"
                                % (idx, pid,
                                   checkpoint_interval,
                                   result['tfid_count'])
                                + ", rss mb: %d/%d"
                                % (rss_mb, max_proc_memory_mb))
                    changemap_file = "%d.%d.pck" \
                        % (idx, pickle_idx)
                    changemap_filepath = path_join(configuration,
                                                   changemap_merged_path,
                                                   changemap_file,
                                                   convert_utf8=False)
                    status = pickle(configuration, changemap,
                                    changemap_filepath)
                    # logger.debug("%d.%d: pickle status: %s" \
                    #               % (idx, pid, status))
                    if status:
                        changemap = {}
                    else:
                        result['msg'] = "%d.%d: Failed to save %r" % (
                            idx, pid, changemap_filepath)
                        break
                    pickle_idx += 1
                    checkpoint_t2 = time.time()
                    logger.info("%d.%d (%d): create changemap progress: "
                                % (idx, pid, rss_mb)
                                + "%d/%d files, %d tfids in %d secs"
                                % (processed_files,
                                    changelogmap_files_cnt,
                                    result['tfid_count'],
                                    checkpoint_t2-t1))
            processed_files += 1
        # Save final changemap
        changemap_file = "%d.%d.pck" \
            % (idx, pickle_idx)
        changemap_filepath = path_join(configuration,
                                       changemap_merged_path,
                                       changemap_file,
                                       convert_utf8=False)
        status = pickle(configuration, changemap, changemap_filepath)
        # logger.debug("%d.%d: pickle status: %s" % (idx, pid, status))
        if not status:
            result['msg'] = "%d.%d: Failed to save %r" % (
                idx, pid, changemap_filepath)
        t2 = time.time()
        logger.info("%d.%d: Found tfids: %d in %d secs"
                    % (idx, pid, result['tfid_count'], t2-t1))
    except Exception:
        status = False
        result['msg'] = str(traceback.format_exc())

    return (status, result)


def __merge_changemap(configuration,
                      changelog_basepath,
                      snapshot):
    """
    FOPS related to a single FID will (most likely) end up in
    several changemap files due to either checkpointing
    within a __create_changemap worker process or due to FOPS for the FID
    being scattered all over the raw changelog file.
    This function merges all FOPS related to a single FID
    and ensure that every FID is only presented once in the overall changamap.
    """
    result = {'msg': ""}
    logger = configuration.logger
    snapshot_timestamp = snapshot.get('timestamp', '')
    nprocs = configuration.system_nprocs
    # multiprocessing.log_to_stderr()
    pool = multiprocessing.Pool(processes=nprocs)
    t1 = time.time()
    changemap_merged_path = path_join(configuration,
                                      changelog_basepath,
                                      snapshot_timestamp,
                                      changelog_merged_dirname,
                                      convert_utf8=False)

    status = makedirs_rec(configuration, changemap_merged_path)
    if not status:
        msg = "Failed to create changemap_merged_path path: %r" \
            % changemap_merged_path
        logger.error(msg)
        result['msg'] = msg
        return (status, result)

    changelog_parsed_path = path_join(configuration,
                                      changelog_basepath,
                                      snapshot_timestamp,
                                      changelog_parsed_dirname,
                                      convert_utf8=False)
    logger.debug("changelog_parsed_path: %s" % changelog_parsed_path)

    # Changelogmaps are devided into nprocs by
    #  __hash(tfid) in __create_changemap

    changelog_parse_filepaths = {}
    for idx in range(nprocs):
        changelog_parse_filepaths[idx] = []
    changemap_parse_re = re.compile(
        "[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*\\.pck")
    with os.scandir(changelog_parsed_path) as it:
        for entry in it:
            if changemap_parse_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[2])
                changelog_parse_filepaths[idx].append(entry.path)

    nr_parsed_files = len(changelog_parse_filepaths)
    if nr_parsed_files < nprocs:
        msg = "Adjusting nprocs: %d to %d" % (nprocs, nr_parsed_files)
        logger.info(msg)

    tasks = {}
    for idx in range(nprocs):
        task = {}
        tasks[idx] = task
        logger.info("Starting __merge_changemap_worker: %d" % idx)
        task['proc'] = pool.apply_async(__merge_changemap_worker,
                                        (configuration.config_file,
                                         changelog_parse_filepaths[idx],
                                         changemap_merged_path,
                                         snapshot_timestamp,
                                         idx,
                                         nprocs,))
    # Wait for tasks to finish

    status = True
    total_tfid_count = 0
    for idx in tasks:
        task = tasks[idx]
        proc = task['proc']
        logger.info("Waiting for changemap task: %d" % idx)
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            msg = "__merge_changemap_worker: %d finished with: " \
                % idx \
                + "status: %s and message: %s " \
                % (worker_status, worker_result)
            if worker_status:
                logger.info("%d: %s" % (idx, worker_result))
            else:
                logger.error("%d: %s" % (idx, worker_result))
            logger.debug("%d: %s: %s" % (idx, worker_status, worker_result))
            if status:
                total_tfid_count += worker_result['tfid_count']
        else:
            status = False
            logger.error("__merge_changemap_worker: %d" % idx
                         + " failed with unknown error")
    t2 = time.time()
    logger.info("Created %d tfid changemap entries in %d secs" %
                (total_tfid_count, t2-t1))

    pool.terminate()

    return (status, result)


def __merge_parsed_changelog_entries(configuration,
                                     source_changemap,
                                     target_changemap,
                                     tfid,
                                     ):
    """Merges tfid entries from source_changemap,
    to target_changemap"""
    logger = configuration.logger
    status = True
    # Find all altries with tfid and merge operations
    target_fop = target_changemap.get(tfid, [])
    source_fop = source_changemap.get(tfid, [])

    if not target_fop:
        target_fop = source_fop
    else:
        if tfid == "[0:0x0:0x0]":
            target_fop.extend(source_fop)
        else:
            target_fop_dict = target_fop[0]
            source_fop_dict = source_fop[0]
            target_ops = target_fop_dict.get('ops', {})
            target_modes = target_fop_dict.get('modes', {})
            target_pfid = target_fop_dict.get('pfid', {})
            target_sfid = target_fop_dict.get('sfid', {})
            target_spfid = target_fop_dict.get('spfid', {})
            target_sfile = target_fop_dict.get('sfile', {})
            target_tfile = target_fop_dict.get('tfile', {})

            source_ops = source_fop_dict.get('ops', {})
            source_modes = source_fop_dict.get('modes', {})
            source_pfid = source_fop_dict.get('pfid', {})
            source_sfid = source_fop_dict.get('sfid', {})
            source_spfid = source_fop_dict.get('spfid', {})
            source_sfile = source_fop_dict.get('sfile', {})
            source_tfile = source_fop_dict.get('tfile', {})

            # Merge mode entries

            for modes, recos in source_modes.items():
                mode_records = target_modes.get(modes, [])
                mode_records.extend(recos)
                target_modes[modes] = mode_records
                target_fop_dict['modes'] = target_modes

            # Merge parent fid (pfid) entries

            for pfid, recos in source_pfid.items():
                pfid_records = target_pfid.get(pfid, [])
                pfid_records.extend(recos)
                target_pfid[pfid] = pfid_records
                target_fop_dict['pfid'] = target_pfid

            # Merge source fid (sfid) entries

            for sfid, recos in source_sfid.items():
                sfid_records = target_sfid.get(sfid, [])
                sfid_records.extend(recos)
                target_sfid[sfid] = sfid_records
                target_fop_dict['sfid'] = target_sfid

            # Merge source parent fid (spfid) entries

            for spfid, recos in source_spfid.items():
                spfid_records = target_spfid.get(spfid, [])
                spfid_records.extend(recos)
                target_spfid[spfid] = spfid_records
                target_fop_dict['spfid'] = target_spfid

            # Merge source file (sfile) entries

            for sfile, recos in source_sfile.items():
                sfile_records = target_sfile.get(sfile, [])
                sfile_records.extend(recos)
                target_sfile[sfile] = sfile_records
                target_fop_dict['sfile'] = target_sfile

            # Merge target file (tfile) entries

            for tfile, recos in source_tfile.items():
                tfile_records = target_tfile.get(tfile, [])
                tfile_records.extend(recos)
                target_tfile[tfile] = tfile_records
                target_fop_dict['tfile'] = target_tfile

            # Merge operation entries

            for op_key, op_value in source_ops.items():
                if op_key in target_ops.keys():
                    if op_value not in target_ops[op_key]:
                        target_ops[op_key].extend(op_value)
                else:
                    target_ops[op_key] = op_value
            # logger.debug("%d: tfid: %s, pfid: %s, sfid: %s, spfid: %s" \
            #    % (idx, tfid,
            #       target_fop_dict['pfid'],
            #       target_fop_dict['sfid'],
            #       target_fop_dict['spfid']) \
            #    + ", sfile: %s, tfile: %s, ops: %s" \
            #    % (target_fop_dict['sfile'],
            #        target_fop_dict['tfile'],
            #        target_ops))
    if status:
        target_changemap[tfid] = target_fop

    return status


def __filter_changemap_worker(conf_file,
                              changemap_filepaths,
                              changelog_merged_path,
                              changelog_filtered_path,
                              snapshot_timestamp,
                              idx,
                              nprocs):
    """Filter changemap, removing temporary files,
    removed dirs are saved to .rmdirs.pck for further inspection by
    __filter_changemap_parent_worker
    """
    status = True
    result = {'msg': "",
              'records': 0,
              'filtered': 0,
              'passed': 0,
              'rmdirs': 0,
              }
    try:
        # Use separate log file for changes worker
        configuration = get_configuration_object(conf_file=conf_file,
                                                 skip_log=True)
        # User local_logger to log path resolves for each timestamp
        worker_log_filepath = path_join(configuration,
                                        configuration.lustre_meta_basepath,
                                        changelog_dirname,
                                        "%d.log" % snapshot_timestamp)
        worker_logger_obj = Logger(configuration.loglevel,
                                   logfile=worker_log_filepath,
                                   app='__filter_changemap_worker.%d.%d'
                                   % (snapshot_timestamp, idx))
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result['msg'] = err
        return (False, result)
    try:
        pid = os.getpid()
        filtered_entries = []
        rmdirs = {}
        mode_write_re = re.compile("[r|-][w][x|-]")
        for filepath in changemap_filepaths:
            logger.debug("filepath: %s" % filepath)
            entries_filepath = filepath.replace(changelog_merged_path,
                                                changelog_filtered_path)
            logger.debug("entries_filepath1: %s" % entries_filepath)
            entries_filepath = entries_filepath.replace(".pck", ".entries.pck")
            logger.debug("entries_filepath2: %s" % entries_filepath)
            rmdirs_filepath = entries_filepath.replace(
                ".entries.pck", ".rmdirs.pck")
            logger.debug("entries_filepath3: %s" % entries_filepath)
            changemap = unpickle(configuration,
                                 filepath,
                                 allow_missing=False)
            for tfid in changemap.keys():
                result['records'] += 1
                if tfid == "[0:0x0:0x0]":
                    result['passed'] += 1
                else:
                    ops = changemap[tfid][0].get('ops', {})
                    mkdir_records = ops.get("02MKDIR", [])
                    mkdir_records.sort()
                    rmdir_records = ops.get("07RMDIR", [])
                    rmdir_records.sort()
                    create_records = ops.get("01CREAT", [])
                    create_records.sort()
                    unlink_records = ops.get("06UNLNK", [])
                    unlink_records.sort()
                    hlink_records = ops.get("03HLINK", [])
                    hlink_records.sort()
                    slink_records = ops.get("04SLINK", [])
                    slink_records.sort()
                    mknod_records = ops.get("05MKNOD", [])
                    mknod_records.sort()
                    # Test if 10OPEN and 11CLOSE are only modes
                    # if so test if entry was opened in write mode
                    # TODO: Rewrite to use generators
                    modes = changemap[tfid][0].get('modes', {})
                    mode_ops = list(changemap[tfid][0].get('ops', {}).keys())
                    for op in ['10OPEN', '11CLOSE']:
                        if op in mode_ops:
                            mode_ops.remove(op)
                    if mode_ops or not modes:
                        mode_readonly = False
                    else:
                        mode_readonly = True
                        for mode in modes.keys():
                            if mode_write_re.search(mode):
                                mode_readonly = False

                    # No write operations found
                    if mode_readonly:
                        filtered_entries.append(tfid)
                        logger.debug("%d.%d: Filtered"
                                     % (idx, pid)
                                     + " readonly entry: %s: %s"
                                     % (tfid, changemap[tfid]))

                    # Removed dir is not a tempirary dir
                    elif rmdir_records and not mkdir_records:
                        logger.debug("%d.%d: Filtered found possible parent:"
                                     % (idx, pid)
                                     + " %s" % changemap[tfid])
                        ops_records = [recno for recno_list in ops.values()
                                       for recno in recno_list]
                        ops_records.sort()
                        if ops_records[-1] == rmdir_records[-1]:
                            rmdirs[tfid] = ops
                        else:
                            logger.info("%d.%d Filtered Skipping"
                                        % (idx, pid)
                                        + " rmdir: %s: %s"
                                        % (tfid, changemap[tfid]))
                    # Removed dir is a tempirary dir
                    elif mkdir_records and rmdir_records \
                            and mkdir_records[-1] < rmdir_records[-1]:
                        ops_records = [recno for recno_list in ops.values()
                                       for recno in recno_list]
                        ops_records.sort()
                        if ops_records[-1] == rmdir_records[-1]:
                            filtered_entries.append(tfid)
                            logger.debug("%d.%d: Filtered"
                                         % (idx, pid)
                                         + " tempporary dir: %s: %s"
                                         % (tfid, changemap[tfid]))
                        else:
                            logger.info("%d.%d: Filtered Skipping"
                                        + " temporary dir: %s: %s"
                                        % (tfid, changemap[tfid]))
                    # Removed entry is tempirary
                    elif (create_records and unlink_records
                            and create_records[-1] < unlink_records[-1]) \
                        or (hlink_records and unlink_records
                            and hlink_records[-1] < unlink_records[-1]) \
                        or (slink_records and unlink_records
                            and slink_records[-1] < unlink_records[-1]) \
                        or (mknod_records and unlink_records
                            and mknod_records[-1] < unlink_records[-1]):
                        ops_records = [recno for _, recno in ops.items()]
                        ops_records.sort()
                        if ops_records[-1] == unlink_records[-1]:
                            filtered_entries.append(tfid)
                            logger.debug("%d.%d: Filtered"
                                         % (idx, pid)
                                         + " tempporary entry: %s: %s"
                                         % (tfid, changemap[tfid]))
                        else:
                            logger.info("__filter_changemap_worker:"
                                        + "Skipping entry: %s: %s"
                                        % (tfid, changemap[tfid]))
                    else:
                        result['passed'] += 1
            if rmdirs:
                result['rmdirs'] += len(list(rmdirs.keys()))
                status = pickle(configuration, rmdirs, rmdirs_filepath)
                # logger.debug("%d.%d: pickle status: %s" % (idx, pid, status))
                if not status:
                    raise IOError("%d.%d: Failed to save %r"
                                  % (idx, pid, rmdirs_filepath))
                rmdirs = {}
            for tfid in filtered_entries:
                result['filtered'] += 1
                logger.debug("%d.%d: Removing filtered entry: %s: %s"
                             % (idx, pid, tfid, changemap[tfid]))
                del changemap[tfid]
            filtered_entries = []
            status = pickle(configuration, changemap, entries_filepath)
            logger.debug("%d.%d: pickle status: %s, entries_filepath: %r"
                         % (idx, pid, status, entries_filepath))
            if not status:
                raise IOError("%d.%d: Failed to save %r"
                              % (idx, pid, entries_filepath))
            changemap = None
    except Exception:
        status = False
        result['msg'] = str(traceback.format_exc())

    return (status, result)


def __filter_changemap_parent_worker(conf_file,
                                     changemap_filepaths,
                                     rmdirs_filepaths,
                                     changelog_filtered_path,
                                     snapshot_timestamp,
                                     idx,
                                     nprocs,):
    """Remove all entries that have a removed dir as parent"""
    status = True
    result = {'msg': "",
              'records': 0,
              'filtered': 0,
              'passed': 0,
              }
    try:
        # Use separate log file for changes worker
        configuration = get_configuration_object(conf_file=conf_file,
                                                 skip_log=True)
        # User local_logger to log path resolves for each timestamp
        worker_log_filepath = path_join(configuration,
                                        configuration.lustre_meta_basepath,
                                        changelog_dirname,
                                        "%d.log" % snapshot_timestamp)
        worker_logger_obj = Logger(configuration.loglevel,
                                   logfile=worker_log_filepath,
                                   app='__filter_changemap_parent_worker.%d.%d'
                                   % (snapshot_timestamp, idx))
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result['msg'] = err
        return (False, result)
    try:
        pid = os.getpid()
        rmdirs = {}
        # TODO: Nest this in 'changemap_filepaths' loop
        #       if we run out of memory
        for rmdirs_file in rmdirs_filepaths:
            rmdirs.update(unpickle(configuration,
                                   rmdirs_file,
                                   allow_missing=False))
        logger.debug("%d.%d: rmdirs: %s"
                     % (idx, pid, rmdirs))
        logger.debug("%d.%d: changemap_filepaths: %s"
                     % (idx, pid, changemap_filepaths))
        for filepath in changemap_filepaths:
            filtered_filepath \
                = filepath.replace(".entries.pck",
                                   ".pck")
            if not rmdirs:
                status = make_symlink(configuration,
                                      os.path.basename(filepath),
                                      filtered_filepath,
                                      force=True)
                continue
            changemap = unpickle(configuration,
                                 filepath,
                                 allow_missing=False)
            # NOTE: Rename ops is represented by FID [0:0x0:0x0]
            # and therefore changemap['[0:0x0:0x0]'] is a list of changes.
            filtered_entries = []
            for tfid in changemap.keys():
                filtered_fschanges = {}
                fschanges_cnt = len(changemap[tfid])
                logger.debug("%d.%d: fschanges_cnt: %d"
                             % (idx, pid, fschanges_cnt))
                for fschange_idx in range(fschanges_cnt):
                    fschange = changemap[tfid][fschange_idx]
                    logger.debug("%d.%d: fschange (%d): %s"
                                 % (idx, pid, fschange_idx, fschange))
                    for rm_tfid in rmdirs.keys():
                        if fschange.get('pfid', {}).get(rm_tfid, []) \
                                or fschange.get('sfid', {}).get(rm_tfid, []) \
                                or fschange.get('spfid', {}).get(rm_tfid, []):
                            logger.debug("%d.%d: Filtered parent: %s"
                                         % (idx, pid, rm_tfid)
                                         + " found: %s"
                                         % changemap[tfid])
                            filtered_fschanges[fschange_idx] \
                                = filtered_fschanges.get(fschange_idx, 0) + 1
                if not filtered_fschanges:
                    result['passed'] += fschanges_cnt
                elif len(filtered_fschanges.keys()) == fschanges_cnt:
                    # All fs changes should be removed,
                    filtered_entries.append(tfid)
                    result['filtered'] += fschanges_cnt
                else:
                    # Remove specific fs changes
                    changemap[tfid] = [changemap[tfid][i]
                                       for i in range(len(changemap[tfid]))
                                       if i not in filtered_fschanges.keys()]
                    result['filtered'] += fschanges_cnt - len(changemap[tfid])
                result['records'] += fschanges_cnt
            # Remove filtered fids
            for tfid in filtered_entries:
                logger.info("%d.%d: Filtered entry: %s: %s"
                            % (idx, pid, tfid, changemap[tfid]))
                del changemap[tfid]
            # Saver filtered changemap
            status = pickle(configuration, changemap,
                            filtered_filepath)
            if not status:
                raise IOError("%d.%d: Failed to save %r" %
                              (idx, pid, filepath))
    except Exception:
        status = False
        result['msg'] = str(traceback.format_exc())

    return (status, result)


def __filter_changemap(configuration,
                       changelog_basepath,
                       snapshot):
    """Filter changemap removing temporary dir and files"""
    logger = configuration.logger
    result = {
        'records': 0,
        'filtered': 0,
        'passed': 0,
        'rmdirs': 0,
        'parent_records': 0,
        'parent_filtered': 0,
        'parent_passed': 0,
    }
    nprocs = configuration.system_nprocs
    snapshot_timestamp = snapshot.get('timestamp')
    # multiprocessing.log_to_stderr()
    pool = multiprocessing.Pool(processes=nprocs)
    t1 = time.time()
    changelog_merged_path = path_join(configuration,
                                      changelog_basepath,
                                      snapshot_timestamp,
                                      changelog_merged_dirname,
                                      convert_utf8=False)
    if not os.path.isdir(changelog_merged_path):
        logger.error("Missing changemap merged path: %r"
                     % changelog_merged_path)
        return (False, result)

    changelog_filtered_path = path_join(configuration,
                                        changelog_basepath,
                                        snapshot_timestamp,
                                        changelog_filtered_dirname,
                                        convert_utf8=False)
    if not os.path.isdir(changelog_filtered_path):
        status = makedirs_rec(configuration, changelog_filtered_path)
        if not status:
            msg = "Failed to create changelog temp path: %r" \
                % changelog_filtered_path
            logger.error(msg)
            return False
        logger.info("Created changelog temp path: %r"
                    % changelog_basepath)

    logger.debug("changelog_merged_path: %s" % changelog_merged_path)
    logger.debug("changelog_filtered_path: %s" % changelog_filtered_path)
    changemap_merged_re = re.compile("[0-9]*\\.[0-9]*\\.pck")
    changemap_filepaths = {}
    for idx in range(nprocs):
        changemap_filepaths[idx] = []
    with os.scandir(changelog_merged_path) as it:
        for entry in it:
            if changemap_merged_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[0])
                changemap_filepaths[idx].append(entry.path)
    t1 = time.time()
    tasks = {}
    for idx in range(nprocs):
        task = {}
        tasks[idx] = task
        logger.info("Starting __filter_changemap_worker: %d" % idx)
        task['proc'] = pool.apply_async(__filter_changemap_worker,
                                        (configuration.config_file,
                                         changemap_filepaths[idx],
                                         changelog_merged_path,
                                         changelog_filtered_path,
                                         snapshot_timestamp,
                                         idx,
                                         nprocs,))
    # Wait for tasks to finish

    status = True

    for idx in tasks:
        task = tasks[idx]
        proc = task['proc']
        logger.info("Waiting for __filter_changemap_worker task: %d" % idx)
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            msg = "__filter_changemap_worker: %d finished with: " % idx \
                + "status: %s and result: %s " \
                % (worker_status, str(worker_result))
            if worker_status:
                logger.info("%d: %s" % (idx, msg))
                msg = "__filter_changemap_worker: %d, filtered: %d" \
                    % (idx, worker_result['filtered']) \
                    + ", passed: %d, total: %d" \
                    % (worker_result['passed'], worker_result['records'])
                result['records'] += worker_result['records']
                result['passed'] += worker_result['passed']
                result['filtered'] += worker_result['filtered']
                result['rmdirs'] += worker_result['rmdirs']
            else:
                status = False
                logger.error("%d: %s" % (idx, msg))
        else:
            status = False
            logger.error("__filter_changemap_worker: %d" % idx
                         + " failed with unknown error")
    t2 = time.time()
    logger.info("Filtered: %d entries, passed: %d entries"
                % (result['records'], result['passed'])
                + ", filtered: %d entries, found: %d rmdirs in %d secs"
                % (result['filtered'], result['rmdirs'], t2-t1))

    if not status:
        pool.terminate()
        return (status, result)

    # Filter entries with removed parents

    changemap_entries_re = re.compile("[0-9]*\\.[0-9]*\\.entries\\.pck")
    changemap_rmdirs_re = re.compile("[0-9]*\\.[0-9]*\\.rmdirs\\.pck")
    changemap_filepaths = {}
    rmdirs_filepaths = []
    for idx in range(nprocs):
        changemap_filepaths[idx] = []
    with os.scandir(changelog_filtered_path) as it:
        for entry in it:
            if changemap_entries_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[0])
                changemap_filepaths[idx].append(entry.path)
            elif changemap_rmdirs_re.fullmatch(entry.name):
                rmdirs_filepaths.append(entry.path)

    # Remove all entries that have a removed dir as parent

    t1 = time.time()
    tasks = {}
    for idx in range(nprocs):
        task = {}
        tasks[idx] = task
        logger.info("Starting __filter_changemap_parent_worker: %d" % idx)
        task['proc'] = pool.apply_async(__filter_changemap_parent_worker,
                                        (configuration.config_file,
                                         changemap_filepaths[idx],
                                         rmdirs_filepaths,
                                         changelog_filtered_path,
                                         snapshot_timestamp,
                                         idx,
                                         nprocs,))
    # Wait for tasks to finish

    for idx in tasks:
        task = tasks[idx]
        proc = task['proc']
        logger.info(
            "Waiting for __filter_changemap_parent_worker task: %d" % idx)
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            msg = "__filter_changemap_parent_worker: %d" % idx \
                + " finished with: status: %s and result: %s " \
                % (worker_status, str(worker_result))
            if worker_status:
                logger.info("%d: %s" % (idx, msg))
                result['parent_records'] += worker_result['records']
                result['parent_passed'] += worker_result['passed']
                result['parent_filtered'] += worker_result['filtered']
            else:
                status = False
                logger.error("%d: %s" % (idx, msg))
        else:
            status = False
            logger.error("__filter_changemap_parent_worker: %d" % idx
                         + " failed with unknown error")
    t2 = time.time()

    logger.info("Filtered parent: %d entries, passed: %d entries"
                % (result['parent_records'], result['parent_passed'])
                + ", filtered: %d entries in %d secs"
                % (result['parent_filtered'], t2-t1))

    pool.terminate()

    return (status, result)


def fetch_raw_changelog(configuration, snapshot):
    """Retrieve raw lustre changelog for snapshot and save it"""
    logger = configuration.logger
    raw_changelog_size = 0
    # TODO: CHECK if snap shot is mounted and if not then mount it
    # NOTE: Right now we expect it's mounted by caller
    snapshot_fsname = snapshot.get('snapshot_fsname', '')
    snapshot_name = snapshot.get('snapshot_name', '')
    snapshot_timestamp = snapshot.get('timestamp')

    meta_basepath = configuration.lustre_meta_basepath
    changelog_path = path_join(configuration,
                               meta_basepath,
                               changelog_dirname)
    snapshot_mdt = "%s-%s" % (snapshot_fsname,
                              configuration.lustre_mdt)
    raw_changelog_filepath = path_join(configuration,
                                       changelog_path, "%s.raw"
                                       % snapshot_timestamp)
    if os.path.exists(raw_changelog_filepath):
        logger.warning("Overriding existing changelog for: %r in %r"
                       % (snapshot_name,
                          raw_changelog_filepath))
    (snapshot_mountpoint, snapshot_umount) \
        = mount_snapshot(configuration, snapshot)
    if not snapshot_mountpoint:
        logger.error("Failed to mount snapshot: %r"
                     % snapshot.get('snapshot_name', ''))
        return None

    t1 = time.time()
    command = "lfs changelog %s" % snapshot_mdt
    (rc, _, err) = shellexec(
        configuration, command, stdout_filepath=raw_changelog_filepath)
    t2 = time.time()
    if rc == 0:
        status = True
        logger.info("Saved snapshot %r changelog list to file: %r in %d secs"
                    % (snapshot_name, raw_changelog_filepath, t2-t1))
        raw_changelog_size = os.path.getsize(raw_changelog_filepath)
    else:
        status = False
        logger.info("Failed to save snapshot %r changelog list to file: %r"
                    % (snapshot_name, raw_changelog_filepath)
                    + ", err: %s" % err)

    if snapshot_umount:
        status = umount_snapshot(configuration, snapshot)

    # No changelog, most likely because changelog is disabled on MGS

    if raw_changelog_size == 0:
        status = False
        logger.error(
            """Empty raw changelog file: %(changelog_file)s
----------------------------------------------------------------------
Check if luster changelog is enabled on MGS: %(mgs)r using this command:
$> lctl get_param mdd.%(fsname)s-%(mdt)s.changelog_users
Enable changelog on MGS: %(mgs)r using this command:
$> lctl --device %(fsname)s-%(mdt)s changelog_register"
Set the correct changelog mask on MGS: %(mgs)r using this command
$> lctl set_param -P mdd.%(fsname)s-%(mdt)s.changelog_mask="CREAT MKDIR HLINK SLINK MKNOD UNLNK RMDIR RENME RNMTO OPEN CLOSE LYOUT TRUNC SATTR XATTR HSM MTIME CTIME MIGRT FLRW RESYNC"
----------------------------------------------------------------------"""
            % {'changelog_file': raw_changelog_filepath,
               'fsname': configuration.lustre_fsname,
               'mdt': configuration.lustre_mdt,
               'mgs': configuration.lustre_mgs})

    result = None
    if status:
        result = raw_changelog_filepath

    return result


def create_changemap(configuration,
                     snapshot,
                     start_recno):
    """Parse changelog and create changemap"""
    logger = configuration.logger
    logger.debug("create_changemap: start_recno: %d, snapshot: %s"
                 % (start_recno, snapshot))
    # Define and check for backup basedir
    meta_basepath = configuration.lustre_meta_basepath
    if not os.path.isdir(meta_basepath):
        logger.error("Missing backup base dir: %r" % meta_basepath)
        return False

    # Define and create change log path if it doesn't exist

    changelog_basepath = path_join(configuration,
                                   meta_basepath,
                                   changelog_dirname)
    if not os.path.isdir(changelog_basepath):
        status = makedirs_rec(configuration, changelog_basepath)
        if not status:
            msg = "Failed to create changelog basepath: %r" \
                % changelog_basepath
            logger.error(msg)
            return False
        logger.info("Created changelog basepath: %r"
                    % changelog_basepath)

    # If changelog result exists, then load and return result
    # NOTE: This is only happens if last backupmap was disrupted
    changelog_result_filepath = path_join(configuration,
                                          changelog_basepath,
                                          "%s.pck" % snapshot.get(
                                              'timestamp', -1),
                                          convert_utf8=False)
    retval = True
    result = None
    if os.path.isfile(changelog_result_filepath):
        result = unpickle(configuration,
                          changelog_result_filepath,
                          allow_missing=False)
    if result is not None:
        logger.info("Using existing changelog result: %r"
                    % changelog_result_filepath)
    else:
        # Switch default logger to changelog logger
        changelog_log_filepath = changelog_result_filepath.replace(
            '.pck', '.log')
        changemap_logger_obj = \
            Logger(configuration.loglevel,
                   logfile=changelog_log_filepath,
                   app=force_unicode(changelog_log_filepath))
        main_logger = configuration.logger
        configuration.logger = changemap_logger_obj.logger
        main_logger.info("Logging changelog details to: %r"
                         % changelog_log_filepath)
        (retval, result) = __create_changemap(configuration,
                                              changelog_basepath,
                                              snapshot,
                                              start_recno)
        if retval:
            (retval, _) = __merge_changemap(configuration,
                                            changelog_basepath,
                                            snapshot)
        if retval:
            (retval, _) = __filter_changemap(configuration,
                                             changelog_basepath,
                                             snapshot)
        # Switch default logger back to main logger
        configuration.logger = main_logger

    return (retval, result)
