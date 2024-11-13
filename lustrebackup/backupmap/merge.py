#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# merge - lustre backup helpers
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

"""This module contains various helpers used to merge backupmap generated
by different worker processes"""

import os
import time
import multiprocessing
import re
import traceback

from lustrebackup.shared.configuration import get_configuration_object
from lustrebackup.shared.defaults import backupmap_dirname, \
    backupmap_resolved_dirname
from lustrebackup.shared.fileio import path_join, make_symlink, \
    pickle, unpickle
from lustrebackup.shared.logger import Logger


def __merge_backupmap_worker(conf_file,
                             backupmap_filepaths,
                             backupmap_merged_path,
                             snapshot_timestamp,
                             idx):
    """Merge backupmap worker"""
    result = {'msg': '',
              'renamed_count': 0,
              'modified_count': 0,
              'dirty_count': 0,
              'missing_count': 0,
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
                                   app='__merge_backupmap_worker.%d.%d'
                                   % (snapshot_timestamp, idx))
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result['msg'] = err
        return (False, result)

    try:
        pid = os.getpid()
        save_idx = 0

        # Merge renamed

        renamed_paths = backupmap_filepaths.get('renamed', [])
        merged_renamed_filename = "%d.%d.renamed.pck" \
            % (idx, save_idx)
        merged_renamed_filepath = path_join(configuration,
                                            backupmap_merged_path,
                                            merged_renamed_filename,
                                            convert_utf8=False)
        if len(renamed_paths) == 1:
            renamed_file = renamed_paths[0]
            rel_renamed_file = path_join(configuration,
                                         "..",
                                         backupmap_resolved_dirname,
                                         os.path.basename(renamed_file),
                                         convert_utf8=False)
            status = make_symlink(configuration,
                                  rel_renamed_file,
                                  merged_renamed_filename,
                                  working_dir=backupmap_merged_path,
                                  force=True)
            if not status:
                msg = "%d.%d: Failed to make symlink %r -> %s" \
                    % (idx, pid, rel_renamed_file, merged_renamed_filename)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            logger.info("%d.%d: Skip renamed backupmap merge, only one file"
                        % (idx, pid))
            # Load for stats and verification
            merged_renamed = unpickle(configuration, merged_renamed_filepath)
            if not merged_renamed:
                msg = "%d.%d: Failed to count merged renamed entries: %r" \
                    % (idx, pid, merged_renamed_filepath)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            result['renamed_count'] = len(list(merged_renamed.keys()))
            merged_renamed = {}
        else:
            merged_renamed = {}
            for path in renamed_paths:
                renamed = unpickle(configuration, path)
                if not renamed:
                    status = False
                    msg = "%d.%d: No renamed backupmap entries in: %r" \
                        % (idx, pid, path)
                    logger.warning(msg)
                else:
                    merged_renamed.update(renamed)
            result['renamed_count'] = len(list(merged_renamed.keys()))
            if result['renamed_count'] == 0:
                logger.debug("%d.%d: Skipping save of empty total renamed"
                             % (pid, idx))
            else:
                status = pickle(configuration,
                                merged_renamed,
                                merged_renamed_filepath)
                if not status:
                    msg = "%d.%d: Failed to save backup info: %r" \
                        % (idx, pid, merged_renamed_filepath)
                    logger.error(msg)
                    result['msg'] = msg
                    return (False, result)
            merged_renamed = {}

        # Merge modified

        modified_paths = backupmap_filepaths.get('modified', [])
        # logger.debug("%d.%d: Merging modified: %s" \
        #               % (idx, pid, modified_paths))
        merged_modified_filename = "%d.%d.modified.pck" \
            % (idx, save_idx)
        merged_modified_filepath = path_join(configuration,
                                             backupmap_merged_path,
                                             merged_modified_filename,
                                             convert_utf8=False)
        if len(modified_paths) == 1:
            modified_file = modified_paths[0]
            rel_modified_file = path_join(configuration,
                                          "..",
                                          backupmap_resolved_dirname,
                                          os.path.basename(modified_file),
                                          convert_utf8=False)
            status = make_symlink(configuration,
                                  rel_modified_file,
                                  merged_modified_filename,
                                  working_dir=backupmap_merged_path,
                                  force=True)
            if not status:
                msg = "%d.%d: Failed to make symlink %r -> %s" \
                    % (idx, pid, rel_modified_file, merged_modified_filename)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            logger.info("Skip modified backupmap merge, only one file")
            # Load for stats and verification
            merged_modified = unpickle(configuration, merged_modified_filepath)
            if not merged_modified:
                msg = "%d.%d: Failed to count merged modifed entries: %r" \
                    % (idx, pid, merged_modified_filepath)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            result['modified_count'] = len(list(merged_modified.keys()))
            merged_modified = {}
        else:
            merged_modified = {}
            for path in modified_paths:
                modified = unpickle(configuration, path)
                if not modified:
                    status = False
                    msg = "%d.%d: No modified backupmap entries in: %r" \
                        % (idx, pid, path)
                    logger.warning(msg)
                for key, value in modified.items():
                    merged_modified[key] = merged_modified.get(key, 0) + value
            result['modified_count'] = len(list(merged_modified.keys()))
            if result['modified_count'] == 0:
                logger.debug("%d.%d: Skipping save of empty total modified"
                             % (pid, idx))
            else:
                status = pickle(configuration,
                                merged_modified,
                                merged_modified_filepath)
                if not status:
                    msg = "%d.%d: Failed to save backup info: %r" \
                        % (idx, pid, merged_modified_filepath)
                    logger.error(msg)
                    result['msg'] = msg
                    return (False, result)
            merged_modified = {}

        # Merge dirty

        dirty_paths = backupmap_filepaths.get('dirty', [])
        merged_dirty_filename = "%d.%d.dirty.pck" \
            % (idx, save_idx)
        merged_dirty_filepath = path_join(configuration,
                                          backupmap_merged_path,
                                          merged_dirty_filename,
                                          convert_utf8=False)
        logger.debug("%d.%d: Merging dirty: %s" % (idx, pid, dirty_paths))
        if len(dirty_paths) == 1:
            dirty_file = dirty_paths[0]
            rel_dirty_file = path_join(configuration,
                                       "..",
                                       backupmap_resolved_dirname,
                                       os.path.basename(dirty_file),
                                       convert_utf8=False)
            status = make_symlink(configuration,
                                  rel_dirty_file,
                                  merged_dirty_filename,
                                  working_dir=backupmap_merged_path,
                                  force=True)
            if not status:
                msg = "%d.%d: Failed to make symlink %r -> %s" \
                    % (idx, pid, rel_dirty_file, merged_dirty_filepath)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            logger.info("%d.%d: Skip dirty backupmap merge, only one file"
                        % (idx, pid))
            # Load for stats and verification
            merged_dirty = unpickle(configuration, merged_dirty_filepath)
            if not merged_dirty:
                msg = "%d.%d: Failed to count merged dirty entries: %r" \
                    % (idx, pid, merged_dirty_filepath)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            result['dirty_count'] = len(list(merged_dirty.keys()))
            merged_dirty = {}
        else:
            merged_dirty = {}
            for path in dirty_paths:
                dirty = unpickle(configuration, path)
                if not dirty:
                    msg = "No dirty backupmap entries in: %r" \
                        % path
                    logger.warning(msg)
                else:
                    merged_dirty.update(dirty)
            result['dirty_count'] = len(list(merged_dirty.keys()))
            if result['dirty_count'] == 0:
                logger.debug("%d.%d: Skipping save of empty total dirty"
                             % (pid, idx))
            else:
                status = pickle(configuration,
                                merged_dirty,
                                merged_dirty_filepath)
                if not status:
                    msg = "%d.%d: Failed to save backup info: %r" \
                        % (idx, pid, merged_dirty_filepath)
                    logger.error(msg)
                    result['msg'] = msg
                    return (False, result)
            merged_dirty = {}

        # Merge missing

        missing_paths = backupmap_filepaths.get('missing', [])
        merged_missing_filename = "%d.%d.missing.pck" \
            % (idx, save_idx)
        merged_missing_filepath = path_join(configuration,
                                            backupmap_merged_path,
                                            merged_missing_filename,
                                            convert_utf8=False)
        logger.debug("%d.%d: Merging missing: %s" % (idx, pid, missing_paths))
        if len(missing_paths) == 1:
            missing_file = missing_paths[0]
            rel_missing_file = path_join(configuration,
                                         "..",
                                         backupmap_resolved_dirname,
                                         os.path.basename(missing_file),
                                         convert_utf8=False)
            status = make_symlink(configuration,
                                  rel_missing_file,
                                  merged_missing_filename,
                                  working_dir=backupmap_merged_path,
                                  force=True)
            if not status:
                msg = "%d.%d: Failed to make symlink %r -> %s" \
                    % (idx, pid, rel_missing_file, merged_missing_filepath)
                result['msg'] = msg
                logger.error(msg)
            logger.info("Skip missing backupmap merge, only one file")
            # Load for stats and verification
            merged_missing = unpickle(configuration, merged_missing_filepath)
            if not merged_missing:
                msg = "%d.%d: Failed to count merged missing entries: %r" \
                    % (idx, pid, merged_missing_filepath)
                result['msg'] = msg
                logger.error(msg)
                return (False, result)
            result['missing_count'] = len(list(merged_missing.keys()))
            merged_missing = {}
        else:
            merged_missing = {}
            for path in missing_paths:
                missing = unpickle(configuration, path)
                if not missing:
                    msg = "No missing backupmap entries in: %r" \
                        % path
                    logger.warning(msg)
                else:
                    merged_missing.update(missing)
            result['missing_count'] = len(list(merged_missing.keys()))
            if result['missing_count'] == 0:
                logger.debug("%d.%d: Skipping save of empty total missing"
                             % (pid, idx))
            else:
                status = pickle(configuration,
                                merged_missing,
                                merged_missing_filepath)
                if not status:
                    msg = "%d.%d: Failed to save backup info: %r" \
                        % (idx, pid, merged_missing_filepath)
                    logger.error(msg)
                    result['msg'] = msg
                    return (False, result)
            merged_missing = {}

    except Exception as err:
        result['error'] = err
        logger.error("%d.%d: %s"
                     % (idx, pid, traceback.format_exc()))
        return (False, result)

    return (True, result)


def merge_backupmap(configuration,
                    backupmap_resolved_path,
                    backupmap_merged_path,
                    snapshot_timestamp):
    """Modified, dirty and missing might be spread across several
    backupmaps, merge when needed
    """
    result = {'renamed_count': 0,
              'modified_count': 0,
              'dirty_count': 0,
              'missing_count': 0,
              }
    logger = configuration.logger
    nprocs = configuration.system_nprocs
    # multiprocessing.log_to_stderr()
    pool = multiprocessing.Pool(processes=nprocs)
    t1 = time.time()

    # Rename is only one file, make symlink

    backupmap_renamed_re = re.compile(
        "[0-9]*\\.[0-9]*\\.[0-9]*\\.renamed\\.pck")
    backupmap_modified_re = re.compile(
        "[0-9]*\\.[0-9]*\\.[0-9]*\\.modified\\.pck")
    backupmap_dirty_re = re.compile("[0-9]*\\.[0-9]*\\.[0-9]*\\.dirty\\.pck")
    backupmap_missing_re = re.compile(
        "[0-9]*\\.[0-9]*\\.[0-9]*\\.missing\\.pck")
    backupmap_filepaths = {}
    for idx in range(nprocs):
        backupmap_filepaths[idx] = {'renamed': [],
                                    'modified': [],
                                    'dirty': [],
                                    'missing': [],
                                    }
    with os.scandir(backupmap_resolved_path) as it:
        for entry in it:
            if backupmap_renamed_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[2])
                backupmap_filepaths[idx]['renamed'].append(entry.path)
            elif backupmap_modified_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[2])
                backupmap_filepaths[idx]['modified'].append(entry.path)
            elif backupmap_dirty_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[2])
                backupmap_filepaths[idx]['dirty'].append(entry.path)
            elif backupmap_missing_re.fullmatch(entry.name):
                idx = int(entry.name.split(".")[2])
                backupmap_filepaths[idx]['missing'].append(entry.path)
    tasks = {}
    for idx in range(nprocs):
        task = {}
        tasks[idx] = task
        logger.info("Starting __merge_backupmap_worker: %d, merge_nprocs: %d"
                    % (idx, nprocs))
        task['proc'] = pool.apply_async(__merge_backupmap_worker,
                                        (configuration.config_file,
                                         backupmap_filepaths[idx],
                                         backupmap_merged_path,
                                         snapshot_timestamp,
                                         idx,))
    # Wait for tasks to finish

    status = True
    for idx in tasks:
        task = tasks[idx]
        proc = task['proc']
        logger.info("Waiting for backupmap merge task: %d" % idx)
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            # msg = "__merge_backupmap_worker: %d finished with: " \
            #    % idx \
            #    + "status: %s and message: %s " \
            #    % (worker_status, worker_result)
            if worker_status:
                logger.info("%d: %s" % (idx, worker_result))
            else:
                logger.error("%d: %s" % (idx, worker_result))
            logger.debug("%d: %s: %s" % (idx, worker_status, worker_result))
            if status:
                result['renamed_count'] += worker_result['renamed_count']
                result['modified_count'] += worker_result['modified_count']
                result['dirty_count'] += worker_result['dirty_count']
                result['missing_count'] += worker_result['missing_count']
        else:
            status = False
            logger.error("__merge_backupmap_worker: %d" % idx
                         + " failed with unknown error")
    t2 = time.time()
    logger.info("Merged %d renamed, %d modified, %d dirty and %d missing"
                % (result['renamed_count'],
                   result['modified_count'],
                   result['dirty_count'],
                   result['missing_count'])
                + " backupmap entries in %d secs" % (t2-t1))

    pool.terminate()

    return (status, result)
