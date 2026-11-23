#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# target_filediff_zfs - lustre backup target filediff_zfs zfs helpers
# Copyright (C) 2020-2026  The lustrebackup Project by the Science HPC Center at UCPH
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

"""This module contains lustre backup target filediff_zfs zfs helpers"""


import os
import re
import multiprocessing
import subprocess
import shlex
import time
import xxhash

from lustrebackup.shared.defaults import bin_target_filediff_zfs
from lustrebackup.shared.fileio import path_join, unpickle, \
    pickle, save_json, touch, truncate
from lustrebackup.shared.backup import get_backuplog_path
from lustrebackup.shared.multiprocessing import terminate
from lustrebackup.shared.ssh import get_ssh_options_str


def __filediff_zfs_worker(filediff_zfs_args,
                          filediff_zfs_stdout,
                          filediff_zfs_stderr,
                          filediff_zfs_pid,):
    """Helper function to call filediff_zfs """
    stdout_handle = open(filediff_zfs_stdout, "w")
    stderr_handle = open(filediff_zfs_stderr, "w")
    pid_handle = open(filediff_zfs_pid, "w")
    process = subprocess.Popen(
        filediff_zfs_args, stdout=stdout_handle, stderr=stderr_handle)
    process_pid = process.pid
    pid_handle.write(str(process_pid))
    try:
        result = process.wait()
    finally:
        pid_handle.close()
        stderr_handle.close()
        stdout_handle.close()

    return result


def __create_filediff_zfs_task(configuration,
                               source_timestamp,
                               start_recno,
                               end_recno,
                               abs_dest_path,
                               relpath,
                               backuplog_path,
                               idx,
                               nprocs,
                               ):
    """Creates filediff_zfs task"""
    logger = configuration.logger

    # Generate filediff_zfs log logpath

    xxh128 = xxhash.xxh128()
    xxh128.update(relpath)
    relpath_digest = xxh128.hexdigest()

    filediff_zfs_logpath = path_join(configuration,
                                     backuplog_path,
                                     "filediff_zfs.%s-%s.%s.%s"
                                     % (start_recno,
                                         end_recno,
                                         idx,
                                         relpath_digest),
                                     convert_utf8=False)

    # Generate task info

    task = {}
    task['stdout'] = "%s.stdout" % filediff_zfs_logpath
    task['stderr'] = "%s.stderr" % filediff_zfs_logpath
    task['pid'] = "%s.pid" % filediff_zfs_logpath

    # Store paths

    task['relpath'] = relpath
    task['dest_path'] = abs_dest_path

    # Generate ssh options

    ssh_opts = task['ssh_opts'] \
        = get_ssh_options_str(configuration,
                              hostname=configuration.source_host,
                              controlpath_postfix=(idx % nprocs))

    # Generate filediff_zfs command

    task['cmd'] = cmd = "%s" % bin_target_filediff_zfs \
        + " --verbose" \
        + " --disable-log" \
        + " --config=%r" % configuration.config_file \
        + " --ssh-options=%r" % ssh_opts \
        + " --filepath=%r" % relpath \
        + " --snapshot=%d" % source_timestamp \
        + " --metadata=%s.transfer" % filediff_zfs_logpath
    logger.debug("filediff_zfs cmd: %s" % cmd)
    # Generate rsync args for subprocess

    task['args'] = shlex.split(cmd)
    # logger.debug("args: %s" % args)

    # Save task to json file

    json_filepath = "%s.json" % filediff_zfs_logpath
    status = save_json(configuration, task, json_filepath)
    if not status:
        logger.error("Failed to save task to json file: %r"
                     % json_filepath)
        return None

    # Pickle filediff_zfs task to file

    pck_filepath = "%s.pck" % filediff_zfs_logpath
    status = pickle(configuration, task, pck_filepath)
    if not status:
        logger.error("Failed to save task to pck file: %r"
                     % json_filepath)
        return None

    return task


def wait_for_filediff_zfs_tasks(configuration, task_list):
    """Wait for tasks to finish"""
    logger = configuration.logger
    idx = 0
    total_tasks = len(task_list)
    completed = 0
    while completed != total_tasks:
        for idx in range(total_tasks):
            task = task_list[idx]
            process = task['proc']
            if task.get('rc', -1) == -1:
                try:
                    # logger.debug("Checking task: %d" % idx)
                    task['rc'] = process.get(1)
                except multiprocessing.TimeoutError:
                    logger.debug("Still executing filediff_zfs task: %d"
                                 " completed: %d/%d, waiting for: %d tasks"
                                 ", runtime: %d secs, filediff_zfs: %r -> %r"
                                 % (idx,
                                    completed,
                                    total_tasks,
                                    total_tasks-completed,
                                    int(time.time()-task['t1']),
                                    task['relpath'],
                                    task['dest_path']))
                except Exception as error:
                    task['rc'] = 1
                    logger.error("filediff_zfs task: %d failed, task: %s"
                                 ", error: %s"
                                 % (idx, task, error))
                if task.get('rc', -1) != -1:
                    completed += 1
                    logger.info("Finished filediff_zfs: %d/%d tasks"
                                % (completed, total_tasks))
                    logger.debug("Finished filediff_zfs: %d/%d tasks"
                                 ", filediff_zfs: %r -> %r"
                                 % (completed, total_tasks,
                                    task['relpath'], task['dest_path']))
        time.sleep(1)

    return completed


def filediff_zfs(configuration,
                 local_backupmaps,
                 remote_snapshot_mount,
                 source_timestamp,
                 start_recno,
                 end_recno,
                 largefile_size,
                 ):
    """Perform parallel diff update of largefiles
    Each filediff_zfs process is responsible for exactly one file
    NOTE: *remote_snapshot_mount* is unused but needed for caller compability
          with the original checksum filediff"""
    logger = configuration.logger
    status = False
    filediff_zfs_status = True

    # print ("remote_snapshot_mount: %s" % remote_snapshot_mount)
    # print ("source_timestamp: %s" % source_timestamp)
    # print ("start_recno: %s" % start_recno)
    # print ("end_recno: %s" % end_recno)

    # Get backup log path

    backuplog_path = get_backuplog_path(configuration, source_timestamp)
    if not backuplog_path:
        logger.error("Failed to create backup log path for: %d"
                     % source_timestamp)
        return False

    # Resolve dirty filepaths

    dirty_part_re = re.compile("[0-9]*\\.[0-9]*\\.dirty\\.pck")
    dirty_filepaths = []

    for local_backupmap_path in local_backupmaps.values():
        with os.scandir(local_backupmap_path) as it:
            for entry in it:
                if dirty_part_re.fullmatch(entry.name):
                    dirty_filepaths.append(entry.path)

    if not dirty_filepaths:
        logger.info("No dirtyfiles found for snapshot timestamp: %d"
                    % source_timestamp)
        return True

    # Fetch number of parallel processes

    nprocs = configuration.system_nprocs
    pool = multiprocessing.Pool(processes=nprocs)

    # Create largefile diff tasks

    idx = 0
    task_list = []
    for filepath in dirty_filepaths:
        task_input = unpickle(configuration, filepath)
        if not task_input:
            logger.info("Found no largefiles entries in: %r"
                        % filepath)
            continue
        for relpath, values in task_input.items():
            abs_dest_path = path_join(configuration,
                                      configuration.lustre_data_mount,
                                      configuration.lustre_data_path,
                                      relpath,
                                      convert_utf8=False)

            # Fetch source filesize

            source_filesize = values.get('size', -1)
            if source_filesize == -1:
                logger.error("Failed to get source file size for: %r"
                             % relpath)
                terminate(configuration, task_list, pool, nprocs)
                return False
            elif source_filesize < largefile_size:
                # logger.debug("filediff_zfs: skipping small file (%d/%d): %r"
                #             % (source_filesize, largefile_size, relpath))
                continue

            # Check if non file entry is blocking

            if os.path.exists(abs_dest_path) \
                    and not os.path.isfile(abs_dest_path):
                logger.error("NON file entry is blocking: %r"
                             % abs_dest_path)
                terminate(configuration, task_list, pool, nprocs)
                return False

            # Ensure that file exists

            status = touch(configuration, abs_dest_path, 0)
            if not status:
                logger.error("Failed to create target file: %r"
                             % abs_dest_path)
                terminate(configuration, task_list, pool, nprocs)
                return False

            # Set target file size if needed

            target_filesize = os.path.getsize(abs_dest_path)
            if target_filesize != source_filesize:
                status = truncate(configuration,
                                  abs_dest_path,
                                  filesize=source_filesize)
                if not status:
                    logger.error("Failed to truncate target file: %r"
                                 % abs_dest_path
                                 + " to size: %d"
                                 % source_filesize)
                    terminate(configuration, task_list, pool, nprocs)
                    return False
                logger.debug("truncated: %r from size: %d to %d"
                             % (abs_dest_path,
                                target_filesize,
                                source_filesize))

            # Create one task per file

            task = __create_filediff_zfs_task(configuration,
                                              source_timestamp,
                                              start_recno,
                                              end_recno,
                                              abs_dest_path,
                                              relpath,
                                              backuplog_path,
                                              idx,
                                              nprocs,
                                              )
            if not task:
                logger.error(
                    "Failed to create filediff_zfs entry (%d) for path: %r"
                    % (idx, relpath)
                )
                terminate(configuration, task_list, pool, nprocs)
                return False

            logger.info("Starting filediff_zfs task: %d" % idx)
            logger.debug("Starting filediff_zfs task: %d, filediff_zfs: %s"
                         % (idx, task['cmd']))
            task['t1'] = time.time()
            task['proc'] = pool.apply_async(__filediff_zfs_worker,
                                            (task['args'],
                                                task['stdout'],
                                                task['stderr'],
                                                task['pid'],))
            task_list.append(task)
            idx += 1

    # Wait for filediff_zfs tasks to complete

    completed = wait_for_filediff_zfs_tasks(configuration, task_list)
    logger.info("Completed: %d filediff_zfs tasks" % completed)

    # Check filediff_zfs status

    for task in task_list:
        task['proc'].wait()
        if task['proc'].successful():
            logger.debug("filediff_zfs finished: %d"
                         % task.get('rc', -1))
        if task.get('rc', -1) != 0:
            filediff_zfs_status = False
            logger.error("Filediff failed: rc: %d, stderr: %r, task: %s"
                         % (task.get('rc', -1), task.get('stderr'), task))

    # Terminate

    status = terminate(
        configuration, task_list, pool, nprocs)

    result = False
    if status and filediff_zfs_status:
        result = True

    return result
