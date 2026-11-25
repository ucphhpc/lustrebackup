#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# target_filediff - lustre backup target filediff helpers
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

"""This module contains vlustre backup target filediff helpers"""


import os
import re
import multiprocessing
import subprocess
import shlex
import time
import math
import xxhash

from lustrebackup.shared.backup import get_backuplog_path
from lustrebackup.shared.defaults import bin_target_filediff
from lustrebackup.shared.fileio import path_join, unpickle, \
    pickle, save_json, touch, truncate
from lustrebackup.shared.multiprocessing import terminate
from lustrebackup.shared.ssh import get_ssh_options_str


def __filediff_worker(filediff_args,
                      filediff_stdout,
                      filediff_stderr,
                      filediff_pid,):
    """Helper function to call filediff """
    stdout_handle = open(filediff_stdout, "w")
    stderr_handle = open(filediff_stderr, "w")
    pid_handle = open(filediff_pid, "w")
    process = subprocess.Popen(
        filediff_args, stdout=stdout_handle, stderr=stderr_handle)
    process_pid = process.pid
    pid_handle.write(str(process_pid))
    try:
        result = process.wait()
    finally:
        pid_handle.close()
        stderr_handle.close()
        stdout_handle.close()

    return result


def __create_filediff_task(configuration,
                           start_recno,
                           end_recno,
                           abs_src_path,
                           abs_dest_path,
                           relpath,
                           backuplog_path,
                           blocksize,
                           offset_block,
                           end_block,
                           idx,
                           nprocs,
                           ):
    """Creates filediff task"""
    logger = configuration.logger

    # Generate filediff log logpath

    xxh128 = xxhash.xxh128()
    xxh128.update(relpath)
    relpath_digest = xxh128.hexdigest()

    filediff_out_basepath = path_join(configuration,
                                      backuplog_path,
                                      "filediff.%s-%s.%s.%s"
                                      % (start_recno,
                                         end_recno,
                                         idx,
                                         relpath_digest),
                                      convert_utf8=False)
    filediff_logpath = "%s.%s-%s" \
        % (filediff_out_basepath,
           offset_block,
           end_block)

    # Generate task info

    task = {}
    task['stdout'] = "%s.stdout" % filediff_logpath
    task['stderr'] = "%s.stderr" % filediff_logpath
    task['pid'] = "%s.pid" % filediff_logpath
    task['offset_block'] = offset_block
    task['end_block'] = end_block

    # Generate source path

    task['src_path'] = src_path = abs_src_path
    task['dest_path'] = dest_path = abs_dest_path
    task['attr'] = attr = "%s.attr" \
        % filediff_logpath
    task['checksum'] = checksum = "%s.checksum" \
        % path_join(configuration,
                    backuplog_path,
                    "filediff.%s-%s.%s"
                    % (start_recno,
                       end_recno,
                       relpath_digest),
                    convert_utf8=False)

    # Generate ssh options

    ssh_opts = task['ssh_opts'] \
        = get_ssh_options_str(configuration,
                              hostname=configuration.source_host,
                              controlpath_postfix=(idx % nprocs))

    # Generate filediff command

    task['cmd'] = cmd = "%s" % bin_target_filediff \
        + " --verbose" \
        + " --disable-log" \
        + " --config=%r" % configuration.config_file \
        + " --attributes=%r" % attr\
        + " --ssh-options=%r" % ssh_opts \
        + " --blocksize=%d" % blocksize \
        + " --offset=%d" % offset_block \
        + " --end=%d" % end_block \
        + " --local=%r" % dest_path \
        + " --remote=%r" % src_path \
        + " --save-checksum=%r" % checksum

    logger.debug("filediff cmd: %s" % cmd)
    # Generate rsync args for subprocess

    task['args'] = shlex.split(cmd)
    # logger.debug("args: %s" % args)

    # Save rsync task to json file

    json_filepath = "%s.json" % filediff_logpath
    status = save_json(configuration, task, json_filepath)
    if not status:
        logger.error("Failed to save task to json file: %r"
                     % json_filepath)
        return None

    # Pickle filediff task to file

    pck_filepath = "%s.pck" % filediff_logpath
    status = pickle(configuration, task, pck_filepath)
    if not status:
        logger.error("Failed to save task to pck file: %r"
                     % json_filepath)
        return None

    return task


def wait_for_filediff_tasks(configuration, task_list):
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
                    logger.debug("Still executing filediff task: %d"
                                 " completed: %d/%d, waiting for: %d tasks"
                                 ", runtime: %d secs, filediff"
                                 " (%d-%d): %r -> %r"
                                 % (idx,
                                    completed,
                                    total_tasks,
                                    total_tasks-completed,
                                    int(time.time()-task['t1']),
                                    task['offset_block'],
                                    task['end_block'],
                                    task['src_path'],
                                    task['dest_path']))
                except Exception as error:
                    task['rc'] = 1
                    logger.error(
                        "filediff task: %d failed, task: %s, error: %s"
                        % (idx, task, error)
                    )
                if task.get('rc', -1) != -1:
                    completed += 1
                    logger.info("Finished filediff: %d/%d tasks"
                                % (completed, total_tasks))
                    logger.debug("Finished filediff: %d/%d tasks"
                                 ", filediff (%d-%d): %r -> %r"
                                 % (completed, total_tasks,
                                    task['offset_block'],
                                    task['end_block'],
                                    task['src_path'],
                                    task['dest_path']))
        time.sleep(1)

    return completed


def filediff(configuration,
             local_backupmaps,
             remote_snapshot_mount,
             source_timestamp,
             start_recno,
             end_recno,
             largefile_size,
             ):
    """Perform parallel diff update of largefiles
    Each filediff process is responsible for exactly one file"""
    logger = configuration.logger
    status = False
    filediff_status = True
    blocksize = 1024**2
    blockcount = 0

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
            abs_src_path = path_join(configuration,
                                     remote_snapshot_mount,
                                     relpath,
                                     convert_utf8=False)
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
                logger.debug("filediff: skipping small file (%d/%d): %r"
                             % (source_filesize, largefile_size, relpath))
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
            # NOTE: filediff require matching file sizes

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
                                source_filesize,
                                ))
                target_filesize = source_filesize
            blockcount = math.ceil(target_filesize / blocksize)
            blockrange = math.floor(blockcount / nprocs)
            if blockcount < nprocs:
                logger.error("blockcount: %d is smaller than nprocs: %d"
                             ", either lower blocksize: %d"
                             " or increase largefile_size: %d"
                             % (blockcount, nprocs, blocksize, largefile_size))
                terminate(configuration, task_list, pool, nprocs)
                return False
            for part in range(nprocs):
                offset_block = part * blockrange
                if part < nprocs-1:
                    end_block = offset_block + blockrange
                else:
                    end_block = -1
                task = __create_filediff_task(configuration,
                                              start_recno,
                                              end_recno,
                                              abs_src_path,
                                              abs_dest_path,
                                              relpath,
                                              backuplog_path,
                                              blocksize,
                                              offset_block,
                                              end_block,
                                              idx,
                                              nprocs,
                                              )
                if not task:
                    logger.error("Failed to create filediff entry (%d)" % idx
                                 + " for path: %r -> %r"
                                 % (relpath, abs_src_path))
                    terminate(configuration, task_list, pool, nprocs)
                    return False

                logger.info("Starting filediff task: %d" % idx)
                logger.debug("Starting filediff task: %d, filediff: %s"
                             % (idx, task['cmd']))
                task['t1'] = time.time()
                task['proc'] = pool.apply_async(__filediff_worker,
                                                   (task['args'],
                                                    task['stdout'],
                                                    task['stderr'],
                                                    task['pid'],))
                task_list.append(task)
                idx += 1

    # Wait for filediff tasks to complete

    completed = wait_for_filediff_tasks(configuration, task_list)
    logger.info("Completed: %d filediff tasks" % completed)

    # Check filediff status

    for task in task_list:
        task['proc'].wait()
        if task['proc'].successful():
            logger.debug("filediff finished: %d, checksum: %r"
                         % (task.get('rc', -1),
                            task.get('checksum', None)))
        if task.get('rc', -1) != 0:
            filediff_status = False
            logger.error("Filediff failed: rc: %d, stderr: %r"
                         % (task.get('rc', -1), task['stderr']))

    # Terminate

    status = terminate(
        configuration, task_list, pool, nprocs)

    result = False
    if status and filediff_status:
        result = True

    return result
