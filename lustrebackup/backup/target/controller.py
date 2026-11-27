#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# target - lustre backup helpers
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

"""This module contains various lustre backup target helpers"""

import multiprocessing
import os
import re
import shlex
import subprocess
import time
import traceback

import psutil
import xxhash
from lustrebackup.backup.target.filediff import filediff
from lustrebackup.backup.target.filediff_zfs import filediff_zfs
from lustrebackup.shared.backup import get_backuplog_path, inprogress_backup
from lustrebackup.shared.base import force_unicode, force_utf8, print_stderr
from lustrebackup.shared.configuration import get_configuration_object
from lustrebackup.shared.defaults import backup_dirname, backupmap_dirname, \
    backupmap_merged_dirname, bin_source_abort, bin_source_done, \
    bin_source_init, bin_target_backup, inprogress_backup_name, \
    last_backup_name, rsync_logformat_modified, rsync_opts_deleted, \
    rsync_opts_modified, snapshot_name_format
from lustrebackup.shared.fileio import delete_file, make_symlink, \
    makedirs_rec, path_join, pickle, remove_dir, save_json, touch, unpickle
from lustrebackup.shared.logger import Logger
from lustrebackup.shared.lustre import lfs_fid2path, lfs_path2fid
from lustrebackup.shared.multiprocessing import terminate
from lustrebackup.shared.serial import loads
from lustrebackup.shared.shell import shellexec
from lustrebackup.shared.snapshot import create_snapshot
from lustrebackup.shared.ssh import get_ssh_options, get_ssh_options_str, \
    ssh_connect, ssh_disconnect
# https://pypi.org/project/scp/
from scp import SCPClient


def fetch_backupmap(configuration, backup_source_conf, source_timestamp):
    """Fetch backupmap from live site"""
    logger = configuration.logger
    result = {}
    remote_meta_basepath = backup_source_conf.get("lustre_meta_basepath", "")
    remote_path = path_join(
        configuration,
        remote_meta_basepath,
        backupmap_dirname,
        source_timestamp,
        backupmap_merged_dirname,
        convert_utf8=False,
    )
    local_meta_basepath = configuration.lustre_meta_basepath
    local_path = path_join(
        configuration,
        local_meta_basepath,
        backupmap_dirname,
        source_timestamp,
        convert_utf8=False,
    )
    logger.debug(
        "fetch_backupmap: remote: %r -> local: %r"
        % (remote_path, local_path)
    )

    if os.path.exists(local_path):
        status = True
        logger.info("Skipping scp_get of existing backupmap: %r" % local_path)
    else:
        status = scp_get(configuration, remote_path,
                         local_path, recursive=True)
    if not status:
        return (status, None)

    result[source_timestamp] = local_path

    return (status, result)


def rename(
    configuration, local_backupmaps, source_timestamp, start_recno, end_recno
):
    """Perform renames"""
    logger = configuration.logger
    retval = True

    backuplog_path = get_backuplog_path(configuration, source_timestamp)
    if not backuplog_path:
        logger.error(
            "Failed to retrieve backup log path for: %d" % source_timestamp
        )
        return False
    rename_logpath = path_join(
        configuration,
        backuplog_path,
        "rename.%d-%d.log" % (start_recno, end_recno),
        convert_utf8=False,
    )
    try:
        fh = open(rename_logpath, "w")
    except Exception as err:
        logger.error(
            "Failed to open rename log: %r, error: %s" % (rename_logpath, err)
        )
        return False

    # NOTE: Renames must be performed in the original order

    sorted_local_backupmaps = sorted(list(local_backupmaps.keys()))
    renamed_part_re = re.compile("[0-9]*\\.[0-9]*\\.renamed\\.pck")
    renamed_filepaths = []
    for bm_timestamp in sorted_local_backupmaps:
        local_backupmap_path = local_backupmaps[bm_timestamp]
        with os.scandir(local_backupmap_path) as it:
            for entry in it:
                if renamed_part_re.fullmatch(entry.name):
                    renamed_filepaths.append(entry.path)

    # Load all rename entries and ordered by recno

    all_renames = {}
    for filepath in renamed_filepaths:
        renamed = unpickle(configuration, filepath)
        if renamed is None:
            retval = False
            logger.error("Failed to load renamed entries from: %r" % filepath)
            break
        if not renamed:
            logger.info("Found no renamed entries in: %r" % filepath)
            continue
        for tfid, value in renamed.items():
            recno = value.get("recno", [])
            if not recno:
                retval = False
                rel_src_path = value.get("src_path", "")
                rel_dest_path = value.get("dest_path", "")
                fh.write(
                    "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                    % (tfid, rel_src_path, rel_dest_path, str(recno))
                    + "|:|status=empty_recno\n"
                )
                logger.error("Empty recno for: %s: %s" % (tfid, value))
                continue
            # NOTE: We need last recno of each renew
            sorted_recno = sorted(recno, reverse=True)
            all_renames[sorted_recno[0]] = (tfid, value)

    if not retval:
        fh.close()
        return retval

    # NOTE: Renames must be handled in-order
    # with repect to last recno

    rename_basepath = path_join(
        configuration,
        configuration.lustre_data_mount,
        configuration.lustre_data_path,
        convert_utf8=False,
    )

    ordered_rename_recno = sorted(all_renames.keys())
    renamed_dirs = {}
    remove_tmpdirs = []
    for rename_recno in ordered_rename_recno:
        (tfid, value) = all_renames[rename_recno]
        rel_src_path = value.get("src_path", "")
        rel_dest_path = value.get("dest_path", "")
        recno = value.get("recno", [])
        if not rel_src_path:
            retval = False
            fh.write(
                "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                % (tfid, rel_src_path, rel_dest_path, str(recno))
                + "|:|status=empty_src\n"
            )
            logger.error("Rename empty source path for: %s: %s" %
                         (tfid, value))
            break
        if not rel_dest_path:
            retval = False
            fh.write(
                "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                % (tfid, rel_src_path, rel_dest_path, str(recno))
                + "|:|status=empty_dest\n"
            )
            logger.error(
                "Rename empty destination path for: %s: %s" % (tfid, value)
            )
            break
        src_path = path_join(
            configuration, rename_basepath, rel_src_path, convert_utf8=False
        )

        dest_path = path_join(
            configuration, rename_basepath, rel_dest_path, convert_utf8=False
        )

        # Check if src parent was renamed prior to this entry
        # and resolve new (renamed) source path for fid if needed

        dirlist = sorted(list(renamed_dirs.keys()), key=len, reverse=True)
        logger.debug("dirlist: %s" % dirlist)
        renamed_parents = [x for x in dirlist if rel_src_path.startswith(x)]
        if renamed_parents:
            parent = renamed_parents[0]
            parent_fid = renamed_dirs[parent]
            logger.debug(
                "Rename found renamed parent: %s -> %r" % (parent_fid, parent)
            )
            (rc, new_parent) = lfs_fid2path(
                configuration.lustre_data_mount, parent_fid
            )
            if rc == 0:
                abs_parent = path_join(
                    configuration, rename_basepath, parent, convert_utf8=False
                )
                abs_new_parent = path_join(
                    configuration,
                    configuration.lustre_data_mount,
                    new_parent,
                    convert_utf8=False,
                )
                logger.info(
                    "Rename changing source path (%s) %r -> %r"
                    % (parent_fid, abs_parent, abs_new_parent)
                )
                logger.debug("old src_path: %r" % src_path)
                src_path = src_path.replace(abs_parent, abs_new_parent)
                logger.debug("new src_path: %r" % src_path)
            else:
                retval = False
                msg = "lfs_path2fid: %d" % rc
                fh.write(
                    "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                    % (tfid, rel_src_path, rel_dest_path, str(recno))
                    + "|:|status=%s\n" % msg
                )
                logger.error(
                    "Remame failed to resolve new parent:"
                    + " %r : %s : %s"
                    % (configuration.lustre_data_mount, parent_fid, msg)
                )
                break

        # Missing src_path and existing dest_path:
        # This happens if src_path was renamed to dest_path
        # in a previous backup run that failed after this rename.
        # When this backup run try to rename src_path to dest_path
        # src_path is then missing as it was already renamed to dest_path

        if not os.path.exists(src_path) and os.path.exists(dest_path):
            # If dest_path is a directory then store fid of it,
            # this is needed if a child of dest_path is renamed
            # after this skipped entry
            if os.path.isdir(dest_path):
                (rc, fid) = lfs_path2fid(dest_path)
                logger.debug(
                    "lfs_path2fid: rc: %d, fid: %s, %r, " % (
                        rc, fid, dest_path)
                )
                if rc == 0:
                    # NOTE: It's the relation between the missing 'src_path'
                    #       the new 'dest_path' we need
                    renamed_dirs[rel_src_path] = fid
                else:
                    msg = "lfs_path2fid: %d" % rc
                    fh.write(
                        "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                        % (tfid, rel_src_path, rel_dest_path, str(recno))
                        + "|:|status=%s\n" % msg
                    )
                    logger.error(
                        "Rename skip failed: %r -> %r, error: %s"
                        % (src_path, dest_path, msg)
                    )
                    break
            fh.write(
                "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                % (tfid, rel_src_path, rel_dest_path, str(recno))
                + "|:|status=skipped\n"
            )
            logger.info(
                "Rename skipping: %r -> %r for %s: %s"
                % (src_path, dest_path, tfid, value)
            )
            continue

        # Log if 'src_path' is missing and can't be resolved from 'dest_path'.
        # This can occur when re-running a failed backup where
        # 'rename' + 'delete' of rename target (dest_path) was performed.

        elif not os.path.exists(src_path):
            fh.write(
                "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                % (tfid, rel_src_path, rel_dest_path, str(recno))
                + "|:|status=missing_src\n"
            )
            msg = (
                "Rename missing src path: %r for %s: %s"
                % (src_path, tfid, value)
            )
            logger.warning(msg)
            continue

        if os.path.exists(dest_path):
            # If a file is blocking rename destination then remove it.
            # If a directory is blocking rename destination then move
            # it to a 'temporary' dir and delete it after all
            # renames are completed.
            # NOTE: This can occur as rename is done before 'rsync' and
            #       thereby delete, that is if a dir/file X is deleted on
            #       backup source and thereafter a dir/file Y is renamed
            #       to X then the original X may still be on the backup target
            #       when rename is done.
            # NOTE: renames are ordered so a blocking dir/file do not occur
            #       as a result of a rename sequence.
            # NOTE: Directories are kept at a temporary location
            #       until all renames are done as rename otherwise fails
            #       if the destination-path is a sub-path of the source-path.
            #       Example:
            #       client:
            #           mkdir -p x/y/z
            #       lustrebackup:
            #           source: create snapshot + backupmap
            #           target: create backup
            #       client:
            #           mv x/y/z x.org
            #           rm -rf x
            #           mv x.org x
            if len(dest_path) <= 1 or len(dest_path) <= (
                len(configuration.lustre_data_mount)
                + len(configuration.lustre_data_path)
            ):
                retval = False
                fh.write(
                    "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                    % (tfid, rel_src_path, rel_dest_path, str(recno))
                    + "|:|status=malformed_destination\n"
                )
                logger.error(
                    "Rename malformed destination: %r for %s: %s"
                    % (dest_path, tfid, value)
                )
                break
            # Move blocking dest_path to temporary location
            # NOTE: Deleted when all renames are done
            if os.path.isdir(dest_path):
                tmp_dest_path = "%s.rename.tmp" % dest_path
                remove_tmpdirs.append(tmp_dest_path)
                try:
                    os.rename(dest_path, tmp_dest_path)
                    (rc, fid) = lfs_path2fid(tmp_dest_path)
                    logger.debug(
                        "lfs_path2fid: rc: %d, fid: %s, %r, "
                        % (rc, fid, src_path)
                    )
                    if rc == 0:
                        # NOTE: It's the relation between
                        # the missing 'src_path' the new 'dest_path' we need
                        renamed_dirs[rel_src_path] = fid
                    else:
                        raise ValueError("lfs_path2fid: %d" % rc)
                except Exception as err:
                    retval = False
                    fh.write(
                        "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s|:|status=%s\n"
                        % (tfid, rel_src_path, rel_dest_path, str(recno), err)
                    )
                    logger.error(
                        "Rename failed to move blocking dest dir:"
                        + " %r -> %r for %s: %s"
                        % (dest_path, tmp_dest_path, tfid, value)
                    )
                    break
                logger.info(
                    "Rename moved blocking dest dir:"
                    + " %r -> %r for %s: %s"
                    % (dest_path, tmp_dest_path, tfid, value)
                )
                # Change source path if part of dest path
                if src_path.startswith(dest_path):
                    new_src_path = tmp_dest_path + src_path[len(dest_path):]
                    logger.info(
                        "Rename changed source path: %r -> %r"
                        % (src_path, new_src_path)
                    )
                    src_path = new_src_path
            else:
                status = delete_file(configuration, dest_path)
                if status:
                    logger.info(
                        "Rename removed blocking dest file:"
                        + " %r for %s: %s" % (dest_path, tfid, value)
                    )
                else:
                    retval = False
                    msg = (
                        "Rename failed to remove blocking dest file:"
                        " %r for %s: %s" % (dest_path, tfid, value)
                    )
                    fh.write(
                        "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s|:|status=%s\n"
                        % (tfid, rel_src_path, rel_dest_path, str(recno), msg)
                    )
                    logger.error(msg)
                    break

        dest_path_dir = os.path.dirname(dest_path)
        if not os.path.exists(dest_path_dir):
            retval = makedirs_rec(
                configuration, dest_path_dir, accept_existing=True
            )
            if not retval:
                fh.write(
                    "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s"
                    % (tfid, rel_src_path, rel_dest_path, str(recno))
                    + "|:|status=failed_to_ensure_dest:%r\n" % dest_path_dir
                )
                logger.error(
                    "Rename failed to ensure dest dir: %r for %s: %s"
                    % (dest_path_dir, tfid, value)
                )
                break
        try:
            # If src_path is a directory then store fid,
            # this is needed if a child of src_path is renamed
            # after this rename
            if os.path.isdir(src_path):
                (rc, fid) = lfs_path2fid(src_path)
                logger.debug(
                    "lfs_path2fid: rc: %d, fid: %s, %r, " % (rc, fid, src_path)
                )
                if rc == 0:
                    renamed_dirs[rel_src_path] = fid
                else:
                    raise ValueError("lfs_path2fid: %d" % rc)
            os.rename(src_path, dest_path)
            fh.write(
                "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s|:|status=OK\n"
                % (tfid, rel_src_path, rel_dest_path, str(recno))
            )
            logger.info("Renamed: %r -> %r" % (src_path, dest_path))
        except Exception as err:
            retval = False
            fh.write(
                "|:|tfid=%s|:|src=%s|:|dest=%s|:|recno=%s|:|status=%s\n"
                % (tfid, rel_src_path, rel_dest_path, str(recno), err)
            )
            logger.error(
                "Rename failed: %r -> %r, error: %s"
                % (src_path, dest_path, err)
            )
            break
    fh.close()

    # Remove renamed temp dirs

    do_remove_tempdirs = retval
    for tmpdir in remove_tmpdirs:
        if not do_remove_tempdirs:
            logger.info("Rename failed, leaving tmpdir: %r" % tmpdir)
            continue
        status = remove_dir(configuration, tmpdir, recursive=True)
        if status:
            logger.info("Rename removed tmpdir: %r" % tmpdir)
        else:
            retval = False
            logger.error("Rename failed to removed tmpdir: %r" % tmpdir)

    return retval


def __mark_dirty_worker(
    conf_file,
    dirty_filepaths,
    backuplog_basepath,
    start_recno,
    end_recno,
    idx,
    nprocs,
):
    """multiprocessing worker for marking dirty files"""
    success = True
    result = {"marked": 0, "failed": 0, "skipped": 0, "error": ""}
    try:
        # Use separate log file for changes worker

        configuration = get_configuration_object(
            conf_file=conf_file, skip_log=True
        )

        # User local_logger to log path resolves for each timestamp

        worker_log_filepath = path_join(
            configuration,
            backuplog_basepath,
            "dirty.%d-%d.out" % (start_recno, end_recno),
            convert_utf8=False,
        )

        worker_logger_obj = Logger(
            configuration.loglevel,
            logfile=worker_log_filepath,
            app="__mark_dirty_worker.%d" % idx,
        )
        logger = worker_logger_obj.logger
        configuration.logger = logger
    except Exception as err:
        result["error"] = str(err)
        return (False, result)

    try:
        pid = os.getpid()
        dirty_logpath = path_join(
            configuration,
            backuplog_basepath,
            "dirty.%d-%d.%d.log" % (start_recno, end_recno, idx),
            convert_utf8=False,
        )
        fh = open(dirty_logpath, "w")
        for filepath in dirty_filepaths:
            dirty = unpickle(configuration, filepath)
            if dirty is None:
                success = False
                msg = "Failed to load dirty files from: %r" % filepath
                result["error"] += "%s\n" % msg
                logger.error("%d.%d: %s" % (idx, pid, msg))
                break
            if not dirty:
                logger.info(
                    "%d.%d: Found no dirty entries in: %r"
                    % (idx, pid, filepath)
                )
                continue
            for relpath in dirty.keys():
                dirty_path = path_join(
                    configuration,
                    configuration.lustre_data_mount,
                    configuration.lustre_data_path,
                    relpath,
                    convert_utf8=False,
                )
                # NOTE: Only mark existing files as dirty
                if not os.path.exists(dirty_path):
                    result["skipped"] += 1
                    fh.write(
                        "|:|path=%s|:|fullpath=%s|:|status=SKIPPED\n"
                        % (relpath, dirty_path)
                    )
                    continue
                status = touch(configuration, dirty_path, 0)
                if status:
                    result["marked"] += 1
                    fh.write(
                        "|:|path=%s|:|fullpath=%s|:|status=OK\n"
                        % (relpath, dirty_path)
                    )
                else:
                    success = False
                    result["failed"] += 1
                    fh.write(
                        "|:|path=%s|:|fullpath=%s|:|status=FAILED\n"
                        % (relpath, dirty_path)
                    )
                    msg = "Failed to mark dirty: %r, fullpath: %r" % (
                        relpath,
                        dirty_path,
                    )
                    result["error"] += "%s\n" % msg
                    logger.error("%d.%d: %s" % (idx, pid, msg))
        fh.close()
    except Exception as err:
        result["error"] += "%s\n" % err
        logger.error(traceback.format_exc())
        return (False, result)

    return (success, result)


def mark_dirty(
    configuration, local_backupmaps, source_timestamp, start_recno, end_recno
):
    "Mark dirty files by setting mtime to 0"
    result = {"marked": 0, "failed": 0, "skipped": 0, "error": None}
    logger = configuration.logger
    status = True
    backuplog_basepath = get_backuplog_path(configuration, source_timestamp)
    if not backuplog_basepath:
        logger.error(
            "Failed to retrieve backup log path for: %d" % source_timestamp
        )
        return False
    nprocs = configuration.system_nprocs
    # multiprocessing.log_to_stderr()
    pool = multiprocessing.Pool(processes=nprocs)

    t1 = time.time()
    dirty_part_re = re.compile("[0-9]*\\.[0-9]*\\.dirty\\.pck")
    dirty_filepaths = {}
    for idx in range(nprocs):
        dirty_filepaths[idx] = {}

    for local_backupmap_path in local_backupmaps.values():
        with os.scandir(local_backupmap_path) as it:
            for entry in it:
                if dirty_part_re.fullmatch(entry.name):
                    idx = int(entry.name.split(".")[0]) % nprocs
                    dirty_filepaths[idx][entry.path] = (
                        dirty_filepaths[idx].get(entry.path, 0) + 1
                    )

    dirty_worker_tasks = []
    for idx in range(nprocs):
        if not dirty_filepaths[idx]:
            logger.debug("Skipping empty idx: %d" % idx)
            continue
        task = {"idx": idx}
        logger.info(
            "Starting __mark_dirty_worker: %d, nprocs: %d" % (idx, nprocs)
        )
        task['proc'] = pool.apply_async(
            __mark_dirty_worker,
            (
                configuration.config_file,
                dirty_filepaths[idx],
                backuplog_basepath,
                start_recno,
                end_recno,
                idx,
                nprocs,
            ),
        )
        dirty_worker_tasks.append(task)

    # Wait for tasks to finish

    status = True
    for task in dirty_worker_tasks:
        idx = task['idx']
        proc = task['proc']
        logger.info("Waiting for mark_dirty task: %d" % idx)
        proc.wait()
        if proc.successful():
            (worker_status, worker_result) = proc.get()
            # msg = "__mark_dirty_worker: %d finished with: " \
            #    % idx \
            #    + "status: %s and message: %s " \
            #    % (worker_status, worker_result)
            if worker_status:
                logger.info("%d: %s" % (idx, worker_result))
                result["marked"] += worker_result["marked"]
                result["failed"] += worker_result["failed"]
                result["skipped"] += worker_result["skipped"]
            else:
                status = False
                logger.error("%d: %s" % (idx, worker_result))
        else:
            status = False
            msg = ("__mark_dirty_worker (%d/%d) failed with error: "
                   % (idx,
                      len(dirty_worker_tasks)))
            try:
                proc.get()
                msg += "unknown"
            except Exception as err:
                msg += str(err)
            logger.error(msg)

    t2 = time.time()
    logger.info(
        "Marked %d dirty, failed: %d, skipped: %d"
        % (result["marked"], result["failed"], result["skipped"])
        + " backupmap entries in %d secs" % (t2 - t1)
    )

    pool.terminate()

    return status


def __rsync_worker(rsync_args, rsync_stdout, rsync_stderr, rsync_pid):
    """Helper function to call rsync"""
    stdout_handle = open(rsync_stdout, "w")
    stderr_handle = open(rsync_stderr, "w")
    pid_handle = open(rsync_pid, "w")
    process = subprocess.Popen(
        rsync_args, stdout=stdout_handle, stderr=stderr_handle
    )
    process_pid = process.pid
    pid_handle.write(str(process_pid))
    pid_handle.close()
    result = process.wait()
    pid_handle.close()
    stderr_handle.close()
    stdout_handle.close()

    return result


def create_target_snapshot(
    configuration,
    backup_source_conf,
    source_timestamp,
    target_timestamp,
    start_recno,
    end_recno,
    largefile_size,
    verbose=False,
):
    """Create lustre snapshot"""
    logger = configuration.logger
    retval = False
    # Force disk flush
    t1 = time.time()
    os.sync()
    t2 = time.time()
    msg = "os.sync() done in %d secs" % (int(t2 - t1))
    logger.info(msg)
    if verbose:
        print_stderr(msg)

    logger = configuration.logger
    retval = True

    # Wait for flush to settle
    # time.sleep(60)

    snapshot_name = snapshot_name_format % {
        'name': configuration.lustre_snapshot_name,
        'timestamp': target_timestamp,
    }

    comment = (
        "lustrebackup snapshot:"
        " source_fsname: %s"
        ", source_snapshot: %d"
        ", source_start_recno: %d"
        ", source_end_recno: %d"
        ", source_largefile_size: %d"
        % (backup_source_conf.get("lustre_fsname", ""),
           source_timestamp,
           start_recno,
           end_recno,
           largefile_size
           )
    )
    created_snapshot_timestamp = create_snapshot(
        configuration,
        snapshot_name=snapshot_name,
        snapshot_timestamp=target_timestamp,
        comment=comment,
        verbose=verbose,
    )
    if created_snapshot_timestamp is None:
        retval = False
        msg = "Failed to create snapshot: %r" % snapshot_name
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def create_rsync_task(
    configuration,
    ssh_options,
    start_recno,
    end_recno,
    abs_src_path,
    relpath,
    backuplog_path,
    min_file_size,
    max_file_size,
    mode,
    idx,
    nprocs,
):
    """Creates rsync task"""
    logger = configuration.logger

    xxh128 = xxhash.xxh128()
    xxh128.update(relpath)
    relpath_digest = xxh128.hexdigest()

    # Generate rsync log logpath

    rsync_logname = "rsync"

    rsync_logpath = path_join(
        configuration,
        backuplog_path,
        "%s.%s.%s-%s.%s.%s"
        % (rsync_logname, mode, start_recno, end_recno, idx, relpath_digest),
        convert_utf8=False,
    )

    # Generate task info

    task = {}
    task['mode'] = mode
    task['log'] = rsync_log_filepath = "%s.log" % rsync_logpath
    task['stdout'] = "%s.stdout" % rsync_logpath
    task['stderr'] = "%s.stderr" % rsync_logpath
    task['pid'] = "%s.pid" % rsync_logpath

    # NOTE: Explicit set ssh options for rsync as we want
    # them in the log
    ssh_opts = task['ssh_opts'] = '-e "ssh %s"' % get_ssh_options_str(
        configuration,
        ssh_options=ssh_options,
        controlpath_postfix=(idx % nprocs),
    )
    # Generate source path

    task['src_path'] = src_path = abs_src_path + os.sep

    # Generate and create destpath as it might not exist on the target
    # prior to execution this rsync process is executed

    task['dest_path'] = dest_path = path_join(
        configuration,
        configuration.lustre_data_mount,
        configuration.lustre_data_path,
        relpath,
        convert_utf8=False,
    )

    # Generate excludes
    # Ensure that destination exists
    status = makedirs_rec(configuration, dest_path, accept_existing=True)
    if not status:
        logger.error("Failed to create rsync destination path: %r" % dest_path)
        return None

    local_rsync_logformat = ""
    if mode == "modified":
        local_rsync_opts = rsync_opts_modified
        local_rsync_logformat = rsync_logformat_modified
        if min_file_size > 0:
            local_rsync_opts += " --min-size=%d" % min_file_size
        if max_file_size > 0:
            local_rsync_opts += " --max-size=%d" % max_file_size
        local_rsync_opts += (
            " --checksum-choice='%s'" % configuration.backup_checksum_choice
        )
    elif mode == "deleted":
        local_rsync_opts = rsync_opts_deleted
    else:
        logger.error("Unsupported rsync mode: %r" % mode)
        return None

    # Generate rsync command
    ssh_user = ssh_options.get("user", "")
    ssh_hostname = ssh_options.get("hostname", "")

    cmd = '%s %s %s --log-file="%s"' % (
        configuration.backup_rsync_command,
        ssh_opts,
        local_rsync_opts,
        rsync_log_filepath,
    )
    if local_rsync_logformat:
        cmd += ' --log-file-format="%s"' % local_rsync_logformat
    cmd += ' %s@%s:"%s" "%s"' % (
        ssh_user,
        ssh_hostname,
        src_path,
        dest_path,
    )
    logger.debug("rsync cmd: %s" % cmd)
    task['cmd'] = cmd
    # Generate rsync args for subprocess

    task['args'] = shlex.split(cmd)
    # logger.debug("args: %s" % args)

    # Save rsync task to json file

    json_filepath = "%s.json" % rsync_logpath
    status = save_json(configuration, task, json_filepath)
    if not status:
        logger.error("Failed to save task to json file: %r" % json_filepath)
        return None

    # Pickle rsync task to file

    pck_filepath = "%s.pck" % rsync_logpath
    status = pickle(configuration, task, pck_filepath)
    if not status:
        logger.error("Failed to save task to pck file: %r" % pck_filepath)
        return None

    return task


def wait_for_rsync_tasks(configuration, task_list):
    """Wait for tasks to finish"""
    logger = configuration.logger
    idx = 0
    total_tasks = len(task_list)
    completed = 0
    while completed != total_tasks:
        for idx in range(total_tasks):
            task = task_list[idx]
            process = task['proc']
            if task.get("rc", None) is None:
                try:
                    # logger.debug("Checking task: %d" % idx)
                    task['rc'] = process.get(1)
                except multiprocessing.TimeoutError:
                    logger.debug(
                        "Still executing %s task: %d" % (task['mode'], idx)
                        + " completed: %d/%d, waiting for: %d tasks"
                        % (completed, total_tasks, total_tasks - completed)
                        + ", runtime: %d secs, rsync: %r -> %r"
                        % (
                            int(time.time() - task['t1']),
                            task['src_path'],
                            task['dest_path'],
                        )
                    )
                except Exception as err:
                    # Worker raised, rsync() reports it
                    task['rc'] = 1
                    logger.error("%s task: %d/%d failed: %s"
                                 % (task['mode'], idx, total_tasks, err))
                if task.get("rc", None) is not None:
                    completed += 1
                    logger.info(
                        "Finished %s: %d/%d tasks"
                        % (task['mode'], completed, total_tasks)
                    )
                    logger.debug(
                        "Finished %s: %d/%d tasks, rsync: %r -> %r"
                        % (
                            task['mode'],
                            completed,
                            total_tasks,
                            task['src_path'],
                            task['dest_path'],
                        )
                    )
        time.sleep(1)
    return completed


def rsync(
    configuration,
    local_backupmaps,
    remote_snapshot_mount,
    source_timestamp,
    start_recno,
    end_recno,
    largefile_size,
    mode,
):
    """Perform parallel rsync of the directories either in modified dict,
    or loaded from filepath
    Each rsync process is responsible for exactly one directory"""
    logger = configuration.logger
    status = False
    rsync_status = True
    ssh_options = get_ssh_options(configuration, configuration.source_host)

    # Get backup log path

    backuplog_path = get_backuplog_path(configuration, source_timestamp)
    if not backuplog_path:
        logger.error(
            "Failed to create backup log path for: %d" % source_timestamp
        )
        return False

    # Fetch number of parallel processes

    nprocs = configuration.system_nprocs

    # Resolve  modified filepaths

    part_re = re.compile("[0-9]*\\.[0-9]*\\.modified\\.pck")
    input_filepaths = {}
    for local_backupmap_path in local_backupmaps.values():
        with os.scandir(local_backupmap_path) as it:
            for entry in it:
                if part_re.fullmatch(entry.name):
                    input_filepaths[entry.path] = (
                        input_filepaths.get(entry.path, 0) + 1
                    )

    # Spawn pool

    pool = multiprocessing.Pool(processes=nprocs)
    min_file_size = 0
    max_file_size = largefile_size

    # Create rsync tasks

    idx = 0
    task_list = []
    for filepath in input_filepaths:
        task_input = unpickle(configuration, filepath)
        if task_input is None:
            logger.error("Failed to load task_input from: %r" % filepath)
            terminate(configuration, task_list, pool, nprocs)
            return False
        if not task_input:
            logger.info("Found no %s entries in: %r" % (mode, filepath))
            continue
        for relpath in task_input.keys():
            abs_src_path = path_join(
                configuration,
                remote_snapshot_mount,
                relpath,
                convert_utf8=False,
            )
            task = create_rsync_task(
                configuration,
                ssh_options,
                start_recno,
                end_recno,
                abs_src_path,
                relpath,
                backuplog_path,
                min_file_size,
                max_file_size,
                mode,
                idx,
                nprocs,
            )
            if not task:
                logger.error(
                    "Failed to create rsync entry (%d)" % idx
                    + " for path: %r -> %r" % (relpath, abs_src_path)
                )
                terminate(configuration, task_list, pool, nprocs)
                return False

            logger.info("Starting %s task: %d" % (mode, idx))
            logger.debug(
                "Starting %s task: %d, rsync: %s" % (mode, idx, task['cmd'])
            )
            task['idx'] = idx
            task['t1'] = time.time()
            task['proc'] = pool.apply_async(
                __rsync_worker,
                (
                    task['args'],
                    task['stdout'],
                    task['stderr'],
                    task['pid'],
                ),
            )
            task_list.append(task)
            idx += 1

    # Wait for rsync tasks to complete
    # TODO: Implement garbage collection of tasks in the above loop
    # to prevent filling op memmory with tasks that was allready done

    completed = wait_for_rsync_tasks(configuration, task_list)
    logger.info("Completed: %d rsync %s tasks" % (completed, mode))

    # Check rsync status

    for task in task_list:
        idx = task['idx']
        proc = task['proc']
        proc.wait()
        if proc.successful():
            logger.debug("rsync finished: %r" % task['log'])
            if task.get("rc", None) != 0:
                rsync_status = False
                logger.error("Rsync failed, stderr: %r" % task['stderr'])
        else:
            rsync_status = False
            msg = ("__rsync_worker (%d/%d) failed with error: "
                   % (idx,
                      len(task_list))
                   )
            try:
                proc.get()
                msg += "unknown"
            except Exception as err:
                msg += str(err)
            logger.error(msg)

    # Terminate

    status = terminate(configuration, task_list, pool, nprocs)

    result = False
    if status and rsync_status:
        result = True

    return result


def abort_backup(configuration, verbose=False):
    """Abort running backup"""
    logger = configuration.logger
    local_meta_basepath = configuration.lustre_meta_basepath

    inprogress_backup_filepath = path_join(
        configuration,
        local_meta_basepath,
        inprogress_backup_name,
        convert_utf8=False,
    )
    backup_pids = {}
    if not os.path.exists(inprogress_backup_filepath):
        msg = "No running backup found"
        logger.info(msg)
        if verbose:
            print(msg)
        return True

    backup_info = unpickle(configuration, inprogress_backup_filepath)
    if not backup_info:
        msg = (
            "Failed to retrieve backup info from: %r"
            % inprogress_backup_filepath
        )
        logger.error(msg)
        if verbose:
            print_stderr(msg)
        return False
    backup_timestamp = backup_info.get("snapshot_timestamp", 0)
    backup_dirpath = path_join(
        configuration,
        local_meta_basepath,
        backup_dirname,
        backup_timestamp,
        convert_utf8=False,
    )
    # NOTE: A pid file is empty if the task failed to start
    pid_re = re.compile("(rsync\\.|filediff).*\\.pid")
    with os.scandir(backup_dirpath) as it:
        for entry in it:
            if pid_re.fullmatch(entry.name):
                with open(entry.path) as fh:
                    pid = fh.readline().strip() 
                    if pid.isdigit():
                        backup_pids[int(pid)] = entry.path

    # Kill backup processes and their parents,
    status = True
    killed_pids = []
    for pid, pidpath in backup_pids.items():
        logger.debug("Aborting pid: %d, %r" % (pid, pidpath))
        if not psutil.pid_exists(pid):
            logger.debug("Pid: %d, no longer active: %r" % (pid, pidpath))
        try:
            process = psutil.Process(pid)
            kill_procs = [process]
            for process_parent in process.parents():
                for part in process_parent.cmdline():
                    if part.endswith(bin_target_backup):
                        kill_procs.append(process_parent)
                        break
            # Without a bin_target_backup parent, only kill the process
            # if it already ran when its pid file was written:
            # the target crashed and left it behind. 
            # Otherwise the pid was reused
            if len(kill_procs) == 1 \
                    and process.create_time() > os.path.getmtime(pidpath) + 1:
                continue
            # Kill parents first, so they can't start new tasks
            for kill_process in reversed(kill_procs):
                kpid = kill_process.pid
                if kpid in killed_pids:
                    continue
                try:
                    kill_process.kill()
                    logger.debug("Waiting for kill: %d" % kpid)
                    kill_process.wait(timeout=60)
                except psutil.NoSuchProcess:
                    pass
                logger.debug("Killed: %d" % kpid)
                killed_pids.append(kpid)

        except psutil.NoSuchProcess:
            logger.debug("no such process pid: %d , %r" % (pid, pidpath))
        except Exception as err:
            status = False
            msg = "abort_backup: Failed to kill %d, error: %s" % (pid, err)
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Call source abort backup

    if status:
        ssh_cmd = "ssh %s" % configuration.source_host
        command = bin_source_abort
        if configuration.source_conf:
            command += " --config %s" % configuration.source_conf
        if verbose:
            command += " --verbose"
        logger.debug("command: %s" % command)
        (command_rc, stdout, stderr) = shellexec(
            configuration, ssh_cmd, args=[command]
        )
        if command_rc > 1:
            status = False
            msg = (
                "Backup abort: ssh host: %r, cmd: %r, rc: %s, error: %s"
                % (configuration.source_host,
                   command,
                   command_rc,
                   stderr)
            )
            logger.error(msg)
            if verbose:
                print_stderr(msg)
            return False

    if status:
        status = delete_file(configuration, inprogress_backup_filepath)

    return status


def scp_get(
    configuration, remote_path, local_path, ssh_handle=None, recursive=False
):
    """scp remote_path to local filepath"""
    logger = configuration.logger
    local_ssh_close = False
    if ssh_handle is None:
        local_ssh_close = True
    status = True

    # Create destination path if it doesn't exist
    local_target_dir = os.path.dirname(local_path)
    if not os.path.exists(local_target_dir):
        logger.info("scp_get: Creating local target dir: %r" %
                    local_target_dir)
        status = makedirs_rec(configuration, local_target_dir)
        if not status:
            logger.error(
                "Failed to create local target dir: %r" % local_target_dir
            )
            return False

    # Open ssh connection to backupmap server

    if ssh_handle is None:
        ssh_handle = ssh_connect(configuration, configuration.source_host)
        if not ssh_handle:
            logger.error(
                "Failed connecting to source host: %s"
                % configuration.source_host
            )
            return False

    # Perform scp

    try:
        scp = SCPClient(ssh_handle.get_transport())
        logger.debug(
            "scp_get: %s:%s -> %s"
            % (
                configuration.source_host,
                force_utf8(remote_path),
                force_utf8(local_path),
            )
        )
        scp.get(remote_path, local_path, recursive=recursive)
    except Exception as err:
        status = False
        logger.error(
            "Failed to execute scp.get: %s -> %s), error: %s"
            % (remote_path, local_path, err)
        )

    # Close ssh connection to server

    if local_ssh_close:
        status = ssh_disconnect(configuration, ssh_handle)
        if not status:
            logger.error(
                "Failed close connection to ssh source host: %r"
                % configuration.source_host
            )

    return status


def init_backup(configuration, verbose=False):
    """Tell remote backupmap server that backup is to begin,
    on success snapshot latest backupmap snapshot is mounted"""

    logger = configuration.logger
    result = None

    # Open ssh connection to backupmap server

    ssh_cmd = "ssh %s" % configuration.source_host
    command = bin_source_init
    if configuration.source_conf:
        command += " --config %s" % configuration.source_conf
    if verbose:
        command += " --verbose"
    logger.debug("ssh_cmd: %s" % ssh_cmd)
    logger.debug("command: %s" % command)
    (command_rc, stdout, stderr) = shellexec(
        configuration, ssh_cmd, args=[command]
    )
    if command_rc == 0:
        try:
            result = loads(
                stdout, serializer="json", parse_int=int, parse_float=float
            )
        except Exception as err:
            msg = (
                "Failed parse source init, error: %s, input: %s"
                % (err, stdout)
            )
            logger.error(msg)
            if verbose:
                print_stderr(msg)
            return None
    else:
        msg = (
            "Backup init: ssh host: %r, cmd: %r, rc: %s, error: %s"
            % (configuration.source_host,
               command,
               command_rc,
               stderr)
        )
        logger.error(msg)
        if verbose:
            print_stderr(msg)
        return None

    return result


def backup_done(configuration, end_timestamp):
    """Tell source server that backup is done"""
    logger = configuration.logger
    status = False
    result = None
    command = bin_source_done
    if configuration.source_conf:
        command += " -c %s" % configuration.source_conf
    command += " -t %d" % end_timestamp
    logger.debug("command: %s" % command)

    ssh_cmd = "ssh %s" % configuration.source_host
    (command_rc, stdout, stderr) = shellexec(
        configuration, ssh_cmd, args=[command]
    )
    if command_rc == 0:
        status = True
        result = stdout.strip()
        if result == "None":
            status = False
            result = None
            logger.error(
                "Backup done: ssh host: %r, cmd: %r, returned: None"
                % (configuration.source_host, command)
            )
    else:
        status = False
        logger.error(
            "Backup done: ssh host: %r, cmd: %r, returned: %s"
            % (configuration.source_host, command, stderr.strip())
        )

    return (status, result)


def backup(configuration, verbose=False):
    """Perform lustre rsync"""
    logger = configuration.logger
    retval = True

    # Generate local backupmeta paths and check of they exists

    local_meta_basepath = configuration.lustre_meta_basepath
    if not os.path.isdir(local_meta_basepath):
        logger.error("Missing local backup meta path: %r" %
                     local_meta_basepath)
        return False

    # Check if backup inprogress

    status = inprogress_backup(configuration, verbose=verbose)
    if status:
        msg = "Backup already in progress"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Check if data path is a lustre is mount

    lustre_mounted = False
    os_mounts = psutil.disk_partitions(all=True)
    for mount in os_mounts:
        if (
            mount.fstype == "lustre"
            and mount.mountpoint == configuration.lustre_data_mount
        ):
            lustre_mounted = True

    if not lustre_mounted:
        msg = (
            "lustre target NOT mounted: %r"
            % configuration.lustre_data_mount
        )
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Initialize backup, call remote backup client which
    # sets inprogress_backup marker, mount snapshot and
    # return remote configuration needed to perform backup

    backup_source_conf = init_backup(configuration)
    if backup_source_conf is None:
        msg = "Failed to init backup"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    remote_backupinfo_filepath = backup_source_conf.get(
        "backupinfo_filepath", ""
    )
    logger.debug("remote_backupinfo_filepath: %r" % remote_backupinfo_filepath)

    if not remote_backupinfo_filepath:
        retval = False
        msg = "Failed to retrieve remote backup info filepath"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    # Fetch remote backup info

    if retval:
        rel_local_backupinfo_filepath = path_join(
            configuration,
            backup_dirname,
            os.path.basename(remote_backupinfo_filepath),
        )
        local_backupinfo_filepath = path_join(
            configuration,
            local_meta_basepath,
            rel_local_backupinfo_filepath,
            convert_utf8=False,
        )
        retval = scp_get(
            configuration,
            remote_backupinfo_filepath,
            local_backupinfo_filepath
        )
        if not retval:
            logger.error(
                "Failed to retrieve remote file: %r to %r"
                % (remote_backupinfo_filepath, local_backupinfo_filepath)
            )

    # Load backupinfo

    if retval:
        backupinfo = unpickle(configuration, local_backupinfo_filepath)
        if not backupinfo:
            retval = False
            msg = (
                "Failed to load backup info from: %r"
                % local_backupinfo_filepath
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Resolve snapshot timestamp

    if retval:
        source_timestamp = backupinfo.get("snapshot_timestamp", 0)
        if source_timestamp == 0:
            retval = False
            msg = "Failed to extract source_timestamp"
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Resolve changelog start-record-number

    if retval:
        start_recno = backupinfo.get("start_recno", -1)
        if start_recno == -1:
            retval = False
            msg = (
                "Failed to resolve start_recno from: %r"
                % remote_backupinfo_filepath
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Resolve changelog end-record-number

    if retval:
        end_recno = backupinfo.get("end_recno", -1)
        if end_recno == -1:
            retval = False
            msg = "Failed to resolve end from: %r" % remote_backupinfo_filepath
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Resolve large file size

    if retval:
        largefile_size = backupinfo.get("largefile_size", -1)

    # Resolve source snapshot mount

    if retval:
        remote_snapshot_mount = backupinfo.get("snapshot_mount", "")
        if not remote_snapshot_mount:
            retval = False
            msg = (
                "Failed to resolve remote snapshot mount from: %r"
                % remote_backupinfo_filepath
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Fetch backupmap

    if retval:
        t1 = time.time()
        (retval, local_backupmaps) = fetch_backupmap(
            configuration,
            backup_source_conf,
            source_timestamp,
        )
        t2 = time.time()
        msg = "fetch_backupmap done in %d secs" % (t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)
        if not retval:
            msg = (
                "Failed to fetch backupmap for source snapshot: %d"
                % source_timestamp
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Mark backup in progress

    if retval:
        retval = make_symlink(
            configuration,
            rel_local_backupinfo_filepath,
            inprogress_backup_name,
            working_dir=local_meta_basepath,
            force=True,
        )
        if not retval:
            msg = (
                "Failed to mark backup in progress: %r"
                % rel_local_backupinfo_filepath
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Switch default logger to backup logger

    main_logger = configuration.logger
    if retval:
        backup_log_filepath = "%s.log" % get_backuplog_path(
            configuration, source_timestamp
        )
        backup_logger_obj = Logger(
            configuration.loglevel,
            logfile=backup_log_filepath,
            app=force_unicode(backup_log_filepath),
        )
        configuration.logger = logger = backup_logger_obj.logger
        main_logger.info("Logging backup details to: %r" % backup_log_filepath)

    # Start with renaming entries

    if retval:
        t1 = time.time()
        retval = rename(
            configuration,
            local_backupmaps,
            source_timestamp,
            start_recno,
            end_recno,
        )
        t2 = time.time()
        msg = "rename done in %d secs" % (t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)
        if not retval:
            msg = (
                "Failed to ensure renames for source snapshot: %d"
                % source_timestamp
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Mark dirty
    # This is needed as data may be changed within the files
    # without the metadata (size and mtime) changing

    if retval:
        t1 = time.time()
        retval = mark_dirty(
            configuration,
            local_backupmaps,
            source_timestamp,
            start_recno,
            end_recno,
        )
        t2 = time.time()
        msg = "mark dirty done in %d secs" % (t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)
        if not retval:
            msg = (
                "Failed to mark dirty entries for source snapshot: %d"
                % source_timestamp
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Transfer modified using rsync

    if retval:
        t1 = time.time()
        retval = rsync(
            configuration,
            local_backupmaps,
            remote_snapshot_mount,
            source_timestamp,
            start_recno,
            end_recno,
            largefile_size,
            "modified",
        )
        t2 = time.time()
        msg = "rsync modified done in %d secs" % (t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)
        if not retval:
            msg = (
                "Failed to rsync modified entries for source snapshot: %d"
                % source_timestamp
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Transfer largefiles filediff

    if retval:
        if configuration.lustre_zfs_filediff:
            filediff_handler = filediff_zfs
        else:
            filediff_handler = filediff
        t1 = time.time()
        retval = filediff_handler(
            configuration,
            local_backupmaps,
            remote_snapshot_mount,
            source_timestamp,
            start_recno,
            end_recno,
            largefile_size,
        )
        t2 = time.time()
        msg = "%s done in %d secs" % (filediff_handler.__name__, t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)
        if not retval:
            msg = "Failed to %s modified entries" " for source snapshot: %d" \
                % (filediff_handler.__name__,
                   source_timestamp)
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Delete files last to ensure deletion dispite filesize

    if retval:
        t1 = time.time()
        retval = rsync(
            configuration,
            local_backupmaps,
            remote_snapshot_mount,
            source_timestamp,
            start_recno,
            end_recno,
            largefile_size,
            "deleted",
        )
        t2 = time.time()
        msg = "rsync deleted done in %d secs" % (t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)
        if not retval:
            msg = (
                "Failed to rsync delete entries for source snapshot: %d"
                % source_timestamp
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Create snapshot

    target_timestamp = int(time.time())

    if retval:
        t1 = time.time()
        status = create_target_snapshot(
            configuration,
            backup_source_conf,
            source_timestamp,
            target_timestamp,
            start_recno,
            end_recno,
            largefile_size,
            verbose=True,
        )
        retval = status
        t2 = time.time()
        if retval:
            msg = "Created snapshot in %d secs" % (t2 - t1)
            logger.info(msg)
            if verbose:
                print(msg)
        else:
            msg = (
                "Failed to create target snapshot for source snapshot: %d"
                % source_timestamp
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Switch default logger back to main logger

    configuration.logger = logger = main_logger

    # Mark backup done

    if retval:
        t1 = target_timestamp = time.time()
        (retval, msg) = backup_done(configuration, target_timestamp)
        t2 = time.time()
        if verbose and msg:
            print("backup_done: %s" % msg)
        msg = "Marked backup_done in %d secs" % (t2 - t1)
        logger.info(msg)
        if verbose:
            print(msg)

    # Create backup done marker

    if retval:
        retval = make_symlink(
            configuration,
            rel_local_backupinfo_filepath,
            last_backup_name,
            working_dir=local_meta_basepath,
            force=True,
        )
        if not retval:
            msg = (
                "Failed to set last backup marker to: %r"
                % rel_local_backupinfo_filepath
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Remove inprogress backup marker

    inprogress_backup_filepath = path_join(
        configuration,
        local_meta_basepath,
        inprogress_backup_name,
        convert_utf8=False,
    )
    del_retval = delete_file(configuration, inprogress_backup_filepath)
    if not del_retval:
        msg = (
            "Failed to remove inprogress backup marker: %r"
            % inprogress_backup_filepath
        )
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    # TODO:
    # log / print backup stats

    return retval
