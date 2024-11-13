#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# verify - lustre backup helpers
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

"""Backup verify helpers"""

import os

from lustrebackup.shared.base import print_stderr
from lustrebackup.shared.defaults import snapshot_dirname, \
    inprogress_verify_name
from lustrebackup.shared.fileio import path_join, make_symlink, \
    delete_file, release_file_lock
from lustrebackup.shared.lock import acquire_verify_lock
from lustrebackup.shared.shell import shellexec


def create_inprogress_verify(configuration,
                             vlogger,
                             snapshot_timestamp,
                             do_lock=True):
    """Check if verify is already in progress,
    if not then "mark inprogress",
    This is used by snapshot cleanup to spare snapshot"""
    retval = True
    meta_basepath = configuration.lustre_meta_basepath
    rel_snapshot_filepath = path_join(configuration,
                                      snapshot_dirname,
                                      "%s.pck" % snapshot_timestamp,
                                      logger=vlogger)
    snapshot_filepath = path_join(configuration,
                                  meta_basepath,
                                  rel_snapshot_filepath,
                                  logger=vlogger)
    if do_lock:
        lock = acquire_verify_lock(configuration, logger=vlogger)
        if not lock:
            vlogger.error("Failed to acquire verify lock")
            return False

    # Check if another instance is running

    status = running_verify(configuration,
                            vlogger,
                            snapshot_timestamp,
                            do_lock=False)
    if status:
        retval = False
        vlogger.error("Another verify process is running")

    # Mark inprogress

    if retval:
        if os.path.isfile(snapshot_filepath):
            inprogress_verify_filename = "%s_%d" \
                % (inprogress_verify_name,
                   snapshot_timestamp)
            retval = make_symlink(configuration,
                                  rel_snapshot_filepath,
                                  inprogress_verify_filename,
                                  working_dir=meta_basepath,
                                  force=True,
                                  logger=vlogger)
            if not retval:
                vlogger.error("Failed to create inprogress verify symlink"
                              + " (%s): %s -> %s"
                              % (meta_basepath,
                                 rel_snapshot_filepath,
                                 inprogress_verify_filename))
        else:
            retval = False
            vlogger.error("Missing snapshot: %r" % snapshot_filepath)

    if do_lock:
        lock_status = release_file_lock(configuration, lock, logger=vlogger)
        if not lock_status:
            retval = False
            vlogger.error("Failed to release verify lock")

    return retval


def remove_inprogress_verify(configuration,
                             vlogger,
                             snapshot_timestamp,
                             do_lock=True):
    """Remove inprogress marker"""
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_verify_filename = "%s_%d" \
        % (inprogress_verify_name,
           snapshot_timestamp)
    inprogress_filepath = path_join(configuration,
                                    meta_basepath,
                                    inprogress_verify_filename,
                                    logger=vlogger)
    if do_lock:
        lock = acquire_verify_lock(configuration, logger=vlogger)
        if not lock:
            vlogger.error("Failed to acquire verify lock")
            return False

    status = delete_file(configuration, inprogress_filepath, logger=vlogger)
    if not status:
        vlogger.error("Failed to remove inprogress verify marker: %r"
                      % inprogress_filepath)
    if do_lock:
        lock_status = release_file_lock(configuration, lock, logger=vlogger)
        if not lock_status:
            status = False
            vlogger.error("Failed to release verify lock")

    return status


def create_checksum(configuration, vlogger, filepath, verbose=False):
    """Create checksum of *filepath*"""
    checksum = None
    command = "%ssum \"%s\"" \
        % (configuration.backup_checksum_choice,
           filepath)
    (rc, stdout, stderr) = shellexec(configuration,
                                     command,
                                     logger=vlogger)
    if rc == 0:
        retval = True
        checksum = stdout[:32]
    else:
        retval = False
        msg = "Verify checksum failed for %r, ERROR: %s" \
            % (filepath,
               stderr)
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return (retval, checksum)


def running_verify(configuration,
                   vlogger,
                   snapshot_timestamp,
                   do_lock=True,
                   verbose=False):
    """Check for active verify, if filemarker
    is set then use psutil to check if there
    are active processes"""
    retval = False
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_verify_filename = "%s_%d" \
        % (inprogress_verify_name,
           snapshot_timestamp)
    inprogress_verify_filepath = path_join(configuration,
                                           meta_basepath,
                                           inprogress_verify_filename,
                                           logger=vlogger)
    if do_lock:
        lock = acquire_verify_lock(configuration, logger=vlogger)
        if not lock:
            msg = "Failed to acquire verify lock"
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
            return True

    if os.path.exists(inprogress_verify_filepath):
        retval = True
        msg = "Verify already running: %r" \
            % inprogress_verify_filepath
        vlogger.info(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    if do_lock:
        lock_status = release_file_lock(configuration, lock, logger=vlogger)
        if not lock_status:
            retval = True
            vlogger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    return retval
