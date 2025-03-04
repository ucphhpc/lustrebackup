#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# verify - lustre backup helpers
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

"""Backup verify helpers"""

import os
import re

from lustrebackup.shared.base import print_stderr, force_unicode
from lustrebackup.shared.defaults import snapshot_dirname, \
    inprogress_verify_name, last_verified_name
from lustrebackup.shared.fileio import path_join, make_symlink, \
    delete_file, release_file_lock
from lustrebackup.shared.lock import acquire_verify_lock
from lustrebackup.shared.shell import shellexec


def create_inprogress_verify(configuration,
                             vlogger,
                             source_timestamp,
                             target_timestamp=0,
                             do_lock=True):
    """Check if verify is already in progress,
    if not then "mark inprogress".
    This is used to prevent multiple verifications
    of the same snapshots as well as to spare snapshots
    from cleanup"""
    retval = True
    meta_basepath = configuration.lustre_meta_basepath
    if target_timestamp > 0:
        snapshot_timestamp = target_timestamp
    else:
        snapshot_timestamp = source_timestamp
    rel_snapshot_filepath = path_join(configuration,
                                      snapshot_dirname,
                                      "%s.pck" % snapshot_timestamp,
                                      logger=vlogger)
    snapshot_filepath = path_join(configuration,
                                  meta_basepath,
                                  rel_snapshot_filepath,
                                  logger=vlogger)
    inprogress_verify_filename = "%s_%d" \
        % (inprogress_verify_name,
           source_timestamp)
    if target_timestamp > 0:
        inprogress_verify_filename = "%s-%d" \
            % (inprogress_verify_filename, target_timestamp)
    if do_lock:
        lock = acquire_verify_lock(configuration, logger=vlogger)
        if not lock:
            vlogger.error("Failed to acquire verify lock")
            return False

    # Check if another instance is running

    status = running_verify(configuration,
                            vlogger,
                            snapshot_timestamp,
                            target_timestamp=target_timestamp,
                            do_lock=False)
    if status:
        retval = False
        vlogger.error("Another verify process is running")

    # Mark inprogress

    if retval:
        if os.path.isfile(snapshot_filepath):
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
                             source_timestamp,
                             target_timestamp=0,
                             do_lock=True):
    """Remove inprogress marker"""
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_verify_filename = "%s_%d" \
        % (inprogress_verify_name,
           source_timestamp)
    if target_timestamp > 0:
        inprogress_verify_filename = "%s-%d" \
            % (inprogress_verify_filename, target_timestamp)
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
                   source_timestamp,
                   target_timestamp=0,
                   do_lock=True,
                   verbose=False):
    """Check for active verify, if filemarker
    is set then use psutil to check if there
    are active processes"""
    retval = False
    meta_basepath = configuration.lustre_meta_basepath
    inprogress_verify_filename = "%s_%d" \
        % (inprogress_verify_name,
           source_timestamp)
    if target_timestamp > 0:
        inprogress_verify_filename = "%s-%d" \
            % (inprogress_verify_filename, target_timestamp)
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


def get_last_verified_timestamp(configuration,
                                vlogger,
                                target=False,
                                verbose=False,
                                ):
    """Resolve last verified timestamp from 'last_verified' link"""
    meta_basepath = configuration.lustre_meta_basepath
    last_verified_filepath = path_join(configuration,
                                       meta_basepath,
                                       last_verified_name)
    result = 0
    if not os.path.islink(last_verified_filepath):
        msg = "No last_verified link: %r" \
            % last_verified_filepath
        vlogger.warning(msg)
        if verbose:
            print_stderr("WARNING: %s" % msg)
        return result

    last_verified_pck_re = re.compile("([0-9]+)[-]?([0-9]*)\\.pck")
    last_verified_pck = force_unicode(os.readlink(last_verified_filepath))
    last_verified_ent = last_verified_pck_re.search(last_verified_pck)
    if not last_verified_ent:
        msg = "Failed to resolve last_verified_ent from: %r" \
            % last_verified_pck
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None
    if not last_verified_ent.group(1):
        msg = "Failed to resolve source timestamp from: %r" \
            % last_verified_pck
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None
    if target and not last_verified_ent.group(2):
        msg = "Failed to resolve target timestamp from: %r" \
            % last_verified_pck
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None
    try:
        if not target:
            result = int(last_verified_ent.group(1))
        else:
            result = int(last_verified_ent.group(2))
    except Exception as err:
        msg = "Failed to resolve target timestamp from: %r, error: %s" \
            % (last_verified_pck, err)
        vlogger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    return result
