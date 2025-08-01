#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# lock - lustre backup lock helpers
# Copyright (C) 2020-2025 The lustrebackup Project by the Science HPC Center at UCPH
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

"""Shared lustre backup lock helpers"""

import os

from lustrebackup.shared.defaults import lock_dirname
from lustrebackup.shared.fileio import path_join, \
    acquire_file_lock, makedirs_rec


def __acquire_lock(configuration, lockname, logger=None):
    """Acquire inprogress backupmap lock"""
    # from lustrebackup.shared.debug import stacktrace
    # stacktrace(configuration, prefix=lockname, logger=logger, verbose=True)
    if logger is None:
        logger = configuration.logger

    meta_basepath = configuration.lustre_meta_basepath
    lock_basepath = path_join(configuration,
                              meta_basepath,
                              lock_dirname,
                              logger=logger)
    if not os.path.exists(lock_basepath):
        status = makedirs_rec(configuration,
                              lock_basepath,
                              logger=logger)
        if not status:
            logger.error("Failed to create log basepath: %r"
                         % lock_basepath)
        return None
    lock_filepath = path_join(configuration,
                              lock_basepath,
                              lockname,
                              logger=logger)
    try:
        lock = acquire_file_lock(configuration,
                                 lock_filepath,
                                 logger=logger)
    except Exception as err:
        logger.error("Failed to acquire file lock: %r, err: %s"
                     % (lock_filepath, err))
        return None

    return lock


def acquire_backupmap_lock(configuration, logger=None):
    """Acquire inprogress backupmap lock"""
    return __acquire_lock(configuration,
                          'backupmap.lock',
                          logger=logger)


def acquire_verify_lock(configuration, logger=None):
    """Acquire inprogress backupmap lock"""
    return __acquire_lock(configuration,
                          'verify.lock',
                          logger=logger)


def acquire_snapshot_lock(configuration, logger=None):
    """Acquire snapshot lock"""

    return __acquire_lock(configuration,
                          'snapshot.lock',
                          logger=logger)
