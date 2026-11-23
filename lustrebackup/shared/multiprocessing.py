#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# multiprocessing - lustre backup helpers
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

"""This module contains various shared lustrebackup multiprocessing helpers"""

import os


def terminate(configuration, task_list, pool, nprocs):
    """Terminate multi processes pool and tasks"""
    logger = configuration.logger
    result = True
    # Check if all tasks finished, if not the kill them
    for task in task_list:
        process = task.get('proc', None)
        pid = task.get('pid', None)
        if process is None or pid is None:
            result = False
            logger.error("Invalid task: %s" % task)
            continue
        if not process.ready():
            try:
                logger.debug("Killing task: %s" % task)
                with open(pid, 'r') as fh:
                    os.kill(int(fh.read()), 9)
            except Exception as err:
                result = False
                logger.error("Failed to kill task: %s with pid: %d, err: %s"
                             % (task, pid, err))

    # Terminate process pool

    try:
        pool.terminate()
    except Exception as err:
        result = False
        logger.error("Failed to terminate pool, err: %s" % err)

    return result
