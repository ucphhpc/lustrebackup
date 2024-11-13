#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# shell - lustre backup shell helpers
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

"""shell operations"""

import shlex
import subprocess

from lustrebackup.shared.base import force_unicode


def shellexec(configuration,
              command,
              args=[],
              stdout_filepath=None,
              stderr_filepath=None,
              logger=None):
    """Executes command
    Returns (exit_code, stdout, stderr) of subprocess"""
    result = 0
    if logger is None:
        logger = configuration.logger
    stdout_handle = subprocess.PIPE
    stderr_handle = subprocess.PIPE
    if stdout_filepath is not None:
        stdout_handle = open(stdout_filepath, "w+")
    if stderr_filepath is not None:
        stderr_handle = open(stderr_filepath, "w+")
    __args = shlex.split(command)
    __args.extend(args)
    # logger.debug("__args: %s" % __args)
    process = subprocess.Popen(
        __args, stdout=stdout_handle, stderr=stderr_handle)
    stdout, stderr = process.communicate()
    rc = process.wait()

    if stdout_filepath:
        stdout = stdout_filepath
        stdout_handle.close()
    if stderr_filepath:
        stderr = stderr_filepath
        stderr_handle.close()

    # Close stdin, stdout and stderr FDs if they exists
    if process.stdin:
        process.stdin.close()
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()

    if stdout:
        stdout = force_unicode(stdout)
    if stderr:
        stderr = force_unicode(stderr)
    if result != 0:
        logger.error("shellexec: %s %s: rc: %s, stdout: %s, error: %s"
                     % (command,
                        " ".join(__args),
                        rc,
                        stdout,
                        stderr))
    # else:
    #    logger.debug("%s %s: rc: %s, stdout: %s, error: %s" \
    #            % (command,
    #            " ".join(args),
    #            rc,
    #            stdout,
    #            stderr))

    return (rc, stdout, stderr)
