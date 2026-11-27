#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# mgs - lustre backup lustre management server helpers
# Copyright (C) 2020-2026 The lustrebackup Project by the Science HPC Center at UCPH#
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

"""lustre management server helpers"""

import os
import time
from lustrebackup.shared.base import print_stderr
from lustrebackup.shared.defaults import tmp_dirname
from lustrebackup.shared.fileio import path_join
from lustrebackup.shared.serial import loads
from lustrebackup.shared.shell import shellexec
from lustrebackup.shared.ssh import get_ssh_options_str


def __active_mgs_host(configuration, verbose=False):
    """resolve active mgs host"""
    logger = configuration.logger
    result = None
    valid_secs = 60
    # Check for active cache file
    active_mgs_host_filepath = path_join(configuration,
                                         configuration.lustre_meta_basepath,
                                         tmp_dirname,
                                         'active_mgs_host',
                                         convert_utf8=False)
    if os.path.exists(active_mgs_host_filepath) \
        and os.path.getmtime(active_mgs_host_filepath) \
            > int(time.time())-valid_secs:
        try:
            with open(active_mgs_host_filepath, 'r') as fh:
                result = fh.readline().strip() or None
        except:
            result = None
            msg = (
                "Failed to read active_mgs_host_filepath: %r"
                % active_mgs_host_filepath
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)

    # Resolve from host if no valid cache file

    if result is None:
        mgs_hosts = configuration.lustre_mgs.split(':')
        status_cmd = "/etc/init.d/lustre status MGS"
        for mgs in mgs_hosts:
            ssh_opts = get_ssh_options_str(configuration,
                                           hostname=mgs)
            ssh_cmd = "ssh %s %s" % (ssh_opts, mgs)
            (status_rc,
             stdout,
             stderr) = shellexec(configuration,
                                 ssh_cmd,
                                 args=[status_cmd])
            if status_rc == 0:
                mgs_status = stdout.strip()
                logger.debug("%s: %s" % (mgs, mgs_status))
                if mgs_status == "running":
                    result = mgs
                    logger.debug("MGS active: %s" % mgs)
                    break
                else:
                    logger.debug("MGS inactive: %s" % mgs)
            else:
                logger.error(
                    "Failed to check MGS: %s, rc: %d, error: %s"
                    % (mgs,
                       status_rc,
                       stderr)
                )
        # Try to write updated result to cache file
        if result:
            try:
                with open(active_mgs_host_filepath, 'w') as fh:
                    fh.write("%s\n" % result)
            except:
                msg = "Failed to write active_mgs_host_filepath: %r" \
                    % active_mgs_host_filepath
                logger.error(msg)
                if verbose:
                    print_stderr("ERROR: %s" % msg)

    if result is None:
        msg = "Found no active MGS in %s" % mgs_hosts
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return result


def ssh_command_mgs(configuration,
                    command,
                    json=False,
                    stdout_filepath=None,
                    stderr_filepath=None,
                    verbose=False):
    """Resolve active MGS and execute command"""
    logger = configuration.logger
    result = {}
    active_mgs_host = __active_mgs_host(configuration, verbose=verbose)
    if active_mgs_host is None:
        msg = "Can't execute ssh_command_mgs due to missing active_mgs_host"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    ssh_opts = get_ssh_options_str(configuration,
                                   hostname=active_mgs_host)
    ssh_cmd = "ssh %s %s" % (ssh_opts, active_mgs_host)
    (command_rc,
     stdout,
     stderr) = shellexec(configuration,
                         ssh_cmd,
                         args=['%s' % command],
                         stdout_filepath=stdout_filepath,
                         stderr_filepath=stderr_filepath)
    result['host'] = active_mgs_host
    result['rc'] = command_rc
    result['stdout'] = stdout
    result['stderr'] = stderr

    if json:
        try:
            result['json'] = loads(result.get('stdout', ''),
                                   serializer='json',
                                   parse_int=int,
                                   parse_float=float)
        except Exception as err:
            result['json'] = {'error': err}
            msg = (
                "ssh_command_mgs json failed: %s: %s"
                ", stdout: %s, stderr: %s, err: %s"
                % (result.get('mgs', ''),
                   result.get('command', ''),
                   result.get('stdout', ''),
                   result.get('stderr', ''),
                   err)
            )
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
    return result
