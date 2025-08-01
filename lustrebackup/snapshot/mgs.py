#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# mgs - lustre backup helpers
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

"""This module contains various lustre snapshots helpers
used for creating, listing and mounting snapshots on the MGS"""

import time

from lustrebackup.shared.base import print_stderr
from lustrebackup.shared.defaults import bin_mgs_snapshot_create, \
    bin_mgs_snapshot_destroy, bin_mgs_snapshot_list, \
    bin_mgs_snapshot_mount, bin_mgs_snapshot_umount, \
    snapshot_name_format
from lustrebackup.shared.serial import loads
from lustrebackup.shared.shell import shellexec


def ssh_command_mgs(configuration,
                    command,
                    json=False,
                    stdout_filepath=None,
                    stderr_filepath=None,
                    verbose=False):
    """Resolve active MGS and execute command"""
    logger = configuration.logger
    result = {}
    active_mgs_host = None
    mgs_hosts = configuration.lustre_mgs.split(':')
    status_cmd = "/etc/init.d/lustre status MGS"
    for mgs in mgs_hosts:
        ssh_cmd = "ssh %s" % mgs
        (status_rc,
         stdout,
         stderr) = shellexec(configuration,
                             ssh_cmd,
                             args=[status_cmd])
        if status_rc == 0:
            mgs_status = stdout.strip()
            logger.debug("%s: %s" % (mgs, mgs_status))
            if mgs_status == "running":
                active_mgs_host = mgs
                logger.debug("MGS active: %s" % mgs)
                break
            else:
                logger.debug("MGS inactive: %s" % mgs)

    if active_mgs_host is None:
        msg = "Found no active MGS in %s" % mgs_hosts
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    ssh_cmd = "ssh %s" % active_mgs_host
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
            msg = "ssh_command_mgs json failed: %s: %s" \
                % (result.get('mgs', ''),
                   result.get('command', '')) \
                + ", stdout: %s, stderr: %s, err: %s" \
                % (result.get('stdout', ''),
                   result.get('stderr', ''),
                   err)
            logger.error(msg)
            if verbose:
                print_stderr("ERROR: %s" % msg)
    return result


def destroy_snapshot_mgs(configuration,
                         snapshot_name,
                         verbose=False):
    """Destroy snapshot on MGS"""
    logger = configuration.logger
    if not snapshot_name:
        msg = "destroy_snapshot: Missing snapshot name"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False
    retval = True
    command = bin_mgs_snapshot_destroy \
        + " -f -F \"%s\" -n \"%s\"" \
        % (configuration.lustre_fsname, snapshot_name)
    result_mgs = ssh_command_mgs(configuration, command)
    if not result_mgs:
        retval = False
        msg = "Failed to destroy %r snapshot: %r" \
            % (configuration.lustre_fsname,
               snapshot_name,)
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
    if result_mgs.get('rc', -1) != 0:
        retval = False
        msg = "Failed to destroy %r snapshot: %r, err: %s" \
            % (configuration.lustre_fsname,
               snapshot_name,
               result_mgs.get('stderr', ''))
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def create_snapshot_mgs(configuration,
                        snapshot_name=None,
                        snapshot_timestamp=int(time.time()),
                        comment='Auto generated snapshot',
                        verbose=False):
    """Create lustre snapshot on MGS, returns timestamp"""
    logger = configuration.logger

    if snapshot_name is None:
        snapshot_name = snapshot_name_format \
            % {'fsname': configuration.lustre_fsname,
               'timestamp': snapshot_timestamp}
    command = bin_mgs_snapshot_create \
        + " -F \"%s\"" % configuration.lustre_fsname \
        + " -n \"%s\"" % snapshot_name \
        + " -c \"%s\"" % comment
    result_mgs = ssh_command_mgs(configuration, command)
    if result_mgs is None:
        msg = "failed to create %r snapshot: %r" \
            % (configuration.lustre_fsname,
               snapshot_name)
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None
    # TODO: rc: 110 (-110 on MGS see why)
    # TODO: rc: 110 barrier expired, if this is the case then try again
    #           then double barrier time and try again
    if result_mgs.get('rc', -1) != 0:
        msg = "failed to create %r snapshot: %r, err: %s" \
            % (configuration.lustre_fsname,
               snapshot_name,
               result_mgs.get('stderr', ''))
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return None

    return snapshot_timestamp


def mount_snapshot_mgs(configuration,
                       snapshot_name,
                       force=True,
                       verbose=False,
                       ):
    """Mount snapshot on MGS"""
    logger = configuration.logger
    retval = True
    if not snapshot_name:
        msg = "mount_snapshot_mgs: Missing snapshot name"
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Skip check if force is True

    if not force:
        # Fetch MGS snapshot info
        (_, snapshot_info) = snapshot_list_mgs(configuration,
                                               snapshot_name=snapshot_name)
        if not snapshot_info:
            logger.error("uount_snapshot_mgs:"
                         " Failed to fetch snapshot info for: %r"
                         % snapshot_name)
            return False
        # Check if snapshot is already mounted
        if snapshot_info.find("status: mounted") != -1:
            logger.debug("snapshot: %r already mounted on mgs"
                         & snapshot_name)
            return True

    # mount snapshot on MGS

    command = bin_mgs_snapshot_mount \
        + " -F \"%s\" -n \"%s\"" \
        % (configuration.lustre_fsname,
           snapshot_name)
    result_mgs = ssh_command_mgs(configuration, command)
    if not result_mgs:
        retval = False
        msg = "MGS: %r, fs: %r snapshot mount: %r failed" \
            % (configuration.lustre_mgs,
               configuration.lustre_fsname,
               snapshot_name)
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
    elif result_mgs.get('rc', -1) != 0:
        retval = False
        msg = "MGS: %r, fs: %r snapshot mount: %r failed" \
            % (result_mgs.get('host', ''),
               configuration.lustre_fsname,
               snapshot_name) \
            + ", rc: %d, host: %s, error: %s" \
            % (result_mgs.get('rc', -1),
               result_mgs.get('host', ''),
               result_mgs.get('stderr', ''))
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def umount_snapshot_mgs(configuration, snapshot, force=False, verbose=False):
    """Umount snapshot on MGS"""
    logger = configuration.logger
    retval = True
    snapshot_name = snapshot.get('snapshot_name', '')
    if not snapshot_name:
        msg = "Failed to extract umount snapshot name: %s" \
            % snapshot
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return False

    # Skip check if force is True

    if not force:
        # Fetch MGS snapshot info
        (_, snapshot_info) = snapshot_list_mgs(configuration,
                                               snapshot_name=snapshot_name)
        if not snapshot_info:
            logger.error("umount_snapshot_mgs:"
                         " Failed to fetch snapshot info for: %r"
                         % snapshot_name)
            return False
        # Check if snapshot is mounted
        if snapshot_info.find("status: not mount") != -1:
            logger.debug("%r NOT mounted on mgs"
                         % snapshot_name)
            return True

    # Umount snapshot on MGS

    command = bin_mgs_snapshot_umount \
        + " -F \"%s\" -n \"%s\"" \
        % (configuration.lustre_fsname,
           snapshot.get('snapshot_name', ''))
    result_mgs = ssh_command_mgs(configuration, command)
    if not result_mgs:
        retval = False
        msg = "MGS: %r, fs: %r snapshot umount: %r failed" \
            % (configuration.lustre_mgs,
               configuration.lustre_fsname,
               snapshot.get('snapshot_name', ''))
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
    elif result_mgs.get('rc', -1) != 0:
        retval = False
        msg = "MGS: %r, fs: %r snapshot umount: %r failed" \
            % (result_mgs.get('host', ''),
               configuration.lustre_fsname,
               snapshot.get('snapshot_name', '')) \
            + ", rc: %d, error: %s" \
            % (result_mgs.get('rc', -1),
               result_mgs.get('stderr', ''))
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return retval


def snapshot_list_mgs(configuration,
                      snapshot_name=None,
                      snapshot_list_filepath=None,
                      allow_missing_snapshot=False,
                      verbose=False):
    """Retrieve snapshot list from MGS to
    and store in snapshot_list_filepath if provided
    """
    retval = True
    logger = configuration.logger
    if snapshot_list_filepath:
        msg = "Using snapshot_list_filepath: %r" % snapshot_list_filepath
        logger.info(msg)
        if verbose:
            print_stderr("Using snapshot_raw_filepath: %r"
                         % snapshot_list_filepath)

    # Fetch snapshot list from MGS

    command = bin_mgs_snapshot_list \
        + " -F \"%s\"" % configuration.lustre_fsname
    if snapshot_name:
        command += " -n \"%s\"" % snapshot_name
    logger.info(command)
    result_mgs = ssh_command_mgs(configuration,
                                 command,
                                 stdout_filepath=snapshot_list_filepath)
    if result_mgs is None:
        msg = "Failed to fetch snapshot list for %r" \
            % configuration.lustre_fsname
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)
        return (False, '')

    rc = result_mgs.get('rc', -1)
    if allow_missing_snapshot and rc == 22:
        logger.debug("MGS missing snapshot: %s" % snapshot_name)
    elif rc != 0:
        retval = False
        msg = "Failed to fetch snapshot list for %r, rc: %d, err: %s" \
            % (configuration.lustre_fsname,
               result_mgs.get('rc', -1),
               result_mgs.get('stderr', ''))
        logger.error(msg)
        if verbose:
            print_stderr("ERROR: %s" % msg)

    return (retval, result_mgs.get('stdout', ''))
