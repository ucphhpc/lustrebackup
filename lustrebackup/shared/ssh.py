#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# ssh - lustre backup ssh helpers
# Copyright (C) 2020-2024 The lustrebackup Project by the Science HPC Center at UCPH#
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

"""ssh helpers"""

import os
# NOTE: MDS/MGS do not use this module
#       and therefore do not require paramiko
try:
    import paramiko
except Exception:
    paramiko = None


def get_ssh_config(configuration):
    """Read ssh config file and return as dict"""
    logger = configuration.logger
    result = {}
    ssh_config = paramiko.SSHConfig()
    if not os.path.exists(configuration.system_ssh_config):
        logger.error("Misssing ssh_config_file: %r"
                     % configuration.system_ssh_config)
        return None
    with open(configuration.system_ssh_config) as f:
        ssh_config.parse(f)

    # If hostname is '' then only global config is returned

    for hostname in ssh_config.get_hostnames():
        result[hostname] = ssh_config.lookup(hostname)

    return result


def get_ssh_options(configuration, hostname):
    """Read ssh config file and return options for
    hostname merged with global
    NOTE: Local options take precedence"""
    logger = configuration.logger
    result = {}
    ssh_config = get_ssh_config(configuration)
    if not ssh_config:
        return None
    if hostname not in ssh_config.keys():
        logger.error("Missing host: %r in ssh config: %r"
                     % (hostname, configuration.system_ssh_config))
        return None
    result = ssh_config.get("*")
    result.update(ssh_config.get(hostname, {}))

    return result


def ssh_connect(configuration, hostname):
    """Establish connection to remote ssh server"""
    logger = configuration.logger
    if not paramiko:
        logger.error("Paramiko NOT installed")
        return None
    ssh_config = get_ssh_config(configuration)
    if not ssh_config:
        logger.error("Missing ssh_config")
        return None
    ssh_options = ssh_config.get(hostname, {})
    if not ssh_options:
        logger.error("Host: %s not found in ssh_config: %r"
                     % (hostname, configuration.system_ssh_config))
        return None
    ssh_handle = None
    ssh_handle = paramiko.SSHClient()
    ssh_handle.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_handle.set_log_channel(logger.name)
    try:
        ssh_handle.connect(ssh_options.get('hostname', ''),
                           port=ssh_options.get('port', 22),
                           username=ssh_options.get('user', 22),
                           key_filename=ssh_options.get('identityfile', ''),
                           timeout=60
                           )

    except Exception as err:
        ssh_handle = None
        logger.error("Failed to estabilsh ssh connecting to hostname: %s"
                     % hostname
                     + ", config: %s, error: %s"
                     % (ssh_config, err))

    return ssh_handle


def ssh_disconnect(configuration, ssh_handle):
    """Disconnect ssh connection"""
    logger = configuration.logger
    status = True
    try:
        ssh_handle.close()
    except Exception as err:
        status = False
        logger.error("Failed close ssh connection, error: %s"
                     % err)

    return status
