#!/bin/bash
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# lustrebackup_ssh_command_validator -lustrebackup_ssh_command_validator helpers
# Copyright (C) 2020-2024  The lustrebackup Project by the Science HPC Center at UCPH
#
# This file is part of lustrebackup.
#
# MiG is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# MiG is distributed in the hope that it will be useful,
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

# Make sure only validated ssh commands are allowed
# NOTE: The remote rsync command must use '--protect-args'
# Used through ssh autorized_keys like:
# from="HOST,IP",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/usr/local/bin/lustrebackup_ssh_command_validator.sh" PUB_KEY

BIN_PATTERN="(/usr/bin/|/bin/|/usr/local/bin/)"
BACKUP_INIT_PATTERN="${BIN_PATTERN}?lustrebackup_source_init( .*)?"
BACKUP_ABORT_PATTERN="${BIN_PATTERN}?lustrebackup_source_abort( .*)?"
BACKUP_DONE_PATTERN="${BIN_PATTERN}?lustrebackup_source_done( .*)?"
BACKUP_VERIFY_INIT_PATTERN="${BIN_PATTERN}?lustrebackup_source_verify_init( .*)?"
BACKUP_VERIFY_LIST_PATTERN="${BIN_PATTERN}?lustrebackup_source_verify_list( .*)?"
FILEDIFF_PATTERN="${BIN_PATTERN}?lustrebackup_source_filediff( .*)?"
RSYNC_PATTERN="${BIN_PATTERN}?rsync --server --sender -[sldogDtprxXe.iLsfxCIvu]+"
SCP_PATTERN="${BIN_PATTERN}?scp( .*)?"

# echo "DEBUG: SSH_ORIGINAL_COMMAND: \"${SSH_ORIGINAL_COMMAND}\""

# NOTE: RSYNC_PATTERN regex MUST be unquoted here
if [[ "${SSH_ORIGINAL_COMMAND}" =~ ^${BACKUP_INIT_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${BACKUP_ABORT_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${BACKUP_DONE_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${BACKUP_VERIFY_INIT_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${BACKUP_VERIFY_LIST_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${FILEDIFF_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${RSYNC_PATTERN}$ \
        || "${SSH_ORIGINAL_COMMAND}" =~ ^${SCP_PATTERN}$ \
        ]]; then
    # /usr/bin/logger -t lustrebackup_ssh_command_validator -p auth.info "Run restricted command: ${SSH_ORIGINAL_COMMAND}"
    eval "${SSH_ORIGINAL_COMMAND}"
else
    /usr/bin/logger -t lustrebackup_ssh_command_validator -p auth.error "Refused illegal command: ${SSH_ORIGINAL_COMMAND}"
    exit 1
fi