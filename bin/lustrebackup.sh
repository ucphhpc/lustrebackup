#!/bin/bash
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# lustrebackup - lustrebackup program
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

HOSTNAME="$(hostname -f)"
BASEPATH="${0%/*}"
COMMAND="${1##*/}"
ARGS="${*:2:$#}"
# echo "HOSTNAME: $HOSTNAME"
# echo "BASEPATH: $BASEPATH"
# echo "COMMAND: $COMMAND"
# echo "ARGS: $ARGS"
RUNLOG="/var/log/${COMMAND}.$$.log"
# echo "RUNLOG: $RUNLOG"
touch "$RUNLOG"
cmd="${BASEPATH}/${COMMAND} ${ARGS}"
# echo "$cmd"
eval "$cmd" >> "$RUNLOG" 2>&1
ret=$?
# NOTE: For mail notifications set: MAILFROM, MAILTO and/or NOTIFY_SUCCESS
#		as environment varibles
if [[ -n "$MAILTO" && -n "$MAILFROM" ]]; then
	if [ "$ret" -ne 0 ]; then
		mail -s "$HOSTNAME: $COMMAND: FAILED" -r "$MAILFROM" "$MAILTO" < "$RUNLOG"
	elif [ -n "${NOTIFY_SUCCESS}" ]; then
		mail -s "$HOSTNAME: $COMMAND: SUCCESS" -r "$MAILFROM" "$MAILTO" < "$RUNLOG"
	fi
fi
rm -f "$RUNLOG"

exit 0