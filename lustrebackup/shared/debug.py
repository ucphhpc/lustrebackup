#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# debug - lustre backup debug helpers
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


"""lustre backup debug helpers"""


from inspect import getframeinfo, stack
from lustrebackup.shared.base import print_stderr


def stacktrace(configuration, prefix=None, logger=None, verbose=False):
    """log and print stacktrace if verbose=True"""
    if logger is None:
        logger = configuration.logger
    stack_bottom = False
    # NOTE: stack_idx = 0 is this 'stacktrace' function
    stack_idx = 1
    while not stack_bottom:
        try:
            caller = getframeinfo(stack()[stack_idx][0])
            msg = "%s:%d" \
                % (caller.filename, caller.lineno)
            if prefix:
                msg = "%s %s" % (prefix, msg)
            logger.debug(msg)
            if verbose:
                print_stderr(msg)
            stack_idx += 1
        except Exception:
            stack_bottom = True
