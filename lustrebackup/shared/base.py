#!/usr/bin/python3

# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# base - shared base helper functions
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

"""Base helper functions"""


from __future__ import print_function
from __future__ import absolute_import

import sys
import math
import zlib


def force_unicode(val):
    """Internal helper to decode unicode strings from utf8 bytes"""
    if not isinstance(val, bytes):
        return str(val)
    return val.decode()


def force_utf8(val):
    """Internal helper to force unicode strings to utf8 bytes"""
    if isinstance(val, bytes):
        return val
    return str(val).encode()


def force_utf8_rec(input_obj):
    """Recursive object conversion from unicode to utf8: useful to convert e.g.
    dictionaries with nested unicode strings to a pure utf8 version.
    """
    if isinstance(input_obj, dict):
        return {force_utf8_rec(i): force_utf8_rec(j) for (i, j) in
                input_obj.items()}
    elif isinstance(input_obj, list):
        return [force_utf8_rec(i) for i in input_obj]
    else:
        return force_utf8(input_obj)


def print_stderr(*args, **kwargs):
    """Print to stderr"""
    print(file=sys.stderr, *args, **kwargs)


def __hash(input_str):
    """Return hash of input_str"""
    return zlib.crc32(force_utf8(input_str))


def human_readable_filesize(filesize):
    """Return human readable filesize"""
    if filesize == 0:
        return "0 B"
    p = int(math.floor(math.log(filesize, 2)/10))
    return "%.3f %s" % (filesize/math.pow(1024, p),
                        ['B',
                         'KiB',
                         'MiB',
                         'GiB',
                         'TiB',
                         'PiB',
                         'EiB',
                         'ZiB',
                         'YiB'][p])
