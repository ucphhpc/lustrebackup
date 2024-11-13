#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# __init__ - luste backup python extensions
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

"""This package provide luste backup using snapshots
This file is needed to tell python that this dir is a package
so that other modules can call, say, import lustrebackup.X.
Please refer to http://www.network-theory.co.uk/docs/pytut/tut_51.html
for details
"""

__dummy = True

# above line is only to make python tidy behave and not
# move module doc string inside header

# All sub modules to load in case of 'from X import *'

__all__ = []
	
# Collect all package information here for easy use from scripts and helpers

package_name = 'Lustre Backup Python extension'
short_name = 'lustrebackup'

# IMPORTANT: Please keep version in sync with doc-src/README.t2t

version_tuple = (0, 0, 1)
version_suffix = ''
version_string = '.'.join([str(i) for i in version_tuple]) + version_suffix
package_version = '%s %s' % (package_name, version_string)
project_team = 'The lustrebackup Project by the Science HPC Center at UCPH'
project_email = 'lustrebackup@erda.dk'
maintainer_team = 'The lustrebackup maintainers'
maintainer_email = 'lustrebackup@erda.dk'
project_url = 'https://github.com/ucphhpc/lustrebackup'
download_url = 'https://github.com/ucphhpc/lustrebackup/releases'
license_name = 'GNU GPL v2'
short_desc = \
    'Python backup extension for lustre'
long_desc = \
    """Python backup extension for for lustre:
Documentation: https://github.com/ucphhpc/lustrebackup
"""
project_class = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Topic :: Software Development :: Debuggers',
    ]
project_keywords = [
    'Python',
    'Python C extensions',
    'lustre',
    'rsync',
    ]

# Requirements

full_requires = []
versioned_requires = []
project_requires = []

# Optional packages required for additional functionality (for extras_require)

project_extras = {}
package_provides = short_name
project_platforms = ['All']
