#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# setup.py - Setup for Python luste backup
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
from setuptools import setup, Extension

from lustrebackup import version_string, short_name, project_team, \
    project_email, short_desc, long_desc, project_url, download_url, \
    license_name, project_class, project_keywords, versioned_requires, \
    project_requires, project_extras, project_platforms, maintainer_team, \
    maintainer_email

setup(
    name=short_name,
    version=version_string,
    description=short_desc,
    long_description=long_desc,
    author=project_team,
    author_email=project_email,
    maintainer=maintainer_team,
    maintainer_email=maintainer_email,
    url=project_url,
    download_url=download_url,
    license=license_name,
    classifiers=project_class,
    keywords=project_keywords,
    platforms=project_platforms,
    install_requires=versioned_requires,
    requires=project_requires,
    extras_require=project_extras,
    scripts=['bin/lustrebackup.sh',
             'bin/lustrebackup_snapshot_cleanup',
             'bin/lustrebackup_snapshot_create',
             'bin/lustrebackup_snapshot_destroy',
             'bin/lustrebackup_snapshot_list',
             'bin/lustrebackup_snapshot_mount',
             'bin/lustrebackup_snapshot_umount',
             'bin/lustrebackup_source_init',
             'bin/lustrebackup_source_abort',
             'bin/lustrebackup_source_done',
             'bin/lustrebackup_source_filediff',
             'bin/lustrebackup_source_verify',
             'bin/lustrebackup_source_verify_init',
             'bin/lustrebackup_source_verify_list',
             'bin/lustrebackup_source_map',
             'bin/lustrebackup_ssh_command_validator.sh',
             'bin/lustrebackup_target',
             'bin/lustrebackup_target_abort',
             'bin/lustrebackup_target_filediff',
             'bin/lustrebackup_target_verify',
             ],
    packages=['lustrebackup',
              'lustrebackup.shared',
              'lustrebackup.snapshot',
              'lustrebackup.backupmap',
              'lustrebackup.backup',
              'lustrebackup.verify'],
    package_dir={'lustrebackup': 'lustrebackup',
                 'lustrebackup.shared': 'lustrebackup/shared',
                 'lustrebackup.snapshot': 'lustrebackup/snapshot',
                 'lustrebackup.backupmap': 'lustrebackup/backupmap',
                 'lustrebackup.backup': 'lustrebackup/backup',
                 'lustrebackup.verify': 'lustrebackup/verify',
                 },
    ext_modules=[
        Extension('lustrebackup.shared.lustre',
                  include_dirs=['/usr/include',
                                '/usr/include/python3',
                                '../lustre-release/libcfs/include',
                                '../lustre-release/lustre/include',
                                '../lustre-release/lustre/include/lustre',
                                '../lustre-release/lustre/include/uapi',
                                '../lustre-release/lnet/include/uapi',
                                '../lustre-release/libcfs/include/uapi',
                                ],
                  library_dirs=['/usr/lib64'],
                  libraries=['lustreapi'],
                  sources=['lustrebackup/shared/lustre.c'],
                  define_macros=[('_DEBUG', 0)],
                  ),
    ]
)
