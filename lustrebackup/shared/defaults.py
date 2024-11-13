#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# defaults - default constant values used in many locations
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


"""Default values for use in modules"""

bin_source_abort = "lustrebackup_source_abort"
bin_source_done = "lustrebackup_source_done"
bin_source_init = "lustrebackup_source_init"
bin_source_map = "lustrebackup_source_map"
bin_source_filediff = "lustrebackup_source_filediff"
bin_source_verify = "lustrebackup_source_verify"
bin_source_verify_init = "lustrebackup_source_verify_init"
bin_source_verify_list = "lustrebackup_source_verify_list"
bin_target_filediff = "lustrebackup_target_filediff"
bin_target_backup = "lustrebackup_target"
bin_mgs_snapshot_create = "lctl_snapshot_create.sh"
bin_mgs_snapshot_destroy = "lctl_snapshot_destroy.sh"
bin_mgs_snapshot_list = "lctl_snapshot_list.sh"
bin_mgs_snapshot_mount = "lctl_snapshot_mount.sh"
bin_mgs_snapshot_umount = "lctl_snapshot_umount.sh"
tmp_dirname = 'tmp'
last_backup_name = 'last_backup'
last_snapshot_name = 'last_snapshot'
last_changelog_name = 'last_changelog'
last_backupmap_name = 'last_backupmap'
last_verified_name = 'last_verified'
lock_dirname = 'locks'
inprogress_backupmap_name = 'inprogress_backupmap'
inprogress_backup_name = 'inprogress_backup'
inprogress_verify_name = 'inprogress_verify'
backup_verify_name = 'verify'
backup_verify_info_name = 'verify_info'
backup_verify_stats_name = 'verify_stats'
backup_renamed_name = 'renamed'
backup_modified_name = 'modified'
backupmeta_dirname = '.lustrebackup'
backupmap_dirname = 'backupmap'
backupmap_resolved_dirname = 'resolve'
backupmap_merged_dirname = 'merged'
changelog_dirname = 'changelog'
changelog_parsed_dirname = 'parsed'
changelog_filtered_dirname = 'filtered'
changelog_merged_dirname = 'merged'
snapshot_dirname = 'snapshot'
ldev_dirname = 'ldev'
ldev_conf = '/etc/ldev.conf'
backup_dirname = 'backup'
backupdata_dirname = 'backup'
backup_verify_dirname = 'verify'
date_format = '%d/%m/%Y-%H:%M:%S'
snapshot_date_format = '%Y%m%d_%H%M%S'
rsync_opts_modified = "--archive --one-file-system --protect-args --no-recursive --dirs --numeric-ids --inplace --no-blocking-io --no-whole-file"
rsync_opts_deleted = "--itemize-changes --one-file-system --protect-args --no-recursive --dirs --delete --existing --ignore-existing"
rsync_logformat_modified = '|:|checksum=%C|:|short=%n|:|long=%f|:|link=%L|:|perm=%B|:|uid=%U|:|gid=%G|:|size=%l|:|modified=%M|:|operation=%o'
