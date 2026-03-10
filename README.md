# lustrebackup

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

Incremental backup system for [Lustre](https://www.lustre.org/) filesystems. It uses Lustre snapshots combined with Lustre changelogs to determine exactly which files changed since the last backup, then transfers only those files via rsync to a backup server — avoiding full filesystem scans. Developed by the Science HPC Center at the University of Copenhagen (UCPH).

## Prerequisites

- Linux with a Lustre filesystem that supports snapshots and changelogs
- [lustrebackup-mgs](https://github.com/ucphhpc/lustrebackup-mgs)
- Python 3
- GCC and build tools (for the `lustreapi` C extension)
- Lustre source tree checked out at `../lustre-release/` (for header files)
- `liblustreapi` development libraries
- Python packages: `xxhash`, `psutil`, `paramiko`, `scp`

## Lustre Setup (one-time, on MGS)

Changelogs must be registered on each MDT before use:

```bash
lctl --device fsname-MDT0000 changelog_register
lctl set_param -P mdd.FSNAME-MDT0000.changelog_mask="CREAT MKDIR HLINK SLINK MKNOD UNLNK RMDIR RENME RNMTO OPEN CLOSE LYOUT TRUNC SATTR XATTR HSM MTIME CTIME MIGRT FLRW RESYNC"
```

## Installation

```bash
pip install -e .
# or
python setup.py install
```

## SSH Setup

The target (backup server) connects to the source (Lustre cluster) over SSH. To restrict what the target can run, add the following to `~/.ssh/authorized_keys` on the **source host**, replacing `TARGET_HOST`, `TARGET_IP`, and `PUBLIC_KEY` accordingly:

```
from="TARGET_HOST,TARGET_IP",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/usr/local/bin/lustrebackup_ssh_command_validator.sh" PUBLIC_KEY
```

`lustrebackup_ssh_command_validator.sh` permits only the specific lustrebackup source commands, rsync, scp, and stat — all other commands are rejected.

## Configuration

All scripts default to `/etc/lustrebackup.conf` (override with `-c PATH`). The file uses INI format:

```ini
[GLOBAL]
logdir   = /var/log/lustrebackup
logfile  = lustrebackup.log
loglevel = info          # debug | info | warning | error

[LUSTRE]
fsname                  = myfs
nid                     = 10.0.0.1@tcp
mgs                     = mgs-host
mdt                     = myfs-MDT0000
changelog_user          = cl1
data_mount              = /mnt/lustre
data_path               = /mnt/lustre/data
meta_basepath           = /mnt/lustre/.lustrebackup
snapshot_home           = /mnt/snapshots
snapshot_create_retries = 10
snapshot_mount_opts     =
data_mount_opts         =
largefile_size          = 1073741824   # 1 GB (bytes)
hugefile_size           = 1099511627776  # 1 TB (bytes)

[SOURCE]
host = source-host
conf = /etc/lustrebackup.conf   # path on the source host

[BACKUP]
rsync_command   = /usr/bin/rsync
checksum_choice = xxh128

[SYSTEM]
nprocs             =    # defaults to CPU count
sys_memory_factor  = 0
user_memory_factor = 0
ssh_config         = /root/.ssh/config
```

## Usage

All commands accept `-h|--help`, `-v|--verbose`, and `-c PATH|--config=PATH`.

### Running a Backup

```bash
# 1. Create a Lustre snapshot on the source
lustrebackup_snapshot_create -c /etc/lustrebackup.conf

# 2. Create a backupmap on the source (from Lustre changelogs)
lustrebackup_source_map -c /etc/lustrebackup.conf
 
# 3. Run the backup (orchestrates source init, rsync, filediff, source done automatically)
lustrebackup_target -c /etc/lustrebackup.conf
```

### Snapshot Management

```bash
# Create a named snapshot with a description
lustrebackup_snapshot_create -n "my-snapshot" -d "pre-upgrade backup"

# List snapshots (use -r to refresh from MGS instead of cache)
lustrebackup_snapshot_list [-r]

# Mount / unmount a snapshot
lustrebackup_snapshot_mount  [-n NAME | -t TIMESTAMP]
lustrebackup_snapshot_umount [-n NAME | -t TIMESTAMP] [-f]   # -f to force

# Destroy a snapshot
lustrebackup_snapshot_destroy [-n NAME | -t TIMESTAMP]

# Clean up old snapshots with retention policy
lustrebackup_snapshot_cleanup \
  -a 7   \   # keep ALL snapshots for last 7 days
  -d 31  \   # keep 1 per day for 31 days
  -w 4   \   # keep 1 per week for 4 weeks
  -m 12  \   # keep 1 per month for 12 months
  -y 10  \   # keep 1 per year for 10 years
  -D         # dry run (no deletions)
```

### Verification

```bash
# Verify source snapshots
lustrebackup_source_verify [-r] [-s TIMESTAMP] [-e TIMESTAMP]

# Verify backup matches source
lustrebackup_target_verify [-r] [-s TIMESTAMP] [-e TIMESTAMP] [-t TIMESTAMP]
```

### Cron / Email Notifications

`lustrebackup.sh` is a wrapper that logs output and optionally sends email:

```bash
# Run via wrapper (logs to /var/log/<command>.<pid>.log)
lustrebackup.sh lustrebackup_target -c /etc/lustrebackup.conf
```

Set environment variables to enable email notifications:

| Variable | Purpose |
|---|---|
| `MAILFROM` | Sender address (required for any notification) |
| `MAILTO` | Recipient address (required for any notification) |
| `NOTIFY_SUCCESS` | If set, also send email on success (failures always notify) |

Example cron entry:

```cron
0 2 * * * MAILTO=admin@example.com MAILFROM=backup@example.com NOTIFY_SUCCESS=1 /usr/local/bin/lustrebackup.sh lustrebackup_target
```

## Architecture

lustrebackup follows a **two-side model**:

- **Source** (Lustre cluster node): Creates/mounts snapshots, reads changelogs, serves file data
- **Target** (backup server): Orchestrates the entire backup process via SSH

**Backup flow:**
1. Source creates a snapshot
2. Source builds a **backupmap** from Lustre changelogs — identifying exactly which files were created, modified, renamed, or deleted since the last backup (using multiprocessing for speed)
3. Target SSHes to source and runs `lustrebackup_source_init` → mounts snapshot, returns metadata as JSON
4. Target rsync-pulls modified files from the source's mounted snapshot; renames and deletes are handled separately
5. Target filediff-pulls (`lustrebackup_target_filediff`) modified files with size > **largefile_size**
4. Target SSHes to source to run `lustrebackup_source_done` (or `lustrebackup_source_abort` on failure)
5. Target creates its own snapshot of the completed backup

Backup state is persisted as pickles under `lustre_meta_basepath`, with symlinks (`last_backup`, `last_snapshot`, `last_backupmap`) pointing to the most recent completed run.

## License

GNU General Public License v2. See [LICENSE](LICENSE) for details.

Copyright (C) 2020-2026 The lustrebackup Project by the Science HPC Center at UCPH.
