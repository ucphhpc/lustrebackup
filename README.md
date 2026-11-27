# lustrebackup

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

Incremental backup system for [Lustre](https://www.lustre.org/) filesystems. It uses Lustre snapshots combined with Lustre changelogs to determine exactly which files changed since the last backup, then transfers only those files to a backup server — avoiding full filesystem scans. Small files are transferred with rsync. Large files are updated in place with a filediff: either by comparing block checksums of the two copies (checksum filediff), or by sending only the blocks that ZFS records as written since the last backup ([ZFS filediff](#zfs-filediff)). Developed by the Science HPC Center at the University of Copenhagen (UCPH).

## Prerequisites

- Linux with a Lustre filesystem that supports snapshots and changelogs (Lustre snapshots require ZFS-backed targets)
- [lustrebackup-mgs](https://github.com/ucphhpc/lustrebackup-mgs) on the MGS and MDS nodes
- Python 3
- GCC and build tools (for the `lustreapi` C extension)
- Lustre source tree checked out at `../lustre-release/` (for header files)
- `liblustreapi` development libraries
- Python packages: `xxhash`, `psutil`, `paramiko`, `scp`, `PyYAML`
- For the ZFS filediff: Lustre 2.15 or older, and root SSH from every MDS node to every OSS (see [ZFS filediff](#zfs-filediff))

## Lustre Setup (one-time)

Register a changelog user for the MDT on the MDS that serves it, and set the changelog mask from the MGS:

```bash
# On the MDS: prints the changelog user id (eg. cl1) to use as [LUSTRE] changelog_user
lctl --device myfs-MDT0000 changelog_register

# On the MGS
lctl set_param -P mdd.myfs-MDT0000.changelog_mask="CREAT MKDIR HLINK SLINK MKNOD UNLNK RMDIR RENME RNMTO OPEN CLOSE LYOUT TRUNC SATTR XATTR HSM MTIME CTIME MIGRT FLRW RESYNC"
```

## Installation

On the source and target hosts:

```bash
pip install -e .
# or
python setup.py install
```

On the MGS nodes of the source and target filesystems, and on the MDS nodes of the source filesystem, including failover partners, install the scripts from [lustrebackup-mgs](https://github.com/ucphhpc/lustrebackup-mgs):

```bash
cp lib/lustre_snapshot_ldev_init.sh /usr/local/lib/
cp sbin/*.sh /usr/local/sbin/
```

The snapshot scripts load the library from `/usr/local/lib`. lustrebackup runs the scripts by name, so keep them in a directory on root's `PATH`, such as `/usr/local/sbin`.

| Script | Runs on | Used for |
|---|---|---|
| `lctl_snapshot_create.sh`, `lctl_snapshot_list.sh`, `lctl_snapshot_mount.sh`, `lctl_snapshot_umount.sh`, `lctl_snapshot_destroy.sh` | MGS | Lustre snapshots |
| `lustre_osp.sh` | MDS | ZFS filediff: finds the active MDS and checks the OST connections |
| `lustre_obj2zfs.sh` | MDS | ZFS filediff: finds an OST object's OSS, ZFS dataset and object number |
| `lustre_zfs_snapshot_blocks.sh` | MDS | ZFS filediff: lists an object's blocks in a snapshot |
| `lustre_ssh_command_validator.sh` | MGS and MDS | Forced SSH command that only allows these scripts and the MGS status check |

## SSH Setup

**Target to source.** The target (backup server) connects to the source (Lustre cluster) over SSH. To restrict what the target can run, add the following to `~/.ssh/authorized_keys` on the **source host**, replacing `TARGET_HOST`, `TARGET_IP`, and `PUBLIC_KEY` accordingly:

```
from="TARGET_HOST,TARGET_IP",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/usr/local/bin/lustrebackup_ssh_command_validator.sh" PUBLIC_KEY
```

`lustrebackup_ssh_command_validator.sh` permits only the specific lustrebackup source commands, rsync, scp, and stat — all other commands are rejected.

**To the MGS and MDS.** The source and the target manage the snapshots of their filesystem by running the lustrebackup-mgs scripts on its MGS, and the source runs the MDS scripts for the ZFS filediff. Restrict these keys in root's `~/.ssh/authorized_keys` on every MGS and MDS node, replacing `HOST`, `HOST_IP`, and `PUBLIC_KEY` with those of the connecting source or target host:

```
from="HOST,HOST_IP",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/usr/local/sbin/lustre_ssh_command_validator.sh" PUBLIC_KEY
```

**MDS to OSS (ZFS filediff only).** `lustre_obj2zfs.sh` and `lustre_zfs_snapshot_blocks.sh` run `lctl`, `zfs` and `zdb` on the OSS that serves each OST, over plain `ssh` to the IP address of the OST's current Lustre NID (for `o2ib`, the IPoIB address). Every MDS node of the source filesystem needs passwordless root SSH to every OSS, including failover partners, on those addresses, with their host keys in root's `known_hosts`.

**SSH config.** Each host lustrebackup connects to needs a `Host` entry with exactly that name in the file that `[SYSTEM] ssh_config` points to: `[SOURCE] host` on the target, and the `[LUSTRE] mgs` and `mds` hosts. Wildcard entries such as `Host mds*` don't count. lustrebackup passes the entry's `Port`, `IdentityFile`, `Ciphers` and `Control*` settings to ssh.

## Configuration

All scripts default to `/etc/lustrebackup.conf` (override with `-c PATH`). The file uses INI format. Comments must be on their own lines: an inline `# ...` is read as part of the value.

```ini
[GLOBAL]
logdir   = /var/log/lustrebackup
logfile  = lustrebackup.log
# debug | info | warning | error
loglevel = info

[LUSTRE]
fsname                  = myfs
# MGS NID, used to mount snapshots
nid                     = 10.0.0.1@tcp
# MDT name without the fsname
mdt                     = MDT0000
# Hosts in [SYSTEM] ssh_config, failover pairs separated by ':' (eg. mds1:mds2)
mgs                     = mgs-host
mds                     = mds-host
changelog_user          = cl1
data_mount              = /mnt/lustre
data_path               = /mnt/lustre/data
meta_basepath           = /mnt/lustre/.lustrebackup
snapshot_home           = /mnt/snapshots
snapshot_create_retries = 10
# Snapshots are named <snapshot_name>-<timestamp>
snapshot_name           = lustrebackup
snapshot_mount_opts     =
data_mount_opts         =
# Files of at least this size (1 GiB) are transferred with the filediff
largefile_size          = 1073741824
# True: ZFS filediff, False: checksum filediff
zfs_filediff            = True

[SOURCE]
host = source-host
# Path of the config file on the source host
conf = /etc/lustrebackup.conf

[BACKUP]
rsync_command   = /usr/bin/rsync
checksum_choice = xxh128

[SYSTEM]
# Defaults to the number of CPUs
nprocs             =
sys_memory_factor  = 0
user_memory_factor = 0
ssh_config         = /root/.ssh/config
```

`zfs_filediff` must be exactly `True` to enable the ZFS filediff; any other value selects the checksum filediff.

## Upgrading

From versions without the ZFS filediff:

- Add `mds`, `zfs_filediff` and `snapshot_name` to `[LUSTRE]`. Without them the configuration fails to load with "Failed to parse configuration". `zfs_filediff = False` keeps the checksum filediff.
- `hugefile_size` is no longer used and can be removed.
- New snapshots are named `<snapshot_name>-<timestamp>` instead of `<fsname>-backup-<timestamp>`. Snapshots made by older versions are still recognized, and `snapshot_name = <fsname>-backup` keeps the old names.
- Install the current lustrebackup-mgs scripts on the MGS and MDS nodes, and point the forced command in their `authorized_keys` to `lustre_ssh_command_validator.sh`, which replaces `lctl_ssh_command_validator.sh`.

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

### Aborting a Backup

```bash
# On the target: stops a running or failed backup
lustrebackup_target_abort -c /etc/lustrebackup.conf
```

It kills the running `lustrebackup_target` and its rsync and filediff processes, runs `lustrebackup_source_abort` on the source and removes the in-progress marker.

### Snapshot Management

```bash
# Create a named snapshot with a description
lustrebackup_snapshot_create -n "my-snapshot" -d "pre-upgrade backup"

# List snapshots (use -r to refresh from MGS instead of cache)
lustrebackup_snapshot_list [-r]

# Mount / unmount snapshots by timestamp
lustrebackup_snapshot_mount  [-p POSTFIX] TIMESTAMP [TIMESTAMP ...]
lustrebackup_snapshot_umount [-p POSTFIX] TIMESTAMP [TIMESTAMP ...]

# Destroy a snapshot
lustrebackup_snapshot_destroy [-n NAME | -t TIMESTAMP]

# Clean up old snapshots: keep all snapshots from the last 7 days,
# and 31 daily, 4 weekly, 12 monthly and 10 yearly snapshots (-D: dry run)
lustrebackup_snapshot_cleanup -a 7 -d 31 -w 4 -m 12 -y 10 -D
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
# Run via wrapper (output is collected in /var/log/<command>.<pid>.log,
# mailed if enabled, and removed)
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
4. Target rsync-pulls modified files smaller than **largefile_size** from the source's mounted snapshot; renames and deletes are handled separately
5. Target updates modified files of at least **largefile_size** with the filediff: `lustrebackup_target_filediff_zfs` when `zfs_filediff = True`, otherwise `lustrebackup_target_filediff`
6. Target creates its own snapshot of the completed backup
7. Target SSHes to source to run `lustrebackup_source_done`

Backup state is persisted as pickles under `lustre_meta_basepath`, with symlinks (`last_backup`, `last_snapshot`, `last_backupmap`) pointing to the most recent completed run.

## ZFS filediff

With `zfs_filediff = True`, large files are updated without reading them in full. For each file:

1. `lustrebackup_target_filediff_zfs` runs `lustrebackup_source_filediff_zfs` on the source over SSH.
2. The source reads the file's layout with `lfs getstripe --yaml` and asks the MDS (`lustre_obj2zfs.sh`) for the OSS, ZFS dataset and object number of each OST object. The result is cached in `fid2zfs/<fid>.pck` under `meta_basepath` on the source. It's resolved again when the layout changes, or when the OST is served from a different NID, for example after an OSS failover.
3. For each object, `lustre_zfs_snapshot_blocks.sh` lists its blocks in the current snapshot. Blocks written after the last backup's snapshot, and holes made since, are found by their ZFS birth time and mapped back to file offsets through the stripe layout.
4. The source sends only those ranges. The target writes them into its copy, sets it to the source's size and copies the file's attributes with rsync (`--size-only`, so no data is sent).

For each transfer, the target keeps `filediff_zfs.*.transfer.json` and `.pck` (transfer metadata), `.transfer.attr` (attribute rsync log) and `.transfer.remote.stderr` (the source's error output) under `meta_basepath/backup/<source snapshot timestamp>/`.

**Requirements**

- Lustre 2.15 or older. Lustre 2.16 changed the `lfs getstripe --yaml` format for composite layouts and allocates new OST objects in normal FID sequences, which `lustre_obj2zfs.sh` doesn't resolve. Use `zfs_filediff = False` on Lustre 2.16 and later.
- The lustrebackup-mgs MDS scripts on every MDS node, and root SSH from every MDS node to every OSS (see [SSH Setup](#ssh-setup)).

**Limitations**

These files make their transfer, and so the backup run, fail with an error. Use `zfs_filediff = False` if the filesystem has them:

- Mirrored (FLR) files
- Composite (PFL) layouts in the Lustre 2.16+ format
- Files with OST objects in normal FID sequences (new objects on Lustre 2.16+)
- Files with objects on an OST that is deactivated on the MDS (its OSP `active` parameter is 0)

These changes are not detected:

- Data-on-MDT components aren't diffed, so changes in the DoM part of a large file are missed. Only use DoM in layouts of files that stay below `largefile_size`.
- Holes without a recorded birth time, for example made before the pool's `hole_birth` feature was active, are treated as unchanged.
- The target's copy must match the last backup outside the changed ranges.

## License

GNU General Public License v2. See [LICENSE](LICENSE) for details.

Copyright (C) 2020-2026 The lustrebackup Project by the Science HPC Center at UCPH.
