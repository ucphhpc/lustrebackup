#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# fileio - lustre backup helpers
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

"""File IO operations"""

from __future__ import print_function
from __future__ import absolute_import

import os
import errno
import fcntl
import shutil
import tempfile
import time

from lustrebackup.shared.base import force_utf8, force_utf8_rec, \
    force_unicode
from lustrebackup.shared.serial import dump, load


def acquire_file_lock(configuration,
                      lock_path,
                      exclusive=True,
                      blocking=True,
                      logger=None):
    """Uses fcntl to acquire the lock in lock_path in exclusive and blocking
    mode unless requested otherwise.
    Should be used on separate lock files and not on the file that is
    meant to be synchronized itself.
    Returns the lock handle used to unlock the file again. We recommend
    explicitly calling release_file_lock when done, but technically it should
    be enough to delete all references to the handle and let garbage
    collection automatically unlock and close it.
    Returns None if blocking is disabled and the lock could not be readily
    acquired.
    """
    if logger is None:
        logger = configuration.logger
    if exclusive:
        lock_mode = fcntl.LOCK_EX
    else:
        lock_mode = fcntl.LOCK_SH
    if not blocking:
        lock_mode |= fcntl.LOCK_NB
    # NOTE: Some system+python combinations require 'w+' here
    #       to allow both SH and EX locking
    lock_handle = open(lock_path, "w+")
    try:
        fcntl.flock(lock_handle.fileno(), lock_mode)
    except IOError as ioe:
        # Clean up
        try:
            lock_handle.close()
        except Exception:
            pass
        # If non-blocking flock gave up an IOError will be raised and the
        # exception will have an errno attribute set to EACCES or EAGAIN.
        # All other exceptions should be re-raised for caller to handle.
        if not blocking and ioe.errno in (errno.EACCES, errno.EAGAIN):
            lock_handle = None
        else:
            raise ioe

    return lock_handle


def release_file_lock(configuration,
                      lock_handle,
                      close=True,
                      logger=None):
    """Uses fcntl to release the lock held in lock_handle. We generally lock a
    separate lock file when we wish to modify a shared file in line with the
    acquire_file_lock notes, so this release helper by default includes closing
    of the lock_handle file object.
    """
    if logger is None:
        logger = configuration.logger
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    if close:
        try:
            lock_handle.close()
        except Exception as err:
            logger.error("could release lock, error: %s" % err)
            return False

    return True


def makedirs_rec(configuration,
                 dir_path,
                 accept_existing=True,
                 logger=None):
    """Make sure dir_path is created if it doesn't already exist. The optional
    accept_existing argument can be used to turn off the default behaviour of
    ignoring if dir_path already exists.
    """
    if logger is None:
        logger = configuration.logger
    try:
        if os.path.exists(dir_path) and not os.path.isdir(dir_path):
            logger.error("Non-directory in the way: %s" % dir_path)
            return False
        os.makedirs(dir_path)
    except OSError as err:
        if not accept_existing or err.errno != errno.EEXIST:
            logger.error("Could not makedirs_rec %s: %s" % (dir_path, err))
            return False
    return True


def touch(configuration,
          filepath,
          timestamp=None,
          logger=None):
    """Create or update timestamp for filepath"""
    if logger is None:
        logger = configuration.logger
    try:
        makedirs_rec(configuration,
                     os.path.dirname(filepath))
        if not os.path.exists(filepath):
            open(filepath, 'w').close()
        elif timestamp is None:
            timestamp = time.time()
        if timestamp is not None:
            # set timestamp to supplied value
            os.utime(filepath, (timestamp, timestamp))
    except Exception as err:
        logger.error("could not touch file: %r" % filepath
                     + ": %s" % err)
        return False

    return True


def truncate(configuration,
             filepath,
             filesize=0,
             logger=None):
    """Truncate filepath, create if it if needed"""
    if logger is None:
        logger = configuration.logger
    try:
        if not os.path.exists(filepath):
            open(filepath, 'w').close()
        os.truncate(filepath, filesize)
    except Exception as err:
        logger.error("could not truncate file: %r to size: %d"
                     % (filepath, filesize)
                     + ", err: %s" % err)
        return False

    return True


def delete_file(configuration,
                path,
                allow_broken_symlink=False,
                allow_missing=False,
                logger=None):
    """Wrapper to handle deletion of path. The optional allow_broken_symlink is
    used to accept delete even if path is a broken symlink.
    """
    if logger is None:
        logger = configuration.logger
    logger.debug('deleting file: %s' % path)
    if os.path.exists(path) or allow_broken_symlink and os.path.islink(path):
        try:
            os.remove(path)
            result = True
        except Exception as err:
            logger.error('could not delete %s %s' % (path, err))
            result = False
    elif allow_missing:
        result = True
    else:
        logger.info('delete_file: %s does not exist.' % path)
        result = False

    return result


def move(configuration, src, dst, logger=None):
    """Move a file/dir to dst where dst must be a new file/dir path and the
    parent dir is created if necessary. The recursive flag is used to enable
    recursion.
    """
    if logger is None:
        logger = configuration.logger
    status = True
    dst_dir = os.path.dirname(dst)
    makedirs_rec(configuration, dst_dir)
    try:
        # Always use the same recursive move
        shutil.move(src, dst)
    except Exception as err:
        status = False
        logger.error("Could not move: %r -> %r, err: %s" %
                     (src, dst, err))
        return (False, "move failed: %s" % err)

    return status


def remove_dir(configuration, path, recursive=False, logger=None):
    """
    Remove the given dir_path, if it's empty
    Returns Boolean to indicate success, writes messages to log.
    """
    if logger is None:
        logger = configuration.logger
    try:
        if recursive:
            shutil.rmtree(path)
        else:
            os.rmdir(path)
    except Exception as err:
        logger.error("Could not remove_dir %s: %s" %
                     (path, err))
        return False

    return True


def make_symlink(configuration,
                 src,
                 dest,
                 working_dir=None,
                 force=False,
                 logger=None):
    """Wrapper to make src a symlink to dest path"""
    if logger is None:
        logger = configuration.logger
    current_dir = None

    try:
        logger.debug('creating symlink (%s): %s -> %s'
                     % (working_dir, src, dest))
        if working_dir:
            current_dir = os.getcwd()
            os.chdir(working_dir)
        # NOTE: we use islink instead of exists here to handle broken symlinks
        if os.path.islink(dest) and force \
                and delete_symlink(configuration, dest):
            logger.debug('deleted existing symlink (%s): %s -> %s'
                         % (working_dir, src, dest))
        os.symlink(src, dest)
        if current_dir:
            os.chdir(current_dir)
    except Exception as err:
        if current_dir:
            try:
                os.chdir(current_dir)
            except Exception as err2:
                logger.error('Could change working dir: %s' % err2)
        logger.error('Could not create symlink %s' % err)
        return False
    return True


def delete_symlink(configuration,
                   path,
                   allow_broken_symlink=True,
                   allow_missing=False,
                   logger=None):
    """Wrapper to handle deletion of symlinks"""
    if logger is None:
        logger = configuration.logger
    logger.debug('deleting symlinks: %s' % path)
    return delete_file(configuration,
                       path,
                       allow_broken_symlink,
                       allow_missing)


def unpickle(configuration,
             path,
             allow_missing=False,
             logger=None):
    """Unpack pickled object in path"""
    if logger is None:
        logger = configuration.logger
    try:
        data_object = load(path)
        logger.debug('%s was unpickled successfully' % path)
        return data_object
    except Exception as err:
        # NOTE: check that it was in fact due to file does not exist error
        if not allow_missing or getattr(err, 'errno', None) != errno.ENOENT:
            logger.error('%s could not be opened/unpickled! %s'
                         % (path, err))
        return None


def pickle(configuration, data_object, path, logger=None):
    """Pack data_object as pickled object in path"""
    if logger is None:
        logger = configuration.logger
    try:
        dump(data_object, path)
        logger.debug('pickle success: %s' % path)
        return True
    except Exception as err:
        logger.error('could not pickle: %s, error: %s'
                     % (path, err))
        return False


def first_and_last_line(configuration, path, logger=None):
    """Read first and list line of file in path to extract recno"""
    if logger is None:
        logger = configuration.logger
    try:
        with open(path, "rb") as fh:
            firstline = fh.readline()     # Read and store the first line.
            for lastline in fh:
                pass      # Read all lines, keep final value.

    except Exception as err:
        logger.error("could not extract first and last line"
                     + " from file: %r, error: %s" % (path, err))
        return (None, None)

    return (firstline, lastline)


def load_json(configuration, path,
              allow_missing=False,
              convert_utf8=True,
              logger=None):
    """Unpack json object in path"""
    if logger is None:
        logger = configuration.logger
    try:
        data_object = load(path, serializer='json', mode='r')
        logger.debug("%r was loaded successfully into type: %s"
                     % (path, type(data_object)))
        if convert_utf8:
            data_object = force_utf8_rec(data_object)
        return data_object
    except Exception as err:
        # NOTE: check that it was in fact due to file does not exist error
        if not allow_missing or getattr(err, 'errno', None) != errno.ENOENT:
            logger.error("%s could not be opened/loaded! %s"
                         % (path, err))
        return None


def save_json(configuration, data_object, path, logger=None):
    """Save data_object as json"""
    if logger is None:
        logger = configuration.logger
    try:
        dump(data_object, path, serializer='json', mode='w')
        logger.debug("json save success: %s" % path)
        return True
    except Exception as err:
        logger.error("could not save json: %s, error: %s"
                     % (path, err))
        return False


def path_join(configuration, *args, convert_utf8=True, logger=None):
    """Convert paths in args to UTF-8 bytes return as joined"""
    if logger is None:
        logger = configuration.logger
    try:
        if convert_utf8:
            paths = [force_utf8(path)
                     for path in args]
        else:
            paths = [force_unicode(path)
                     for path in args]
        return os.path.join(*paths)

    except Exception as err:
        logger.error("could not join_path, error: %s"
                     % err)
        return None


def copy(configuration, src, dst, logger=None):
    """Copy a file from src to dst where dst may be a directory"""
    if logger is None:
        logger = configuration.logger
    return shutil.copy(src, dst)


def copyattr(configuration, src, dst, logger=None):
    """Copy file attr and xattr from src to dest including user and group"""
    if logger is None:
        logger = configuration.logger
    try:
        # Copy attr and xattr

        shutil.copystat(src, dst)

        # Copy owner and group (not part of copystat)

        src_stat = os.stat(src)
        shutil.chown(dst,
                     user=src_stat.st_uid,
                     group=src_stat.st_gid)

    except Exception as err:
        logger.error("could not copyattr from %r to %r: %s"
                     % (src, dst, err))
        return False

    return True


def make_temp_file(suffix='', prefix='tmp', dir=None, text=False):
    """Expose tempfile.mkstemp functionality"""
    return tempfile.mkstemp(suffix, prefix, dir, text)
