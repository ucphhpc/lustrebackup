#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# --- BEGIN_HEADER ---
#
# logger - logging helpers
# Copyright (C) 2020-2024  The lustrebackup Project by the Science HPC Center at UCPH
#
# This file is part of lustrebackup.
#
# Python lustre backup is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Python lustre backup is distributed in the hope that it will be useful,
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

"""Logging helpers"""

import logging
import os
import signal
import syslog

_default_level = "info"
_default_format = "%(asctime)s %(levelname)s %(message)s"
_debug_format = "%(asctime)s %(module)s:%(funcName)s:%(lineno)s %(levelname)s %(message)s"
__hangup_helpers = {}


def _name_to_level(name):
    """Translate log level name to internal logging value"""
    levels = {"debug": logging.DEBUG, "info": logging.INFO,
              "warning": logging.WARNING, "error": logging.ERROR,
              "critical": logging.CRITICAL}
    name = name.lower()
    if name not in levels:
        print('Unknown logging level %s, using %s!' % (name, _default_level))
        name = _default_level
    return levels[name]


def _name_to_format(name):
    formats = {"debug": _debug_format, "info": _default_format,
               "warning": _default_format, "error": _default_format,
               "critical": _default_format}
    name = name.lower()
    if name not in formats:
        print('Unknown logging format %s, using %s!' % (name, _default_format))
        name = _default_format
    return formats[name]


class SysLogLibHandler(logging.Handler):
    """A logging handler that emits messages to syslog.syslog."""

    # Dummy attribute to avoid isinstance(X, SysLogLibHandler)
    # import confusion: https://bugs.python.org/issue1249615
    # USE: hasattr(X, "shared_logger_sysloglibhandler")
    # instead of isinstance(X, SysLogLibHandler)
    shared_logger_sysloglibhandler = True

    def __init__(self, facility, logident='logger'):
        try:
            syslog.openlog(
                ident=logident, logoption=syslog.LOG_PID, facility=facility)
        except Exception as err:
            raise Exception(err)
        logging.Handler.__init__(self)

    def emit(self, record):
        syslog.syslog(self.format(record))


class Logger:
    """lustrebackup code should use an instance of this class to handle
    writing to log-files.
    """
    logger = None
    logginglevel = None
    logfile = None
    syslog = None
    loggingformat = None

    def __init__(self,
                 level,
                 logformat=None,
                 logfile=None,
                 syslog=None,
                 app='lustrebackup_main_logger'):
        self.logfile = logfile
        self.syslog = syslog
        self.app = app
        self.logger = logging.getLogger(app)

        # Repeated import of Configuration in cgi's would cause echo
        # in log files if a second handler is added to the existing
        # logger!

        self.logginglevel = _name_to_level(level)
        if logformat is None:
            self.loggingformat = _name_to_format(level)
        else:
            self.loggingformat = logformat

        self.init_handler()
        self.logger.setLevel(self.logginglevel)

        # Make sure root logger does not filter us

        logging.getLogger().setLevel(self.logginglevel)

    def init_handler(self):
        """Init handler"""

        reload_handlers = False
        if self.logger.handlers:
            cur_handler = self.logger.handlers[0]
            handler_count = len(self.logger.handlers)
            if handler_count > 1:
                self.logger.warning("Too many logger handlers: %d"
                                    % handler_count)
                reload_handlers = True
            elif self.logfile and not isinstance(
                    cur_handler, logging.FileHandler):
                reload_handlers = True
            elif self.syslog and not hasattr(
                    cur_handler, "shared_logger_sysloglibhandler"):
                reload_handlers = True
        if self.logger.handlers and not reload_handlers:
            return
        elif reload_handlers:
            self.logger.debug("Hanging up, logger handlers"
                              + " expired logger handlers: %s"
                              % self.logger.handlers)
            self.hangup()

        if self.logfile:
            # Add file handler
            handler = logging.FileHandler(self.logfile)
        elif self.syslog:
            # Add syslog lib handler
            handler = SysLogLibHandler(self.syslog, logident=self.app)
        else:
            # Add null handler to simply throw away all log messages
            handler = logging.NullHandler()

        formatter = logging.Formatter(self.loggingformat)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def hangup(self):
        """Remove handler"""

        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)

    def loglevel(self):
        """Return active log level"""
        return logging.getLevelName(self.logginglevel)

    def reopen(self):
        """Force reopening of any associated handlers.
        There's no method to re-open the handler, but the next call to
        emit() will automatically re-open the handler if it isn't already open:
        https://groups.google.com/forum/#!topic/comp.lang.python/h6-h95PiPTU
        """

        # Close handlers

        for handler in self.logger.handlers:
            handler.close()

        # Close root handlers

        for handler in logging.getLogger().handlers:
            handler.close()

    def shutdown(self):
        """Flush all open files and disable logging to prepare for a
        clean shutdown.
        """

        logging.shutdown()


def reopen_log(conf):
    """A helper to force reopening of any associated log FileHandlers like:
    https://groups.google.com/forum/#!topic/comp.lang.python/h6-h95PiPTU
    Particularly useful to avoid full restart after log rotation.
    """
    logger = conf.logger
    for handler in logger.handlers:
        handler.close()

    gdp_logger = conf.gdp_logger
    for handler in gdp_logger.handlers:
        handler.close()

    auth_logger = conf.auth_logger
    for handler in auth_logger.handlers:
        handler.close()


def hangup_handler(signal, frame):
    """A simple signal handler to force log reopening on SIGHUP"""
    pid = os.getpid()
    configuration = __hangup_helpers['configuration']
    logger = configuration.logger
    logger.info('(%s) reopening log in reaction to hangup signal' % pid)
    reopen_log(configuration)
    logger.info('(%s) reopened log after hangup signal' % pid)


def register_hangup_handler(conf):
    """Register a HUP signal handler to reopen log based on provided
    configuration object.
    NOTE: We need to keep configuration object around for signal handler to
    use without explicit args.
    """
    # Allow e.g. logrotate to force log re-open after rotates
    __hangup_helpers['configuration'] = conf
    signal.signal(signal.SIGHUP, hangup_handler)


# TODO: Add unit test
# if __name__ == "__main__":
