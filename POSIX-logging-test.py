import logging
import logging.handlers
import time
import syslog

logger = logging.getLogger("sc-perth_log-test")

# Changed from file_fmt to be more clear
logfile_fmt = "%(processName)s[%(process)s]: %(levelname)s:%(name)s:%(message)s"
fallback_logfile_fmt = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
# Changed from logfile to reflect change to syslog
fallback_logfile = "letsencrypt.log"

def setup_log_file_handler(config, logfile, fmt):
    """Setup file debug logging.
    Used as fallaback if setup_syslog_handler() encounters issues"""
    log_file_path = os.path.join(config.logs_dir, logfile)
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_file_path, maxBytes=2 ** 20, backupCount=1000)
    except IOError as error:
        raise errors.Error(_PERM_ERR_FMT.format(error))
    # rotate on each invocation, rollover only possible when maxBytes
    # is nonzero and backupCount is nonzero, so we set maxBytes as big
    # as possible not to overrun in single CLI invocation (1MB).
    handler.doRollover()  # TODO: creates empty letsencrypt.log.1 file
    handler.setLevel(logging.DEBUG)
    handler_formatter = logging.Formatter(fmt=fmt)
    handler_formatter.converter = time.gmtime  # don't use localtime
    handler.setFormatter(handler_formatter)
    return handler, log_file_path

def find_facility(facility):
    '''
    "Derived" from:
    https://github.com/openstack/oslo.log/blob/7d1ef90316d4907ccbb3654f7f3628fba4526bce/oslo_log/log.py
    Credit to the OpenStack Foundation & the United States Government as represented by the
    Administrator of the National Aeronautics and Space Administration.

    This function is/was licensed under the Apache License, Version 2.0 (the "License"); you may
    not use this function exept in compliance with the License. You may obtain a copy of the
    License at: http://www.apache.org/licenses/LICENSE-2.0

    # NOTE(jd): Check the validity of facilities at run time as they differ
    # depending on the OS and Python version being used.
    '''
    valid_facilities = [f for f in
                        ["LOG_KERN",   "LOG_USER",     "LOG_MAIL",
                         "LOG_DAEMON", "LOG_AUTH",     "LOG_SYSLOG",
                         "LOG_LPR",    "LOG_NEWS",     "LOG_UUCP",
                         "LOG_CRON",   "LOG_AUTHPRIV", "LOG_FTP",
                         "LOG_LOCAL0", "LOG_LOCAL1",   "LOG_LOCAL2",
                         "LOG_LOCAL3", "LOG_LOCAL4",   "LOG_LOCAL5",
                         "LOG_LOCAL6", "LOG_LOCAL7"]
                        if getattr(syslog, f, None)]
    facility = facility.upper()
    if not facility.startswith("LOG_"):
        facility = "LOG_" + facility
    if facility not in valid_facilities:
        return -1
    return getattr(syslog, facility)

def setup_syslog_handler(facility, fmt):
    """ Configure a handler for using syslog, or fallback to
    the previous manual logging technique.
    Returns: handler, log_file_path
    log_file_path will be None if we were successful setting up SysLogHandler
    """
    # Check provided facility is valid, otherwise fall back to user
    if find_facility(facility) == -1:
        facility = "user"

    handler = None            # So we can check for success
    # handlerPaths = Linux/BSD interface, MAC OSX interface
    handlerPaths = ['/dev/log', '/var/run/syslog']
    for path in handlerPaths:
        try:
            handler = logging.handlers.SysLogHandler(path, facility)
        except IOError as e:
            if e.errno == 2:  # No such file, try the next one
                continue
            else:             # Unexpected exception, fallback to manual logging
                return setup_log_file_handler(
                    config, fallback_logfile, fallback_logfile_fmt)
        else:
            break

    if handler is not None:   # Don't assume we were successful, validate!
        #handler.setLevel(logging.DEBUG) # Appears to be pointless...
        handler_formatter = logging.Formatter(fmt=fmt)
        handler_formatter.converter = time.gmtime
        handler.setFormatter(handler_formatter)
        return handler, None
    else:                     # We didn't find the syslog interface, fallback
        return setup_log_file_handler(
            config, fallback_logfile, fallback_logfile_fmt)

#logger.setLevel(logging.ERROR)

target_facilities = ["kern",   "user",     "mail",
                     "daemon", "auth",     "syslog",
                     "lpr",    "news",     "uucp",
                     "cron",   "authpriv", "ftp",
                     "local0", "local1",   "local2",
                     "local3", "local4",   "local5",
                     "local6", "local7"]

for target_facility in target_facilities:
    print target_facility
    handler, log_file_path = setup_syslog_handler(target_facility, logfile_fmt)
    logger.addHandler(handler)
    logger.debug(target_facility + " debug test")
    time.sleep(1)
    logger.info(target_facility + " info test")
    time.sleep(1)
    logger.warning(target_facility + " warning test")
    time.sleep(1)
    logger.error(target_facility + " error test")
    time.sleep(1)
    logger.critical(target_facility + " critical test")
    time.sleep(3)
