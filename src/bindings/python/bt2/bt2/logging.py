# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>

import enum

from bt2 import native_bt
from bt2 import utils as bt2_utils


class LoggingLevel(enum.Enum):
    TRACE = native_bt.LOGGING_LEVEL_TRACE
    DEBUG = native_bt.LOGGING_LEVEL_DEBUG
    INFO = native_bt.LOGGING_LEVEL_INFO
    WARNING = native_bt.LOGGING_LEVEL_WARNING
    ERROR = native_bt.LOGGING_LEVEL_ERROR
    FATAL = native_bt.LOGGING_LEVEL_FATAL
    NONE = native_bt.LOGGING_LEVEL_NONE


def get_minimal_logging_level() -> LoggingLevel:
    return LoggingLevel(native_bt.logging_get_minimal_level())


def get_global_logging_level() -> LoggingLevel:
    return LoggingLevel(native_bt.logging_get_global_level())


def set_global_logging_level(level: LoggingLevel):
    bt2_utils._check_type(level, LoggingLevel)
    return native_bt.logging_set_global_level(level.value)
