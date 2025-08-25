# SPDX-License-Identifier: MIT
#
# Copyright (c) 2024 EfficiOS Inc.

import sys

major, minor, micro, release, serial = sys.version_info
# The purpose of this import is to make the typing module easily accessible
# elsewhere, without having to do the try-except everywhere.
try:
    # Early releases of Python 3.5 have a bug with typing
    # @see https://github.com/python/typing/issues/266
    if major == 3 and minor == 5 and micro < 3:
        raise ImportError
    import typing as _typing_mod
except ImportError:
    from bt2 import local_typing as _typing_mod  # noqa: F401
