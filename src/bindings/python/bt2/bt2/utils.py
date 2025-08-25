# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>


from bt2 import error as bt2_error
from bt2 import native_bt, typing_mod

typing = typing_mod._typing_mod


class UnknownObject(Exception):
    """Raised when a component class handles a query for an object it doesn't
    know about.
    """

    pass


class _OverflowError(bt2_error._Error, OverflowError):
    pass


class TryAgain(Exception):
    pass


class Stop(StopIteration):
    pass


def _check_bool(o):
    if not isinstance(o, bool):
        raise TypeError("'{}' is not a 'bool' object".format(o.__class__.__name__))


def _check_int(o):
    if not isinstance(o, int):
        raise TypeError("'{}' is not an 'int' object".format(o.__class__.__name__))

    return o


def _check_float(o):
    if not isinstance(o, float):
        raise TypeError("'{}' is not a 'float' object".format(o.__class__.__name__))


def _check_str(o):
    if not isinstance(o, str):
        raise TypeError("'{}' is not a 'str' object".format(o.__class__.__name__))

    return o


_Type = typing.TypeVar("_Type")


def _check_type(o: typing.Any, expected_type: typing.Type[_Type]) -> _Type:
    if not isinstance(o, expected_type):
        raise TypeError("'{}' is not a '{}' object".format(o.__class__.__name__, expected_type))

    return o


def _is_in_int64_range(v):
    assert isinstance(v, int)
    return v >= -(2**63) and v <= (2**63 - 1)


def _is_int64(v):
    if not isinstance(v, int):
        return False

    return _is_in_int64_range(v)


def _is_in_uint64_range(v):
    assert isinstance(v, int)
    return v >= 0 and v <= (2**64 - 1)


def _is_uint64(v):
    if not isinstance(v, int):
        return False

    return _is_in_uint64_range(v)


def _check_int64(v, msg=None):
    _check_int(v)

    if not _is_in_int64_range(v):
        if msg is None:
            msg = "expecting a signed 64-bit integral value"

        msg += " (got {})".format(v)
        raise ValueError(msg)


def _check_uint64(v, msg=None):
    _check_int(v)

    if not _is_in_uint64_range(v):
        if msg is None:
            msg = "expecting an unsigned 64-bit integral value"

        msg += " (got {})".format(v)
        raise ValueError(msg)


def _is_m1ull(v):
    return v == 18446744073709551615


def _is_pow2(v):
    return v != 0 and ((v & (v - 1)) == 0)


def _check_alignment(a):
    _check_uint64(a)

    if not _is_pow2(a):
        raise ValueError("{} is not a power of two".format(a))


def _mip_version_from_obj(obj) -> int:
    if hasattr(obj, "graph_mip_version"):
        return obj.graph_mip_version
    elif hasattr(obj, "_graph_mip_version"):
        return obj._graph_mip_version
    else:
        raise RuntimeError("object does not have a property to get the graph's MIP version")


def _check_mip_ge(obj, what, mip):
    if _mip_version_from_obj(obj) < mip:
        raise ValueError(
            "{} is only available with MIP version ≥ {} (currently {})".format(
                what, mip, _mip_version_from_obj(obj)
            )
        )


def _check_mip_eq(obj, what, mip):
    if _mip_version_from_obj(obj) != mip:
        raise ValueError(
            "{} is only available with MIP version {} (currently {})".format(
                what, mip, _mip_version_from_obj(obj)
            )
        )


def _handle_func_status(status, msg=None):
    if status == native_bt.__BT_FUNC_STATUS_OK:
        # no error
        return

    if status == native_bt.__BT_FUNC_STATUS_ERROR:
        assert msg is not None
        raise bt2_error._Error(msg)
    elif status == native_bt.__BT_FUNC_STATUS_MEMORY_ERROR:
        assert msg is not None
        raise bt2_error._MemoryError(msg)
    elif status == native_bt.__BT_FUNC_STATUS_END:
        if msg is None:
            raise Stop
        else:
            raise Stop(msg)
    elif status == native_bt.__BT_FUNC_STATUS_AGAIN:
        if msg is None:
            raise TryAgain
        else:
            raise TryAgain(msg)
    elif status == native_bt.__BT_FUNC_STATUS_OVERFLOW_ERROR:
        raise _OverflowError(msg)
    elif status == native_bt.__BT_FUNC_STATUS_UNKNOWN_OBJECT:
        if msg is None:
            raise UnknownObject
        else:
            raise UnknownObject(msg)
    else:
        assert False


class _ListenerHandle:
    def __init__(self, addr):
        self._addr = addr
        self._listener_id = None

    def _set_listener_id(self, listener_id):
        self._listener_id = listener_id

    def _invalidate(self):
        self._listener_id = None
