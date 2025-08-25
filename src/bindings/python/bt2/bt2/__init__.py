# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>

import os
import sys

# With Python ≥ 3.8 on Windows, the DLL lookup mechanism to load native
# modules doesn't search the `PATH` environment variable like everything
# else on this platform.
#
# See <https://docs.python.org/3/whatsnew/3.8.html#bpo-36085-whatsnew>.
#
# Restore this behaviour by doing it manually.
if os.name == "nt" and sys.version_info >= (3, 8):
    for path in os.getenv("PATH", "").split(os.pathsep):
        if os.path.exists(path) and path != ".":
            os.add_dll_directory(path)

del os

# import all public names
from bt2.clock_class import (
    ClockClassOffset,
    ClockOffset,
    ClockOrigin,
    _ClockClass,
    _ClockClassConst,
    _UnixEpochClockOrigin,
    _UnknownClockOrigin,
    unix_epoch_clock_origin,
    unknown_clock_origin,
)
from bt2.clock_snapshot import _ClockSnapshotConst, _UnknownClockSnapshot
from bt2.component import (
    _FilterComponentClassConst,
    _FilterComponentConst,
    _IncompleteUserClass,
    _SinkComponentClassConst,
    _SinkComponentConst,
    _SourceComponentClassConst,
    _SourceComponentConst,
    _UserFilterComponent,
    _UserFilterComponentConfiguration,
    _UserSinkComponent,
    _UserSinkComponentConfiguration,
    _UserSourceComponent,
    _UserSourceComponentConfiguration,
)
from bt2.component_descriptor import ComponentDescriptor
from bt2.error import (
    ComponentClassType,
    _ComponentClassErrorCause,
    _ComponentErrorCause,
    _Error,
    _ErrorCause,
    _MemoryError,
    _MessageIteratorErrorCause,
)
from bt2.event_class import EventClassLogLevel, _EventClass, _EventClassConst
from bt2.field import (
    _ArrayField,
    _ArrayFieldConst,
    _BitArrayField,
    _BitArrayFieldConst,
    _BlobField,
    _BlobFieldConst,
    _BoolField,
    _BoolFieldConst,
    _DoublePrecisionRealField,
    _DoublePrecisionRealFieldConst,
    _DynamicArrayField,
    _DynamicArrayFieldConst,
    _DynamicArrayFieldWithLengthField,
    _DynamicArrayFieldWithLengthFieldConst,
    _DynamicBlobField,
    _DynamicBlobFieldConst,
    _DynamicBlobFieldWithLengthField,
    _DynamicBlobFieldWithLengthFieldConst,
    _EnumerationField,
    _EnumerationFieldConst,
    _Field,
    _FieldConst,
    _IntegerField,
    _IntegerFieldConst,
    _OptionField,
    _OptionFieldConst,
    _OptionFieldWithBoolSelectorField,
    _OptionFieldWithBoolSelectorFieldConst,
    _OptionFieldWithSignedIntegerSelectorField,
    _OptionFieldWithSignedIntegerSelectorFieldConst,
    _OptionFieldWithUnsignedIntegerSelectorField,
    _OptionFieldWithUnsignedIntegerSelectorFieldConst,
    _RealField,
    _RealFieldConst,
    _SignedEnumerationField,
    _SignedEnumerationFieldConst,
    _SignedIntegerField,
    _SignedIntegerFieldConst,
    _SinglePrecisionRealField,
    _SinglePrecisionRealFieldConst,
    _StaticArrayField,
    _StaticArrayFieldConst,
    _StaticBlobField,
    _StaticBlobFieldConst,
    _StringField,
    _StringFieldConst,
    _StructureField,
    _StructureFieldConst,
    _UnsignedEnumerationField,
    _UnsignedEnumerationFieldConst,
    _UnsignedIntegerField,
    _UnsignedIntegerFieldConst,
    _VariantField,
    _VariantFieldConst,
    _VariantFieldWithSignedIntegerSelectorField,
    _VariantFieldWithSignedIntegerSelectorFieldConst,
    _VariantFieldWithUnsignedIntegerSelectorField,
    _VariantFieldWithUnsignedIntegerSelectorFieldConst,
)
from bt2.field_class import (
    IntegerDisplayBase,
    _ArrayFieldClass,
    _ArrayFieldClassConst,
    _BitArrayFieldClass,
    _BitArrayFieldClassConst,
    _BitArrayFieldClassFlagConst,
    _BlobFieldClass,
    _BlobFieldClassConst,
    _BoolFieldClass,
    _BoolFieldClassConst,
    _DoublePrecisionRealFieldClass,
    _DoublePrecisionRealFieldClassConst,
    _DynamicArrayFieldClass,
    _DynamicArrayFieldClassConst,
    _DynamicArrayFieldClassWithLengthField,
    _DynamicArrayFieldClassWithLengthFieldConst,
    _DynamicArrayWithLengthFieldFieldClass,
    _DynamicArrayWithLengthFieldFieldClassConst,
    _DynamicBlobFieldClass,
    _DynamicBlobFieldClassConst,
    _DynamicBlobFieldClassWithLengthField,
    _DynamicBlobFieldClassWithLengthFieldConst,
    _EnumerationFieldClass,
    _EnumerationFieldClassConst,
    _FieldClass,
    _FieldClassConst,
    _IntegerFieldClass,
    _IntegerFieldClassConst,
    _OptionFieldClass,
    _OptionFieldClassConst,
    _OptionFieldClassWithBoolSelectorField,
    _OptionFieldClassWithBoolSelectorFieldConst,
    _OptionFieldClassWithIntegerSelectorField,
    _OptionFieldClassWithIntegerSelectorFieldConst,
    _OptionFieldClassWithSelectorField,
    _OptionFieldClassWithSelectorFieldConst,
    _OptionFieldClassWithSignedIntegerSelectorField,
    _OptionFieldClassWithSignedIntegerSelectorFieldConst,
    _OptionFieldClassWithUnsignedIntegerSelectorField,
    _OptionFieldClassWithUnsignedIntegerSelectorFieldConst,
    _OptionWithBoolSelectorFieldClass,
    _OptionWithBoolSelectorFieldClassConst,
    _OptionWithIntegerSelectorFieldClass,
    _OptionWithIntegerSelectorFieldClassConst,
    _OptionWithSelectorFieldClass,
    _OptionWithSelectorFieldClassConst,
    _OptionWithSignedIntegerSelectorFieldClass,
    _OptionWithSignedIntegerSelectorFieldClassConst,
    _OptionWithUnsignedIntegerSelectorFieldClass,
    _OptionWithUnsignedIntegerSelectorFieldClassConst,
    _RealFieldClass,
    _RealFieldClassConst,
    _SignedEnumerationFieldClass,
    _SignedEnumerationFieldClassConst,
    _SignedEnumerationFieldClassMappingConst,
    _SignedIntegerFieldClass,
    _SignedIntegerFieldClassConst,
    _SinglePrecisionRealFieldClass,
    _SinglePrecisionRealFieldClassConst,
    _StaticArrayFieldClass,
    _StaticArrayFieldClassConst,
    _StaticBlobFieldClass,
    _StaticBlobFieldClassConst,
    _StringFieldClass,
    _StringFieldClassConst,
    _StructureFieldClass,
    _StructureFieldClassConst,
    _StructureFieldClassMember,
    _StructureFieldClassMemberConst,
    _UnsignedEnumerationFieldClass,
    _UnsignedEnumerationFieldClassConst,
    _UnsignedEnumerationFieldClassMappingConst,
    _UnsignedIntegerFieldClass,
    _UnsignedIntegerFieldClassConst,
    _VariantFieldClass,
    _VariantFieldClassConst,
    _VariantFieldClassOption,
    _VariantFieldClassOptionConst,
    _VariantFieldClassWithIntegerSelector,
    _VariantFieldClassWithIntegerSelectorConst,
    _VariantFieldClassWithIntegerSelectorField,
    _VariantFieldClassWithIntegerSelectorFieldConst,
    _VariantFieldClassWithIntegerSelectorFieldOption,
    _VariantFieldClassWithIntegerSelectorFieldOptionConst,
    _VariantFieldClassWithoutSelector,
    _VariantFieldClassWithoutSelectorConst,
    _VariantFieldClassWithoutSelectorField,
    _VariantFieldClassWithoutSelectorFieldConst,
    _VariantFieldClassWithSignedIntegerSelector,
    _VariantFieldClassWithSignedIntegerSelectorConst,
    _VariantFieldClassWithSignedIntegerSelectorField,
    _VariantFieldClassWithSignedIntegerSelectorFieldConst,
    _VariantFieldClassWithSignedIntegerSelectorFieldOption,
    _VariantFieldClassWithSignedIntegerSelectorFieldOptionConst,
    _VariantFieldClassWithUnsignedIntegerSelector,
    _VariantFieldClassWithUnsignedIntegerSelectorConst,
    _VariantFieldClassWithUnsignedIntegerSelectorField,
    _VariantFieldClassWithUnsignedIntegerSelectorFieldConst,
    _VariantFieldClassWithUnsignedIntegerSelectorFieldOption,
    _VariantFieldClassWithUnsignedIntegerSelectorFieldOptionConst,
)
from bt2.field_location import FieldLocationScope, _FieldLocationConst
from bt2.field_path import (
    FieldPathScope,
    _CurrentArrayElementFieldPathItem,
    _CurrentOptionContentFieldPathItem,
    _FieldPathConst,
    _FieldPathItem,
    _IndexFieldPathItem,
)
from bt2.graph import Graph
from bt2.integer_range_set import (
    SignedIntegerRange,
    SignedIntegerRangeSet,
    UnsignedIntegerRange,
    UnsignedIntegerRangeSet,
    _SignedIntegerRangeConst,
    _SignedIntegerRangeSetConst,
    _UnsignedIntegerRangeConst,
    _UnsignedIntegerRangeSetConst,
)
from bt2.interrupter import Interrupter
from bt2.logging import (
    LoggingLevel,
    get_global_logging_level,
    get_minimal_logging_level,
    set_global_logging_level,
)
from bt2.message import (
    _DiscardedEventsMessage,
    _DiscardedEventsMessageConst,
    _DiscardedPacketsMessage,
    _DiscardedPacketsMessageConst,
    _EventMessage,
    _EventMessageConst,
    _MessageConst,
    _MessageIteratorInactivityMessage,
    _MessageIteratorInactivityMessageConst,
    _PacketBeginningMessage,
    _PacketBeginningMessageConst,
    _PacketEndMessage,
    _PacketEndMessageConst,
    _StreamBeginningMessage,
    _StreamBeginningMessageConst,
    _StreamEndMessage,
    _StreamEndMessageConst,
)
from bt2.message_iterator import (
    _MessageIteratorConfiguration,
    _UserComponentInputPortMessageIterator,
    _UserMessageIterator,
)
from bt2.mip import get_greatest_operative_mip_version, get_maximal_mip_version
from bt2.plugin import _PluginSet, find_plugin, find_plugins, find_plugins_in_path
from bt2.port import (
    _InputPortConst,
    _OutputPortConst,
    _UserComponentInputPort,
    _UserComponentOutputPort,
)
from bt2.py_plugin import plugin_component_class, register_plugin
from bt2.query_executor import QueryExecutor, _PrivateQueryExecutor
from bt2.stream import _Stream, _StreamConst
from bt2.stream_class import _StreamClass, _StreamClassConst
from bt2.trace import _Trace, _TraceConst
from bt2.trace_class import _TraceClass, _TraceClassConst
from bt2.trace_collection_message_iterator import (
    AutoSourceComponentSpec,
    ComponentSpec,
    TraceCollectionMessageIterator,
)
from bt2.utils import Stop, TryAgain, UnknownObject, _ListenerHandle, _OverflowError
from bt2.value import (
    ArrayValue,
    BoolValue,
    MapValue,
    RealValue,
    SignedIntegerValue,
    StringValue,
    UnsignedIntegerValue,
    _ArrayValueConst,
    _BoolValueConst,
    _IntegerValue,
    _IntegerValueConst,
    _MapValueConst,
    _RealValueConst,
    _SignedIntegerValueConst,
    _StringValueConst,
    _UnsignedIntegerValueConst,
    _Value,
    _ValueConst,
    create_value,
)
from bt2.version import __version__

if (sys.version_info.major, sys.version_info.minor) != (3, 4):

    def _del_global_name(name):
        if name in globals():
            del globals()[name]

    # remove private module names from the package
    _del_global_name("_native_bt")
    _del_global_name("clock_class")
    _del_global_name("clock_snapshot")
    _del_global_name("component")
    _del_global_name("component_descriptor")
    _del_global_name("connection")
    _del_global_name("error")
    _del_global_name("event")
    _del_global_name("event_class")
    _del_global_name("field")
    _del_global_name("field_class")
    _del_global_name("field_location")
    _del_global_name("field_path")
    _del_global_name("graph")
    _del_global_name("integer_range_set")
    _del_global_name("interrupter")
    _del_global_name("logging")
    _del_global_name("message")
    _del_global_name("message_iterator")
    _del_global_name("mip")
    _del_global_name("native_bt")
    _del_global_name("object")
    _del_global_name("packet")
    _del_global_name("plugin")
    _del_global_name("port")
    _del_global_name("py_plugin")
    _del_global_name("query_executor")
    _del_global_name("stream")
    _del_global_name("stream_class")
    _del_global_name("trace")
    _del_global_name("trace_class")
    _del_global_name("trace_collection_message_iterator")
    _del_global_name("typing_mod")
    _del_global_name("user_attributes")
    _del_global_name("utils")
    _del_global_name("value")
    _del_global_name("version")

    # remove private `_del_global_name` name from the package
    del _del_global_name


# remove sys module name from the package
del sys


def _init_and_register_exit():
    import atexit

    from bt2 import native_bt

    atexit.register(native_bt.bt2_exit_handler)
    native_bt.bt2_init_from_bt2()


_init_and_register_exit()

# remove private `_init_and_register_exit` name from the package
del _init_and_register_exit

__all__ = [
    ClockClassOffset,
    ClockOffset,
    ClockOrigin,
    _ClockClass,
    _ClockClassConst,
    _UnixEpochClockOrigin,
    _UnknownClockOrigin,
    unix_epoch_clock_origin,
    unknown_clock_origin,
    _ClockSnapshotConst,
    _UnknownClockSnapshot,
    _FilterComponentClassConst,
    _FilterComponentConst,
    _IncompleteUserClass,
    _SinkComponentClassConst,
    _SinkComponentConst,
    _SourceComponentClassConst,
    _SourceComponentConst,
    _UserFilterComponent,
    _UserFilterComponentConfiguration,
    _UserSinkComponent,
    _UserSinkComponentConfiguration,
    _UserSourceComponent,
    _UserSourceComponentConfiguration,
    ComponentDescriptor,
    ComponentClassType,
    _ComponentClassErrorCause,
    _ComponentErrorCause,
    _Error,
    _ErrorCause,
    _MemoryError,
    _MessageIteratorErrorCause,
    EventClassLogLevel,
    _EventClass,
    _EventClassConst,
    _ArrayField,
    _ArrayFieldConst,
    _BitArrayField,
    _BitArrayFieldConst,
    _BlobField,
    _BlobFieldConst,
    _BoolField,
    _BoolFieldConst,
    _DoublePrecisionRealField,
    _DoublePrecisionRealFieldConst,
    _DynamicArrayField,
    _DynamicArrayFieldConst,
    _DynamicArrayFieldWithLengthField,
    _DynamicArrayFieldWithLengthFieldConst,
    _DynamicBlobField,
    _DynamicBlobFieldConst,
    _DynamicBlobFieldWithLengthField,
    _DynamicBlobFieldWithLengthFieldConst,
    _EnumerationField,
    _EnumerationFieldConst,
    _Field,
    _FieldConst,
    _IntegerField,
    _IntegerFieldConst,
    _OptionField,
    _OptionFieldConst,
    _OptionFieldWithBoolSelectorField,
    _OptionFieldWithBoolSelectorFieldConst,
    _OptionFieldWithSignedIntegerSelectorField,
    _OptionFieldWithSignedIntegerSelectorFieldConst,
    _OptionFieldWithUnsignedIntegerSelectorField,
    _OptionFieldWithUnsignedIntegerSelectorFieldConst,
    _RealField,
    _RealFieldConst,
    _SignedEnumerationField,
    _SignedEnumerationFieldConst,
    _SignedIntegerField,
    _SignedIntegerFieldConst,
    _SinglePrecisionRealField,
    _SinglePrecisionRealFieldConst,
    _StaticArrayField,
    _StaticArrayFieldConst,
    _StaticBlobField,
    _StaticBlobFieldConst,
    _StringField,
    _StringFieldConst,
    _StructureField,
    _StructureFieldConst,
    _UnsignedEnumerationField,
    _UnsignedEnumerationFieldConst,
    _UnsignedIntegerField,
    _UnsignedIntegerFieldConst,
    _VariantField,
    _VariantFieldConst,
    _VariantFieldWithSignedIntegerSelectorField,
    _VariantFieldWithSignedIntegerSelectorFieldConst,
    _VariantFieldWithUnsignedIntegerSelectorField,
    _VariantFieldWithUnsignedIntegerSelectorFieldConst,
    IntegerDisplayBase,
    _ArrayFieldClass,
    _ArrayFieldClassConst,
    _BitArrayFieldClass,
    _BitArrayFieldClassConst,
    _BitArrayFieldClassFlagConst,
    _BlobFieldClass,
    _BlobFieldClassConst,
    _BoolFieldClass,
    _BoolFieldClassConst,
    _DoublePrecisionRealFieldClass,
    _DoublePrecisionRealFieldClassConst,
    _DynamicArrayFieldClass,
    _DynamicArrayFieldClassConst,
    _DynamicArrayFieldClassWithLengthField,
    _DynamicArrayFieldClassWithLengthFieldConst,
    _DynamicArrayWithLengthFieldFieldClass,
    _DynamicArrayWithLengthFieldFieldClassConst,
    _DynamicBlobFieldClass,
    _DynamicBlobFieldClassConst,
    _DynamicBlobFieldClassWithLengthField,
    _DynamicBlobFieldClassWithLengthFieldConst,
    _EnumerationFieldClass,
    _EnumerationFieldClassConst,
    _FieldClass,
    _FieldClassConst,
    _IntegerFieldClass,
    _IntegerFieldClassConst,
    _OptionFieldClass,
    _OptionFieldClassConst,
    _OptionFieldClassWithBoolSelectorField,
    _OptionFieldClassWithBoolSelectorFieldConst,
    _OptionFieldClassWithIntegerSelectorField,
    _OptionFieldClassWithIntegerSelectorFieldConst,
    _OptionFieldClassWithSelectorField,
    _OptionFieldClassWithSelectorFieldConst,
    _OptionFieldClassWithSignedIntegerSelectorField,
    _OptionFieldClassWithSignedIntegerSelectorFieldConst,
    _OptionFieldClassWithUnsignedIntegerSelectorField,
    _OptionFieldClassWithUnsignedIntegerSelectorFieldConst,
    _OptionWithBoolSelectorFieldClass,
    _OptionWithBoolSelectorFieldClassConst,
    _OptionWithIntegerSelectorFieldClass,
    _OptionWithIntegerSelectorFieldClassConst,
    _OptionWithSelectorFieldClass,
    _OptionWithSelectorFieldClassConst,
    _OptionWithSignedIntegerSelectorFieldClass,
    _OptionWithSignedIntegerSelectorFieldClassConst,
    _OptionWithUnsignedIntegerSelectorFieldClass,
    _OptionWithUnsignedIntegerSelectorFieldClassConst,
    _RealFieldClass,
    _RealFieldClassConst,
    _SignedEnumerationFieldClass,
    _SignedEnumerationFieldClassConst,
    _SignedEnumerationFieldClassMappingConst,
    _SignedIntegerFieldClass,
    _SignedIntegerFieldClassConst,
    _SinglePrecisionRealFieldClass,
    _SinglePrecisionRealFieldClassConst,
    _StaticArrayFieldClass,
    _StaticArrayFieldClassConst,
    _StaticBlobFieldClass,
    _StaticBlobFieldClassConst,
    _StringFieldClass,
    _StringFieldClassConst,
    _StructureFieldClass,
    _StructureFieldClassConst,
    _StructureFieldClassMember,
    _StructureFieldClassMemberConst,
    _UnsignedEnumerationFieldClass,
    _UnsignedEnumerationFieldClassConst,
    _UnsignedEnumerationFieldClassMappingConst,
    _UnsignedIntegerFieldClass,
    _UnsignedIntegerFieldClassConst,
    _VariantFieldClass,
    _VariantFieldClassConst,
    _VariantFieldClassOption,
    _VariantFieldClassOptionConst,
    _VariantFieldClassWithIntegerSelector,
    _VariantFieldClassWithIntegerSelectorConst,
    _VariantFieldClassWithIntegerSelectorField,
    _VariantFieldClassWithIntegerSelectorFieldConst,
    _VariantFieldClassWithIntegerSelectorFieldOption,
    _VariantFieldClassWithIntegerSelectorFieldOptionConst,
    _VariantFieldClassWithoutSelector,
    _VariantFieldClassWithoutSelectorConst,
    _VariantFieldClassWithoutSelectorField,
    _VariantFieldClassWithoutSelectorFieldConst,
    _VariantFieldClassWithSignedIntegerSelector,
    _VariantFieldClassWithSignedIntegerSelectorConst,
    _VariantFieldClassWithSignedIntegerSelectorField,
    _VariantFieldClassWithSignedIntegerSelectorFieldConst,
    _VariantFieldClassWithSignedIntegerSelectorFieldOption,
    _VariantFieldClassWithSignedIntegerSelectorFieldOptionConst,
    _VariantFieldClassWithUnsignedIntegerSelector,
    _VariantFieldClassWithUnsignedIntegerSelectorConst,
    _VariantFieldClassWithUnsignedIntegerSelectorField,
    _VariantFieldClassWithUnsignedIntegerSelectorFieldConst,
    _VariantFieldClassWithUnsignedIntegerSelectorFieldOption,
    _VariantFieldClassWithUnsignedIntegerSelectorFieldOptionConst,
    FieldLocationScope,
    _FieldLocationConst,
    FieldPathScope,
    _CurrentArrayElementFieldPathItem,
    _CurrentOptionContentFieldPathItem,
    _FieldPathConst,
    _FieldPathItem,
    _IndexFieldPathItem,
    Graph,
    SignedIntegerRange,
    SignedIntegerRangeSet,
    UnsignedIntegerRange,
    UnsignedIntegerRangeSet,
    _SignedIntegerRangeConst,
    _SignedIntegerRangeSetConst,
    _UnsignedIntegerRangeConst,
    _UnsignedIntegerRangeSetConst,
    Interrupter,
    LoggingLevel,
    get_global_logging_level,
    get_minimal_logging_level,
    set_global_logging_level,
    _DiscardedEventsMessage,
    _DiscardedEventsMessageConst,
    _DiscardedPacketsMessage,
    _DiscardedPacketsMessageConst,
    _EventMessage,
    _EventMessageConst,
    _MessageConst,
    _MessageIteratorInactivityMessage,
    _MessageIteratorInactivityMessageConst,
    _PacketBeginningMessage,
    _PacketBeginningMessageConst,
    _PacketEndMessage,
    _PacketEndMessageConst,
    _StreamBeginningMessage,
    _StreamBeginningMessageConst,
    _StreamEndMessage,
    _StreamEndMessageConst,
    _MessageIteratorConfiguration,
    _UserComponentInputPortMessageIterator,
    _UserMessageIterator,
    get_greatest_operative_mip_version,
    get_maximal_mip_version,
    _PluginSet,
    find_plugin,
    find_plugins,
    find_plugins_in_path,
    _InputPortConst,
    _OutputPortConst,
    _UserComponentInputPort,
    _UserComponentOutputPort,
    plugin_component_class,
    register_plugin,
    QueryExecutor,
    _PrivateQueryExecutor,
    _Stream,
    _StreamConst,
    _StreamClass,
    _StreamClassConst,
    _Trace,
    _TraceConst,
    _TraceClass,
    _TraceClassConst,
    AutoSourceComponentSpec,
    ComponentSpec,
    TraceCollectionMessageIterator,
    Stop,
    TryAgain,
    UnknownObject,
    _ListenerHandle,
    _OverflowError,
    ArrayValue,
    BoolValue,
    MapValue,
    RealValue,
    SignedIntegerValue,
    StringValue,
    UnsignedIntegerValue,
    _ArrayValueConst,
    _BoolValueConst,
    _IntegerValue,
    _IntegerValueConst,
    _MapValueConst,
    _RealValueConst,
    _SignedIntegerValueConst,
    _StringValueConst,
    _UnsignedIntegerValueConst,
    _Value,
    _ValueConst,
    create_value,
    __version__,
]
