/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Antmicro
 * Copyright (C) 2026 Analog Devices
 *
 */
#ifndef BABELTRACE_PLUGINS_CTF_LIVE_SRC_LIVE_SRC_HPP
#define BABELTRACE_PLUGINS_CTF_LIVE_SRC_LIVE_SRC_HPP

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

#include <sys/types.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/logging.hpp"

#include "../common/src/metadata/metadata-stream-parser-utils.hpp"
#include "../common/src/msg-iter.hpp"
#include "plugins/ctf/common/src/item-seq/medium.hpp"
#include "plugins/ctf/live-src/socket.hpp"

template <typename T, void (*put_ref_func)(const T *)>
struct bt_object_put_reffer
{
    void operator()(T *obj)
    {
        if (obj) {
            put_ref_func(obj);
        }
    }
};

#define BT_OBJ_REF(name)                                                                           \
    using name##_put_reffer = bt_object_put_reffer<name, name##_put_ref>;                          \
    using name##_ref = std::unique_ptr<name, name##_put_reffer>;

BT_OBJ_REF(bt_clock_class)
BT_OBJ_REF(bt_trace_class)
BT_OBJ_REF(bt_stream_class)
BT_OBJ_REF(bt_event_class)
BT_OBJ_REF(bt_field_class)
BT_OBJ_REF(bt_trace)
BT_OBJ_REF(bt_stream)
BT_OBJ_REF(bt_message)

struct ctf_live_trace
{
    bt2c::Logger logger;
    ctf::src::ClkClsCfg clkClsCfg;
    bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp;
    bt2s::optional<ctf::src::MetadataStreamParser::ParseRet> parseRet;
    bt2::Trace::Shared trace;

    explicit ctf_live_trace(const ctf::src::ClkClsCfg& clkClsCfg,
                            const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                            const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/TRACE"}, clkClsCfg {clkClsCfg}, selfComp {selfComp}
    {
    }

    const ctf::src::TraceCls *cls() const
    {
        BT_ASSERT(parseRet);
        BT_ASSERT(parseRet->traceCls);
        return parseRet->traceCls.get();
    }

    void parseMetadata(const bt2c::ConstBytes buffer)
    {
        parseRet = ctf::src::parseMetadataStream(selfComp, clkClsCfg, buffer, logger);
    }
};

struct ctf_live_component
{
    std::unique_ptr<ctf_live_trace> trace;
    std::unique_ptr<CtfLiveSocketServer> server;
};

struct ctf_live_iterator
{
    ctf_live_component *comp;
    std::unique_ptr<ctf::src::MsgIter> msg_iter;
    bt2::Stream::Shared stream;
    /*
     * Saved error.  If we hit an error in the _next method, but have some
     * messages ready to return, we save the error here and return it on
     * the next _next call.
     */
    bt_message_iterator_class_next_method_status next_saved_status =
        BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
    const bt_error *next_saved_error = nullptr;
};

struct ctf_live_port_output
{
    ctf_live_component *comp;
    std::string name;
    uint8_t stream_id;
    const ctf::src::DataStreamCls *data_stream_cls;
};

bt_message_iterator_class_next_method_status
ctf_live_iterator_next(bt_self_message_iterator *iterator, bt_message_array_const msgs,
                       uint64_t capacity, uint64_t *count);

bt_component_class_get_supported_mip_versions_method_status
ctf_live_get_supported_mip_versions(bt_self_component_class_source *selfCompClsSrc,
                                    const bt_value *params, void *, bt_logging_level logLevel,
                                    bt_integer_range_set_unsigned *supportedVersionsRaw);

bt_component_class_initialize_method_status ctf_live_init(bt_self_component_source *self_comp_src,
                                                          bt_self_component_source_configuration *,
                                                          const bt_value *params, void *);

bt_component_class_query_method_status
ctf_live_query(bt_self_component_class_source *comp_class_src,
               bt_private_query_executor *priv_query_exec, const char *object,
               const bt_value *params, __attribute__((unused)) void *method_data,
               const bt_value **result);

void ctf_live_finalize(bt_self_component_source *component);

bt_message_iterator_class_initialize_method_status
ctf_live_iterator_init(bt_self_message_iterator *self_msg_iter,
                       bt_self_message_iterator_configuration *config,
                       bt_self_component_port_output *self_port);

void ctf_live_iterator_finalize(bt_self_message_iterator *it);

bt_message_iterator_class_seek_beginning_method_status
ctf_live_iterator_seek_beginning(bt_self_message_iterator *it);

#endif