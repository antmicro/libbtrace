/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Antmicro
 * Copyright (C) 2026 Analog Devices
 *
 */
#include <cstdio>
#include <string>

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2/wrap.hpp"
#include "cpp-common/bt2c/data-len.hpp"
#include "cpp-common/bt2c/exc.hpp"
#include "cpp-common/bt2c/file-utils.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2s/make-unique.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "../common/src/metadata/ctf-ir.hpp"
#include "../common/src/metadata/tsdl/ctf-meta-configure-ir-trace.hpp"
#include "../common/src/msg-iter.hpp"
#include "../common/src/pkt-props.hpp"
#include "live-src.hpp"
#include "plugins/ctf/common/src/item-seq/medium.hpp"
#include "plugins/ctf/live-src/socket.hpp"
#include "plugins/utils/muxer/msg-iter.hpp"

#define DEBUGPROBE std::printf("enter %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__)

using namespace bt2c::literals::datalen;

static bt2c::Logger s_logger {"SOURCE.CTF.LIVE", "SOURCE.CTF.LIVE", bt2c::Logger::Level::Info};

static ctf_live_component *priv(bt_self_component_source *component)
{
    return static_cast<ctf_live_component *>(
        bt_self_component_get_data(bt_self_component_source_as_self_component(component)));
}

static std::unique_ptr<ctf_live_trace>
ctf_live_trace_create(const char *path, const char *name, const ctf::src::ClkClsCfg& clkClsCfg,
                      const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp)
{
    auto live_trace = bt2s::make_unique<ctf_live_trace>(clkClsCfg, selfComp, s_logger);
    const auto metadataPath = fmt::format("{}" G_DIR_SEPARATOR_S "metadata", path);

    live_trace->parseMetadata(bt2c::dataFromFile(metadataPath, s_logger, true));

    BT_ASSERT(live_trace->cls());

    if (live_trace->cls()->libCls()) {
        bt2::TraceClass traceCls = *live_trace->cls()->libCls();
        live_trace->trace = traceCls.instantiate();
        ctf_trace_class_configure_ir_trace(
            *live_trace->cls(), *live_trace->trace,
            bt_self_component_get_graph_mip_version(selfComp->libObjPtr()), s_logger);
        live_trace->trace->name(name);
    }

    return live_trace;
}

bt_component_class_get_supported_mip_versions_method_status ctf_live_get_supported_mip_versions(
    bt_self_component_class_source *selfCompClsSrc, const bt_value *params, void *method_data,
    bt_logging_level logLevel, bt_integer_range_set_unsigned *supportedVersions)
{
    (void) selfCompClsSrc;
    (void) params;
    (void) method_data;
    (void) logLevel;
    (void) supportedVersions;

    bt_integer_range_set_unsigned_add_range(supportedVersions, 0, 0);

    return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}

bt_component_class_initialize_method_status
ctf_live_init(bt_self_component_source *self_comp_src,
              bt_self_component_source_configuration *config, const bt_value *params,
              void *init_method_data)
{
    (void) init_method_data;
    (void) config;

    auto *comp = new ctf_live_component;
    if (!comp) {
        return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
    }
    bt_self_component_set_data(bt_self_component_source_as_self_component(self_comp_src), comp);

    //  Parse the metadata file
    comp->trace = ctf_live_trace_create(".", "trace", ctf::src::ClkClsCfg {},
                                        static_cast<bt2::SelfComponent>(bt2::wrap(self_comp_src)));
    size_t idx = 0;
    //  Create an output port for each of the streams found in the metadata
    //  file.
    for (const auto& streamCls : comp->trace->cls()->dataStreamClasses()) {
        auto *port = new ctf_live_port_output;
        if (!port) {
            return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
        }
        port->comp = comp;
        port->stream_id = idx++;
        port->name = std::string {"out"} + std::to_string(port->stream_id);
        port->data_stream_cls = streamCls.get();
        bt_self_component_source_add_output_port(self_comp_src, port->name.data(), port, nullptr);
    }
    try {
        unsigned port = 42674;
        if (bt_value_is_map(params)) {
            if (bt_value_map_has_entry(params, "port")) {
                port = bt_value_integer_unsigned_get(
                    bt_value_map_borrow_entry_value_const(params, "port"));
            }
        }

        comp->server = bt2s::make_unique<CtfLiveSocketServer>(port);
    } catch (const bt2c::Error& e) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(s_logger, "Error initializing live socket server");
        return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
    }

    return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

bt_component_class_query_method_status
ctf_live_query(bt_self_component_class_source *comp_class_src,
               bt_private_query_executor *priv_query_exec, const char *object,
               const bt_value *params, void *method_data, const bt_value **result)
{
    (void) comp_class_src;
    (void) priv_query_exec;
    (void) object;
    (void) params;
    (void) method_data;

    *result = bt_value_null;
    return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
}

void ctf_live_finalize(bt_self_component_source *component)
{
    auto *comp = priv(component);
    if (comp) {
        delete comp;
    }
    // TODO free/destroy ports
}

bt_message_iterator_class_initialize_method_status
ctf_live_iterator_init(bt_self_message_iterator *self_msg_iter,
                       bt_self_message_iterator_configuration *config,
                       bt_self_component_port_output *self_port)
{
    auto *self_component_port = bt_self_component_port_output_as_self_component_port(self_port);
    auto *self_component = bt_self_component_port_borrow_component(self_component_port);

    auto *port = static_cast<ctf_live_port_output *>(bt_self_component_port_get_data(
        bt_self_component_port_output_as_self_component_port(self_port)));
    auto *it = new ctf_live_iterator;
    if (!it) {
        return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
    }
    bt_self_message_iterator_configuration_set_can_seek_forward(config, true);
    bt_self_message_iterator_set_data(self_msg_iter, it);

    const auto streamCls = *port->data_stream_cls->libCls();

    it->comp = static_cast<ctf_live_component *>(bt_self_component_get_data(self_component));
    it->stream = streamCls.instantiate(*it->comp->trace->trace, port->stream_id);
    auto medium = it->comp->server->create_medium();
    it->msg_iter = bt2s::make_unique<ctf::src::MsgIter>(
        bt2::wrap(self_msg_iter), *it->comp->trace->cls(), it->comp->trace->parseRet->uuid,
        *it->stream, std::move(medium), ctf::src::MsgIterQuirks {}, s_logger);

    return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

bt_message_iterator_class_next_method_status
ctf_live_iterator_next(bt_self_message_iterator *self_msg_iter, bt_message_array_const msgs,
                       uint64_t capacity, uint64_t *count)
{
    auto *it = static_cast<ctf_live_iterator *>(bt_self_message_iterator_get_data(self_msg_iter));

    bt_message_iterator_class_next_method_status status =
        BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
    uint64_t i = 0;

    do {
        try {
            bt2::ConstMessage::Shared msg = it->msg_iter->next();
            if (G_LIKELY(msg)) {
                msgs[i] = msg.release().libObjPtr();
                ++i;
            } else {
                status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_END;
            }
        } catch (const bt2::Error&) {
            status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_ERROR;
            break;
        } catch (const std::bad_alloc&) {
            status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_MEMORY_ERROR;
            break;
        } catch (const bt2::TryAgain&) {
            status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_AGAIN;
            break;
        }
    } while (i < capacity && status == BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK);

    if (i > 0) {
        /*
         * Even if ctf_fs_iterator_next_one() returned something
         * else than BT_MESSAGE_ITERATOR_NEXT_METHOD_STATUS_OK, we
         * accumulated message objects in the output
         * message array, so we need to return
         * BT_MESSAGE_ITERATOR_NEXT_METHOD_STATUS_OK so that they are
         * transferred to downstream. This other status occurs
         * again the next time muxer_msg_iter_do_next() is
         * called, possibly without any accumulated
         * message, in which case we'll return it.
         */
        if (status < 0) {
            /*
             * Save this error for the next _next call.  Assume that
             * this component always appends error causes when
             * returning an error status code, which will cause the
             * current thread error to be non-NULL.
             */
            it->next_saved_error = bt_current_thread_take_error();
            BT_ASSERT(it->next_saved_error);
            it->next_saved_status = status;
        }

        *count = i;
        status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
    }

    return status;
}

bt_message_iterator_class_seek_beginning_method_status
ctf_live_iterator_seek_beginning(bt_self_message_iterator *it)
{
    (void) it;
    return BT_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHOD_STATUS_OK;
}

void ctf_live_iterator_finalize(bt_self_message_iterator *self_msg_iter)
{
    auto *it = static_cast<ctf_live_iterator *>(bt_self_message_iterator_get_data(self_msg_iter));
    if (it) {
        delete it;
    }
}
