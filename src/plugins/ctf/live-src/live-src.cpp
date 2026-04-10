/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Antmicro
 * Copyright (C) 2026 Analog Devices
 *
 */
#include <cstdio>

#include <babeltrace2/babeltrace.h>

#include "live-src.hpp"

#define DEBUGPROBE std::printf("enter %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__)

bt_message_iterator_class_next_method_status
ctf_live_iterator_next(bt_self_message_iterator *iterator, bt_message_array_const msgs,
                       uint64_t capacity, uint64_t *count)
{
    DEBUGPROBE;
    return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_MEMORY_ERROR;
}

bt_component_class_get_supported_mip_versions_method_status
ctf_live_get_supported_mip_versions(bt_self_component_class_source *selfCompClsSrc,
                                    const bt_value *params, void *, bt_logging_level logLevel,
                                    bt_integer_range_set_unsigned *supportedVersionsRaw)
{
    DEBUGPROBE;
    return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_MEMORY_ERROR;
}

bt_component_class_initialize_method_status ctf_live_init(bt_self_component_source *self_comp_src,
                                                          bt_self_component_source_configuration *,
                                                          const bt_value *params, void *)
{
    DEBUGPROBE;
    return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
}

bt_component_class_query_method_status
ctf_live_query(bt_self_component_class_source *comp_class_src,
               bt_private_query_executor *priv_query_exec, const char *object,
               const bt_value *params, __attribute__((unused)) void *method_data,
               const bt_value **result)
{
    DEBUGPROBE;
    return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_MEMORY_ERROR;
}

void ctf_live_finalize(bt_self_component_source *component)
{
    DEBUGPROBE;
}

bt_message_iterator_class_initialize_method_status
ctf_live_iterator_init(bt_self_message_iterator *self_msg_iter,
                       bt_self_message_iterator_configuration *config,
                       bt_self_component_port_output *self_port)
{
    DEBUGPROBE;
    return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
}

void ctf_live_iterator_finalize(bt_self_message_iterator *it)
{
    DEBUGPROBE;
}

bt_message_iterator_class_seek_beginning_method_status
ctf_live_iterator_seek_beginning(bt_self_message_iterator *it)
{
    DEBUGPROBE;
    return BT_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHOD_STATUS_MEMORY_ERROR;
}