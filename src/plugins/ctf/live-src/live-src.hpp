/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Antmicro
 * Copyright (C) 2026 Analog Devices
 *
 */
#ifndef BABELTRACE_PLUGINS_CTF_LIVE_SRC_LIVE_SRC_HPP
#define BABELTRACE_PLUGINS_CTF_LIVE_SRC_LIVE_SRC_HPP

#include <babeltrace2/babeltrace.h>

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