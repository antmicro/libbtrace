/*
 * Copyright (c) 2025 Analog Devices, Inc.
 * Copyright (c) 2025 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BABELTRACE_COMMON_LIST_H
#define BABELTRACE_COMMON_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#define _dnode bt_list_head

#include "zephyr/util.h"
#include "zephyr/dlist.h"

static inline void sys_dlist_splice(sys_dlist_t *list, sys_dlist_t *add)
{
  if (!sys_dlist_is_empty(add)) {
    add->head->prev = list;
    add->tail->next = list->head;
    list->head->prev = add->tail;
    list->head = add->head;
  }
}

#define BT_LIST_HEAD(name) struct bt_list_head name = SYS_DLIST_STATIC_INIT(&name)
#define BT_INIT_LIST_HEAD(ptr) sys_dlist_init(ptr)

#define bt_list_add(__newp, __head) sys_dlist_prepend(__head, __newp)
#define bt_list_add_tail(__newp, __head) sys_dlist_append(__head, __newp)
#define bt_list_del(__elem) sys_dlist_dequeue(__elem)
#define bt_list_empty(__head) sys_dlist_is_empty(__head)
#define bt_list_splice(__add, __head) sys_dlist_splice(__head, __add)

#define bt_list_entry(ptr, type, member) CONTAINER_OF(ptr, type, member)

#define bt_list_for_each_entry(pos, head, member) SYS_DLIST_FOR_EACH_CONTAINER(head, pos, member)
#define bt_list_for_each_entry_safe(pos, p, head, member) SYS_DLIST_FOR_EACH_CONTAINER_SAFE(head, pos, p, member)

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_COMMON_LIST_H */
