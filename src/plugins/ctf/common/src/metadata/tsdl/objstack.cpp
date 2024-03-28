/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Common Trace Format Object Stack.
 */

#include <stdlib.h>

#define BT_LOG_OUTPUT_LEVEL ctf_plugin_metadata_log_level
#define BT_LOG_TAG          "PLUGIN/CTF/META/OBJSTACK"
#include "logging.hpp"

#include "common/align.h"
#include "common/list.h"

#include "objstack.hpp"

#define OBJSTACK_ALIGN    8 /* Object stack alignment */
#define OBJSTACK_INIT_LEN 128
#define OBJSTACK_POISON   0xcc

struct objstack
{
    struct bt_list_head head; /* list of struct objstack_node */
};

struct objstack_node
{
    struct bt_list_head node;
    size_t len;
    size_t used_len;
    char __attribute__((aligned(OBJSTACK_ALIGN))) data[];
};

struct objstack *objstack_create(void)
{
    struct objstack *objstack;
    struct objstack_node *node;

    objstack = (struct objstack *) calloc(1, sizeof(*objstack));
    if (!objstack) {
        BT_LOGE_STR("Failed to allocate one object stack.");
        return NULL;
    }
    node = (objstack_node *) calloc(sizeof(struct objstack_node) + OBJSTACK_INIT_LEN, sizeof(char));
    if (!node) {
        BT_LOGE_STR("Failed to allocate one object stack node.");
        free(objstack);
        return NULL;
    }
    BT_INIT_LIST_HEAD(&objstack->head);
    bt_list_add_tail(&node->node, &objstack->head);
    node->len = OBJSTACK_INIT_LEN;
    return objstack;
}

static void objstack_node_free(struct objstack_node *node)
{
    size_t offset, len;
    char *p;

    if (!node)
        return;
    p = (char *) node;
    len = sizeof(*node) + node->len;
    for (offset = 0; offset < len; offset++)
        p[offset] = OBJSTACK_POISON;
    free(node);
}

void objstack_destroy(struct objstack *objstack)
{
    struct objstack_node *node, *p;

    if (!objstack)
        return;
    bt_list_for_each_entry_safe (node, p, &objstack->head, node) {
        bt_list_del(&node->node);
        objstack_node_free(node);
    }
    free(objstack);
}

static struct objstack_node *objstack_append_node(struct objstack *objstack)
{
    struct objstack_node *last_node, *new_node;

    /* Get last node */
    last_node = bt_list_entry(objstack->head.prev, struct objstack_node, node);

    /* Allocate new node with double of size of last node */
    new_node = (objstack_node *) calloc(sizeof(struct objstack_node) + (last_node->len << 1),
                                        sizeof(char));
    if (!new_node) {
        BT_LOGE_STR("Failed to allocate one object stack node.");
        return NULL;
    }
    bt_list_add_tail(&new_node->node, &objstack->head);
    new_node->len = last_node->len << 1;
    return new_node;
}

void *objstack_alloc(struct objstack *objstack, size_t len)
{
    struct objstack_node *last_node;
    void *p;

    len = BT_ALIGN(len, OBJSTACK_ALIGN);

    /* Get last node */
    last_node = bt_list_entry(objstack->head.prev, struct objstack_node, node);
    while (last_node->len - last_node->used_len < len) {
        last_node = objstack_append_node(objstack);
        if (!last_node) {
            return NULL;
        }
    }
    p = &last_node->data[last_node->used_len];
    last_node->used_len += len;
    return p;
}
