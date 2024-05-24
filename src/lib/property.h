/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2018 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_LIB_PROPERTY_H
#define BABELTRACE_LIB_PROPERTY_H

#include "common/assert.h"
#include <babeltrace2/babeltrace.h>
#include <glib.h>
#include <stdint.h>

struct bt_property {
	enum bt_property_availability avail;
};

struct bt_property_uint {
	struct bt_property base;
	uint64_t value;
};

static inline
void bt_property_uint_set(struct bt_property_uint *prop, uint64_t value)
{
	BT_ASSERT(prop);
	prop->base.avail = BT_PROPERTY_AVAILABILITY_AVAILABLE;
	prop->value = value;
}

static inline
void bt_property_uint_init(struct bt_property_uint *prop,
		enum bt_property_availability avail, uint64_t value)
{
	BT_ASSERT(prop);
	prop->base.avail = avail;
	prop->value = value;
}

#endif /* BABELTRACE_LIB_PROPERTY_H */
