/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * Babeltrace CTF writer - Clock
 */

#define BT_LOG_TAG "CTF-WRITER/CLOCK"
#include "logging.h"

#include "common/assert.h"
#include "common/uuid.h"
#include "compat/compiler.h"
#include <babeltrace2-ctf-writer/utils.h>
#include <babeltrace2-ctf-writer/object.h>
#include <inttypes.h>

#include "clock-class.h"
#include "clock.h"
#include "object.h"
#include "writer.h"

static
void bt_ctf_clock_destroy(struct bt_ctf_object *obj);

BT_EXPORT
struct bt_ctf_clock *bt_ctf_clock_create(const char *name)
{
	int ret;
	struct bt_ctf_clock *clock = NULL;
	bt_uuid_t cc_uuid;

	BT_CTF_ASSERT_PRE_NON_NULL(name, "Name");
	clock = g_new0(struct bt_ctf_clock, 1);
	if (!clock) {
		goto error;
	}

	bt_ctf_object_init_shared(&clock->base, bt_ctf_clock_destroy);
	clock->value = 0;

	/* Pre-2.0.0 backward compatibility: default frequency is 1 GHz */
	clock->clock_class = (void *) bt_ctf_clock_class_create(name, 1000000000);
	if (!clock->clock_class) {
		goto error;
	}

	/* Automatically set clock class's UUID. */
	bt_uuid_generate(cc_uuid);

	ret = bt_ctf_clock_class_set_uuid(clock->clock_class, cc_uuid);
	BT_ASSERT_DBG(ret == 0);
	return clock;

error:
	BT_CTF_OBJECT_PUT_REF_AND_RESET(clock);
	return clock;
}

BT_EXPORT
const char *bt_ctf_clock_get_name(struct bt_ctf_clock *clock)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_name(clock->clock_class);
}

BT_EXPORT
const char *bt_ctf_clock_get_description(struct bt_ctf_clock *clock)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_description(clock->clock_class);
}

BT_EXPORT
int bt_ctf_clock_set_description(struct bt_ctf_clock *clock, const char *desc)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_description(clock->clock_class,
		desc);
}

BT_EXPORT
uint64_t bt_ctf_clock_get_frequency(struct bt_ctf_clock *clock)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_frequency(clock->clock_class);
}

BT_EXPORT
int bt_ctf_clock_set_frequency(struct bt_ctf_clock *clock, uint64_t freq)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_frequency(clock->clock_class,
		freq);
}

BT_EXPORT
uint64_t bt_ctf_clock_get_precision(struct bt_ctf_clock *clock)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_precision(clock->clock_class);
}

BT_EXPORT
int bt_ctf_clock_set_precision(struct bt_ctf_clock *clock, uint64_t precision)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_precision(clock->clock_class,
		precision);
}

BT_EXPORT
int bt_ctf_clock_get_offset_s(struct bt_ctf_clock *clock, int64_t *offset_s)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_offset_s(clock->clock_class,
		offset_s);
}

BT_EXPORT
int bt_ctf_clock_set_offset_s(struct bt_ctf_clock *clock, int64_t offset_s)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_offset_s(clock->clock_class,
		offset_s);
}

BT_EXPORT
int bt_ctf_clock_get_offset(struct bt_ctf_clock *clock, int64_t *offset)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_offset_cycles(clock->clock_class,
		offset);
}

BT_EXPORT
int bt_ctf_clock_set_offset(struct bt_ctf_clock *clock, int64_t offset)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_offset_cycles(clock->clock_class,
		offset);
}

BT_EXPORT
int bt_ctf_clock_get_is_absolute(struct bt_ctf_clock *clock)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_is_absolute(clock->clock_class);
}

BT_EXPORT
int bt_ctf_clock_set_is_absolute(struct bt_ctf_clock *clock, int is_absolute)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_is_absolute(clock->clock_class,
		is_absolute);
}

BT_EXPORT
const uint8_t *bt_ctf_clock_get_uuid(struct bt_ctf_clock *clock)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_get_uuid(clock->clock_class);
}

BT_EXPORT
int bt_ctf_clock_set_uuid(struct bt_ctf_clock *clock, const uint8_t *uuid)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	return bt_ctf_clock_class_set_uuid(clock->clock_class, uuid);
}

BT_EXPORT
int bt_ctf_clock_set_time(struct bt_ctf_clock *clock, int64_t time)
{
	int64_t value;
	struct bt_ctf_clock_class *cc;

	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	cc = clock->clock_class;

	/* Common case where cycles are actually nanoseconds */
	if (cc->frequency == 1000000000) {
		value = time;
	} else {
		value = (uint64_t) (((double) time *
		        (double) cc->frequency) / 1e9);
	}

	BT_CTF_ASSERT_PRE(clock->value <= value,
		"CTF writer clock value must be updated monotonically: "
		"prev-value=%" PRId64 ", new-value=%" PRId64,
		clock->value, value);
	clock->value = value;
	return 0;
}

int bt_ctf_clock_get_value(struct bt_ctf_clock *clock, uint64_t *value)
{
	BT_CTF_ASSERT_PRE_NON_NULL(clock, "CTF writer clock");
	BT_CTF_ASSERT_PRE_NON_NULL(value, "Value");
	*value = clock->value;
	return 0;
}

static
void bt_ctf_clock_destroy(struct bt_ctf_object *obj)
{
	struct bt_ctf_clock *clock;

	clock = container_of(obj, struct bt_ctf_clock, base);
	bt_ctf_object_put_ref(clock->clock_class);
	g_free(clock);
}

void bt_ctf_clock_class_serialize(struct bt_ctf_clock_class *clock_class,
		struct metadata_context *context)
{
	uint8_t *uuid;

	BT_LOGD("Serializing clock class's metadata: clock-class-addr=%p, "
		"name=\"%s\", metadata-context-addr=%p", clock_class,
		bt_ctf_clock_class_get_name(clock_class),
		context);

	if (!clock_class || !context) {
		BT_LOGW("Invalid parameter: clock class or metadata context is NULL: "
			"clock-class-addr=%p, name=\"%s\", metadata-context-addr=%p",
			clock_class,
			bt_ctf_clock_class_get_name(clock_class),
			context);
		return;
	}

	uuid = clock_class->uuid;
	g_string_append(context->string, "clock {\n");
	g_string_append_printf(context->string, "\tname = %s;\n",
		clock_class->name->str);

	if (clock_class->uuid_set) {
		g_string_append_printf(context->string,
			"\tuuid = \"" BT_UUID_FMT "\";\n",
			BT_UUID_FMT_VALUES(uuid));
	}

	if (clock_class->description) {
		g_string_append_printf(context->string, "\tdescription = \"%s\";\n",
			clock_class->description->str);
	}

	g_string_append_printf(context->string, "\tfreq = %" PRIu64 ";\n",
		clock_class->frequency);
	g_string_append_printf(context->string, "\tprecision = %" PRIu64 ";\n",
		clock_class->precision);
	g_string_append_printf(context->string, "\toffset_s = %" PRIu64 ";\n",
		clock_class->offset_s);
	g_string_append_printf(context->string, "\toffset = %" PRIu64 ";\n",
		clock_class->offset);
	g_string_append_printf(context->string, "\tabsolute = %s;\n",
		clock_class->absolute ? "true" : "false");
	g_string_append(context->string, "};\n\n");
}
