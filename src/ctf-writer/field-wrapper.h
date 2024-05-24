/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2018 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_CTF_WRITER_FIELD_WRAPPER_H
#define BABELTRACE_CTF_WRITER_FIELD_WRAPPER_H

#include "common/macros.h"

#include "fields.h"
#include "object.h"
#include "object-pool.h"

struct bt_ctf_field_wrapper {
	struct bt_ctf_object base;

	/* Owned by this */
	struct bt_ctf_field_common *field;
};

struct bt_ctf_field_wrapper *bt_ctf_field_wrapper_new(void *data);

void bt_ctf_field_wrapper_destroy(struct bt_ctf_field_wrapper *field);

struct bt_ctf_field_wrapper *bt_ctf_field_wrapper_create(
		struct bt_ctf_object_pool *pool, struct bt_ctf_field_type *ft);

#endif /* BABELTRACE_CTF_WRITER_FIELD_WRAPPER_H */
