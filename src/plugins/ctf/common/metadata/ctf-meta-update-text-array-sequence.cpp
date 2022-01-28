/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2018 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>
#include "common/macros.h"
#include "common/assert.h"
#include <glib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "ctf-meta-visitors.hpp"

static inline int set_text_array_sequence_field_class(struct ctf_field_class *fc)
{
    int ret = 0;
    uint64_t i;

    if (!fc) {
        goto end;
    }

    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_STRUCT:
    {
        struct ctf_field_class_struct *struct_fc = ctf_field_class_as_struct(fc);

        for (i = 0; i < struct_fc->members->len; i++) {
            struct ctf_named_field_class *named_fc =
                ctf_field_class_struct_borrow_member_by_index(struct_fc, i);

            ret = set_text_array_sequence_field_class(named_fc->fc);
            if (ret) {
                goto end;
            }
        }

        break;
    }
    case CTF_FIELD_CLASS_TYPE_VARIANT:
    {
        struct ctf_field_class_variant *var_fc = ctf_field_class_as_variant(fc);

        for (i = 0; i < var_fc->options->len; i++) {
            struct ctf_named_field_class *named_fc =
                ctf_field_class_variant_borrow_option_by_index(var_fc, i);

            ret = set_text_array_sequence_field_class(named_fc->fc);
            if (ret) {
                goto end;
            }
        }

        break;
    }
    case CTF_FIELD_CLASS_TYPE_ARRAY:
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    {
        struct ctf_field_class_array_base *array_fc = ctf_field_class_as_array_base(fc);

        if (array_fc->elem_fc->type == CTF_FIELD_CLASS_TYPE_INT ||
            array_fc->elem_fc->type == CTF_FIELD_CLASS_TYPE_ENUM) {
            struct ctf_field_class_int *int_fc = ctf_field_class_as_int(array_fc->elem_fc);

            if (int_fc->base.base.alignment == 8 && int_fc->base.size == 8 &&
                int_fc->encoding == CTF_ENCODING_UTF8) {
                array_fc->is_text = true;

                /*
                 * Force integer element to be unsigned;
                 * this makes the decoder enter a single
                 * path when reading a text
                 * array/sequence and we can safely
                 * decode bytes as characters anyway.
                 */
                int_fc->is_signed = false;
            }
        }

        ret = set_text_array_sequence_field_class(array_fc->elem_fc);
        if (ret) {
            goto end;
        }

        break;
    }
    default:
        break;
    }

end:
    return ret;
}

BT_HIDDEN
int ctf_trace_class_update_text_array_sequence(struct ctf_trace_class *ctf_tc)
{
    int ret = 0;
    uint64_t i;

    if (!ctf_tc->is_translated) {
        ret = set_text_array_sequence_field_class(ctf_tc->packet_header_fc);
        if (ret) {
            goto end;
        }
    }

    for (i = 0; i < ctf_tc->stream_classes->len; i++) {
        ctf_stream_class *sc = (ctf_stream_class *) ctf_tc->stream_classes->pdata[i];
        uint64_t j;

        if (!sc->is_translated) {
            ret = set_text_array_sequence_field_class(sc->packet_context_fc);
            if (ret) {
                goto end;
            }

            ret = set_text_array_sequence_field_class(sc->event_header_fc);
            if (ret) {
                goto end;
            }

            ret = set_text_array_sequence_field_class(sc->event_common_context_fc);
            if (ret) {
                goto end;
            }
        }

        for (j = 0; j < sc->event_classes->len; j++) {
            struct ctf_event_class *ec = (ctf_event_class *) sc->event_classes->pdata[j];

            if (ec->is_translated) {
                continue;
            }

            ret = set_text_array_sequence_field_class(ec->spec_context_fc);
            if (ret) {
                goto end;
            }

            ret = set_text_array_sequence_field_class(ec->payload_fc);
            if (ret) {
                goto end;
            }
        }
    }

end:
    return ret;
}
