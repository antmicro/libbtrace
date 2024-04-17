/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "common/common.h"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "ctf-meta-visitors.hpp"

using field_class_stack_t = GPtrArray;

/*
 * A stack frame.
 *
 * `fc` contains a compound field class (structure, variant, array,
 * or sequence) and `index` indicates the index of the field class in
 * the upper frame (-1 for array and sequence field classes). `name`
 * indicates the name of the field class in the upper frame (empty
 * string for array and sequence field classes).
 */
struct field_class_stack_frame
{
    struct ctf_field_class *fc;
    int64_t index;
};

/*
 * The current context of the resolving engine.
 */
struct resolve_context
{
    explicit resolve_context(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/CTF/META/RESOLVE"}
    {
    }

    bt2c::Logger logger;

    struct ctf_trace_class *tc = nullptr;
    struct ctf_stream_class *sc = nullptr;
    struct ctf_event_class *ec = nullptr;

    struct
    {
        struct ctf_field_class *packet_header = nullptr;
        struct ctf_field_class *packet_context = nullptr;
        struct ctf_field_class *event_header = nullptr;
        struct ctf_field_class *event_common_context = nullptr;
        struct ctf_field_class *event_spec_context = nullptr;
        struct ctf_field_class *event_payload = nullptr;
    } scopes;

    /* Root scope being visited */
    enum ctf_scope root_scope = CTF_SCOPE_PACKET_HEADER;
    field_class_stack_t *field_class_stack = nullptr;
    struct ctf_field_class *cur_fc = nullptr;
};

/* TSDL dynamic scope prefixes as defined in CTF Section 7.3.2 */
static const char * const absolute_path_prefixes[] = {
    /* CTF_SCOPE_PACKET_HEADER */ "trace.packet.header.",
    /* CTF_SCOPE_PACKET_CONTEXT */ "stream.packet.context.",
    /* CTF_SCOPE_EVENT_HEADER */ "stream.event.header.",
    /* CTF_SCOPE_EVENT_COMMON_CONTEXT */ "stream.event.context.",
    /* CTF_SCOPE_EVENT_SPECIFIC_CONTEXT */ "event.context.",
    /* CTF_SCOPE_EVENT_PAYLOAD */ "event.fields.",
};

/* Number of path tokens used for the absolute prefixes */
static const uint64_t absolute_path_prefix_ptoken_counts[] = {
    /* CTF_SCOPE_PACKET_HEADER */ 3,
    /* CTF_SCOPE_PACKET_CONTEXT */ 3,
    /* CTF_SCOPE_EVENT_HEADER */ 3,
    /* CTF_SCOPE_EVENT_COMMON_CONTEXT */ 3,
    /* CTF_SCOPE_EVENT_SPECIFIC_CONTEXT */ 2,
    /* CTF_SCOPE_EVENT_PAYLOAD */ 2,
};

static void destroy_field_class_stack_frame(struct field_class_stack_frame *frame)
{
    if (!frame) {
        return;
    }

    g_free(frame);
}

/*
 * Creates a class stack.
 */
static field_class_stack_t *field_class_stack_create(void)
{
    return g_ptr_array_new_with_free_func((GDestroyNotify) destroy_field_class_stack_frame);
}

/*
 * Destroys a class stack.
 */
static void field_class_stack_destroy(field_class_stack_t *stack)
{
    if (stack) {
        g_ptr_array_free(stack, TRUE);
    }
}

/*
 * Pushes a field class onto a class stack.
 */
static int field_class_stack_push(field_class_stack_t *stack, struct ctf_field_class *fc,
                                  struct resolve_context *ctx)
{
    int ret = 0;
    struct field_class_stack_frame *frame = NULL;

    if (!stack || !fc) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Invalid parameter: stack or field class is `NULL`.");
        ret = -1;
        goto end;
    }

    frame = g_new0(struct field_class_stack_frame, 1);
    if (!frame) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Failed to allocate one field class stack frame.");
        ret = -1;
        goto end;
    }

    BT_CPPLOGD_SPEC(ctx->logger,
                    "Pushing field class on context's stack: "
                    "fc-addr={}, stack-size-before={}",
                    fmt::ptr(fc), stack->len);
    frame->fc = fc;
    g_ptr_array_add(stack, frame);

end:
    return ret;
}

/*
 * Checks whether or not `stack` is empty.
 */
static bool field_class_stack_empty(field_class_stack_t *stack)
{
    return stack->len == 0;
}

/*
 * Returns the number of frames in `stack`.
 */
static size_t field_class_stack_size(field_class_stack_t *stack)
{
    return stack->len;
}

/*
 * Returns the top frame of `stack`.
 */
static struct field_class_stack_frame *field_class_stack_peek(field_class_stack_t *stack)
{
    BT_ASSERT(stack);
    BT_ASSERT(!field_class_stack_empty(stack));

    return (field_class_stack_frame *) g_ptr_array_index(stack, stack->len - 1);
}

/*
 * Returns the frame at index `index` in `stack`.
 */
static struct field_class_stack_frame *field_class_stack_at(field_class_stack_t *stack,
                                                            size_t index)
{
    BT_ASSERT(stack);
    BT_ASSERT(index < stack->len);

    return (field_class_stack_frame *) g_ptr_array_index(stack, index);
}

/*
 * Removes the top frame of `stack`.
 */
static void field_class_stack_pop(field_class_stack_t *stack, struct resolve_context *ctx)
{
    if (!field_class_stack_empty(stack)) {
        /*
         * This will call the frame's destructor and free it, as
         * well as put its contained field class.
         */
        BT_CPPLOGD_SPEC(ctx->logger, "Popping context's stack: stack-size-before={}", stack->len);
        g_ptr_array_set_size(stack, stack->len - 1);
    }
}

/*
 * Returns the scope field class of `scope` in the context `ctx`.
 */
static struct ctf_field_class *borrow_class_from_ctx(struct resolve_context *ctx,
                                                     enum ctf_scope scope)
{
    switch (scope) {
    case CTF_SCOPE_PACKET_HEADER:
        return ctx->scopes.packet_header;
    case CTF_SCOPE_PACKET_CONTEXT:
        return ctx->scopes.packet_context;
    case CTF_SCOPE_EVENT_HEADER:
        return ctx->scopes.event_header;
    case CTF_SCOPE_EVENT_COMMON_CONTEXT:
        return ctx->scopes.event_common_context;
    case CTF_SCOPE_EVENT_SPECIFIC_CONTEXT:
        return ctx->scopes.event_spec_context;
    case CTF_SCOPE_EVENT_PAYLOAD:
        return ctx->scopes.event_payload;
    default:
        bt_common_abort();
    }

    return NULL;
}

/*
 * Returns the CTF scope from a path string. May return -1 if the path
 * is found to be relative.
 */
static enum ctf_scope get_root_scope_from_absolute_pathstr(const char *pathstr,
                                                           struct resolve_context *ctx)
{
    enum ctf_scope scope;
    enum ctf_scope ret = CTF_SCOPE_PACKET_UNKNOWN;
    const size_t prefixes_count = sizeof(absolute_path_prefixes) / sizeof(*absolute_path_prefixes);

    for (scope = CTF_SCOPE_PACKET_HEADER; scope < CTF_SCOPE_PACKET_HEADER + prefixes_count;
         scope = (ctf_scope) (scope + 1)) {
        /*
         * Check if path string starts with a known absolute
         * path prefix.
         *
         * Refer to CTF 7.3.2 STATIC AND DYNAMIC SCOPES.
         */
        if (strncmp(pathstr, absolute_path_prefixes[scope],
                    strlen(absolute_path_prefixes[scope]))) {
            /* Prefix does not match: try the next one */
            BT_CPPLOGD_SPEC(ctx->logger,
                            "Prefix does not match: trying the next one: "
                            "path=\"{}\", path-prefix=\"{}\", scope={}",
                            pathstr, absolute_path_prefixes[scope], scope);
            continue;
        }

        /* Found it! */
        ret = scope;
        BT_CPPLOGD_SPEC(ctx->logger,
                        "Found root scope from absolute path: "
                        "path=\"{}\", scope={}",
                        pathstr, scope);
        goto end;
    }

end:
    return ret;
}

/*
 * Destroys a path token.
 */
static void ptokens_destroy_func(gpointer ptoken, gpointer)
{
    g_string_free((GString *) ptoken, TRUE);
}

/*
 * Destroys a path token list.
 */
static void ptokens_destroy(GList *ptokens)
{
    if (!ptokens) {
        return;
    }

    g_list_foreach(ptokens, ptokens_destroy_func, NULL);
    g_list_free(ptokens);
}

/*
 * Returns the string contained in a path token.
 */
static const char *ptoken_get_string(GList *ptoken)
{
    GString *tokenstr = (GString *) ptoken->data;

    return tokenstr->str;
}

/*
 * Converts a path string to a path token list, that is, splits the
 * individual words of a path string into a list of individual
 * strings.
 */
static GList *pathstr_to_ptokens(const char *pathstr, struct resolve_context *ctx)
{
    const char *at = pathstr;
    const char *last = at;
    GList *ptokens = NULL;

    for (;;) {
        if (*at == '.' || *at == '\0') {
            GString *tokenstr;

            if (at == last) {
                /* Error: empty token */
                BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger, "Empty path token: path=\"{}\", pos={}",
                                             pathstr, (unsigned int) (at - pathstr));
                goto error;
            }

            tokenstr = g_string_new(NULL);
            g_string_append_len(tokenstr, last, at - last);
            ptokens = g_list_append(ptokens, tokenstr);
            last = at + 1;
        }

        if (*at == '\0') {
            break;
        }

        at++;
    }

    return ptokens;

error:
    ptokens_destroy(ptokens);
    return NULL;
}

/*
 * Converts a path token list to a field path object. The path token
 * list is relative from `fc`. The index of the source looking for its
 * target within `fc` is indicated by `src_index`. This can be
 * `INT64_MAX` if the source is contained in `fc`.
 *
 * `field_path` is an output parameter owned by the caller that must be
 * filled here.
 */
static int ptokens_to_field_path(GList *ptokens, struct ctf_field_path *field_path,
                                 struct ctf_field_class *fc, int64_t src_index,
                                 struct resolve_context *ctx)
{
    int ret = 0;
    GList *cur_ptoken = ptokens;
    bool first_level_done = false;

    /* Locate target */
    while (cur_ptoken) {
        int64_t child_index;
        struct ctf_field_class *child_fc;
        const char *ft_name = ptoken_get_string(cur_ptoken);

        BT_CPPLOGD_SPEC(ctx->logger, "Current path token: token=\"{}\"", ft_name);

        /* Find to which index corresponds the current path token */
        if (fc->type == CTF_FIELD_CLASS_TYPE_ARRAY || fc->type == CTF_FIELD_CLASS_TYPE_SEQUENCE) {
            child_index = -1;
        } else {
            child_index =
                ctf_field_class_compound_get_field_class_index_from_orig_name(fc, ft_name);
            if (child_index < 0) {
                /*
                 * Error: field name does not exist or
                 * wrong current class.
                 */
                BT_CPPLOGD_SPEC(ctx->logger,
                                "Cannot get index of field class: "
                                "field-name=\"{}\", "
                                "src-index={}, "
                                "child-index={}, "
                                "first-level-done={}",
                                ft_name, src_index, child_index, first_level_done);
                ret = -1;
                goto end;
            } else if (child_index > src_index && !first_level_done) {
                BT_CPPLOGD_SPEC(ctx->logger,
                                "Child field class is located after source field class: "
                                "field-name=\"{}\", "
                                "src-index={}, "
                                "child-index={}, "
                                "first-level-done={}",
                                ft_name, src_index, child_index, first_level_done);
                ret = -1;
                goto end;
            }

            /* Next path token */
            cur_ptoken = g_list_next(cur_ptoken);
            first_level_done = true;
        }

        /* Create new field path entry */
        ctf_field_path_append_index(field_path, child_index);

        /* Get child field class */
        child_fc = ctf_field_class_compound_borrow_field_class_by_index(fc, child_index);
        BT_ASSERT(child_fc);

        /* Move child class to current class */
        fc = child_fc;
    }

end:
    return ret;
}

/*
 * Converts a known absolute path token list to a field path object
 * within the resolving context `ctx`.
 *
 * `field_path` is an output parameter owned by the caller that must be
 * filled here.
 */
static int absolute_ptokens_to_field_path(GList *ptokens, struct ctf_field_path *field_path,
                                          struct resolve_context *ctx)
{
    int ret = 0;
    GList *cur_ptoken;
    struct ctf_field_class *fc;

    /*
     * Make sure we're not referring to a scope within a translated
     * object.
     */
    switch (field_path->root) {
    case CTF_SCOPE_PACKET_HEADER:
        if (ctx->tc->is_translated) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Trace class is already translated: "
                                         "root-scope={}",
                                         field_path->root);
            ret = -1;
            goto end;
        }

        break;
    case CTF_SCOPE_PACKET_CONTEXT:
    case CTF_SCOPE_EVENT_HEADER:
    case CTF_SCOPE_EVENT_COMMON_CONTEXT:
        if (!ctx->sc) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "No current stream class: "
                                         "root-scope={}",
                                         field_path->root);
            ret = -1;
            goto end;
        }

        if (ctx->sc->is_translated) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Stream class is already translated: "
                                         "root-scope={}",
                                         field_path->root);
            ret = -1;
            goto end;
        }

        break;
    case CTF_SCOPE_EVENT_SPECIFIC_CONTEXT:
    case CTF_SCOPE_EVENT_PAYLOAD:
        if (!ctx->ec) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "No current event class: "
                                         "root-scope={}",
                                         field_path->root);
            ret = -1;
            goto end;
        }

        if (ctx->ec->is_translated) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Event class is already translated: "
                                         "root-scope={}",
                                         field_path->root);
            ret = -1;
            goto end;
        }

        break;

    default:
        bt_common_abort();
    }

    /* Skip absolute path tokens */
    cur_ptoken = g_list_nth(ptokens, absolute_path_prefix_ptoken_counts[field_path->root]);

    /* Start with root class */
    fc = borrow_class_from_ctx(ctx, field_path->root);
    if (!fc) {
        /* Error: root class is not available */
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Root field class is not available: "
                                     "root-scope={}",
                                     field_path->root);
        ret = -1;
        goto end;
    }

    /* Locate target */
    ret = ptokens_to_field_path(cur_ptoken, field_path, fc, INT64_MAX, ctx);

end:
    return ret;
}

/*
 * Converts a known relative path token list to a field path object
 * within the resolving context `ctx`.
 *
 * `field_path` is an output parameter owned by the caller that must be
 * filled here.
 */
static int relative_ptokens_to_field_path(GList *ptokens, struct ctf_field_path *field_path,
                                          struct resolve_context *ctx)
{
    int ret = 0;
    int64_t parent_pos_in_stack;
    struct ctf_field_path tail_field_path;

    ctf_field_path_init(&tail_field_path);
    parent_pos_in_stack = field_class_stack_size(ctx->field_class_stack) - 1;

    while (parent_pos_in_stack >= 0) {
        struct ctf_field_class *parent_class =
            field_class_stack_at(ctx->field_class_stack, parent_pos_in_stack)->fc;
        int64_t cur_index =
            field_class_stack_at(ctx->field_class_stack, parent_pos_in_stack)->index;

        BT_CPPLOGD_SPEC(ctx->logger,
                        "Locating target field class from current parent field class: "
                        "parent-pos={}, parent-fc-addr={}, "
                        "cur-index={}",
                        parent_pos_in_stack, fmt::ptr(parent_class), cur_index);

        /* Locate target from current parent class */
        ret = ptokens_to_field_path(ptokens, &tail_field_path, parent_class, cur_index, ctx);
        if (ret) {
            /* Not found... yet */
            BT_CPPLOGD_STR_SPEC(ctx->logger, "Not found at this point.");
            ctf_field_path_clear(&tail_field_path);
        } else {
            /* Found: stitch tail field path to head field path */
            uint64_t i = 0;
            size_t tail_field_path_len = tail_field_path.path->len;

            while (BT_TRUE) {
                struct ctf_field_class *cur_class =
                    field_class_stack_at(ctx->field_class_stack, i)->fc;
                int64_t index = field_class_stack_at(ctx->field_class_stack, i)->index;

                if (cur_class == parent_class) {
                    break;
                }

                ctf_field_path_append_index(field_path, index);
                i++;
            }

            for (i = 0; i < tail_field_path_len; i++) {
                int64_t index = ctf_field_path_borrow_index_by_index(&tail_field_path, i);

                ctf_field_path_append_index(field_path, (int64_t) index);
            }
            break;
        }

        parent_pos_in_stack--;
    }

    if (parent_pos_in_stack < 0) {
        /* Not found */
        ret = -1;
    }

    ctf_field_path_fini(&tail_field_path);
    return ret;
}

/*
 * Converts a path string to a field path object within the resolving
 * context `ctx`.
 */
static int pathstr_to_field_path(const char *pathstr, struct ctf_field_path *field_path,
                                 struct resolve_context *ctx)
{
    int ret = 0;
    enum ctf_scope root_scope;
    GList *ptokens = NULL;

    /* Convert path string to path tokens */
    ptokens = pathstr_to_ptokens(pathstr, ctx);
    if (!ptokens) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Cannot convert path string to path tokens: "
                                     "path=\"{}\"",
                                     pathstr);
        ret = -1;
        goto end;
    }

    /* Absolute or relative path? */
    root_scope = get_root_scope_from_absolute_pathstr(pathstr, ctx);

    if (root_scope == CTF_SCOPE_PACKET_UNKNOWN) {
        /* Relative path: start with current root scope */
        field_path->root = ctx->root_scope;
        BT_CPPLOGD_SPEC(ctx->logger,
                        "Detected relative path: starting with current root scope: "
                        "scope={}",
                        field_path->root);
        ret = relative_ptokens_to_field_path(ptokens, field_path, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot get relative field path of path string: "
                                         "path=\"{}\", start-scope={}, end-scope={}",
                                         pathstr, ctx->root_scope, field_path->root);
            goto end;
        }
    } else {
        /* Absolute path: use found root scope */
        field_path->root = root_scope;
        BT_CPPLOGD_SPEC(ctx->logger,
                        "Detected absolute path: using root scope: "
                        "scope={}",
                        field_path->root);
        ret = absolute_ptokens_to_field_path(ptokens, field_path, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot get absolute field path of path string: "
                                         "path=\"{}\", root-scope={}",
                                         pathstr, root_scope);
            goto end;
        }
    }

    if (ret == 0) {
        BT_CPPLOGD_SPEC(ctx->logger, "Found field path: path=\"{}\", field-path=\"{}\"", pathstr,
                        *field_path);
    }

end:
    ptokens_destroy(ptokens);
    return ret;
}

/*
 * Retrieves a field class by following the field path `field_path` in
 * the resolving context `ctx`.
 */
static struct ctf_field_class *field_path_to_field_class(struct ctf_field_path *field_path,
                                                         struct resolve_context *ctx)
{
    uint64_t i;
    struct ctf_field_class *fc;

    /* Start with root class */
    fc = borrow_class_from_ctx(ctx, field_path->root);
    if (!fc) {
        /* Error: root class is not available */
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            ctx->logger, "Root field class is not available: root-scope={}", field_path->root);
        goto end;
    }

    /* Locate target */
    for (i = 0; i < field_path->path->len; i++) {
        struct ctf_field_class *child_fc;
        int64_t child_index = ctf_field_path_borrow_index_by_index(field_path, i);

        /* Get child field class */
        child_fc = ctf_field_class_compound_borrow_field_class_by_index(fc, child_index);
        BT_ASSERT(child_fc);

        /* Move child class to current class */
        fc = child_fc;
    }

end:
    return fc;
}

/*
 * Fills the equivalent field path object of the context class stack.
 */
static void get_ctx_stack_field_path(struct resolve_context *ctx, struct ctf_field_path *field_path)
{
    uint64_t i;

    BT_ASSERT(field_path);
    field_path->root = ctx->root_scope;
    ctf_field_path_clear(field_path);

    for (i = 0; i < field_class_stack_size(ctx->field_class_stack); i++) {
        struct field_class_stack_frame *frame = field_class_stack_at(ctx->field_class_stack, i);

        ctf_field_path_append_index(field_path, frame->index);
    }
}

/*
 * Returns the index of the lowest common ancestor of two field path
 * objects having the same root scope.
 */
static int64_t get_field_paths_lca_index(struct ctf_field_path *field_path1,
                                         struct ctf_field_path *field_path2,
                                         struct resolve_context *ctx)
{
    int64_t lca_index = 0;
    uint64_t field_path1_len, field_path2_len;

    BT_CPPLOGD_SPEC(ctx->logger,
                    "Finding lowest common ancestor (LCA) between two field paths: "
                    "field-path-1=\"{}\", field-path-2=\"{}\"",
                    *field_path1, *field_path2);

    /*
     * Start from both roots and find the first mismatch.
     */
    BT_ASSERT(field_path1->root == field_path2->root);
    field_path1_len = field_path1->path->len;
    field_path2_len = field_path2->path->len;

    while (true) {
        int64_t target_index, ctx_index;

        if (lca_index == (int64_t) field_path2_len || lca_index == (int64_t) field_path1_len) {
            /*
             * This means that both field paths never split.
             * This is invalid because the target cannot be
             * an ancestor of the source.
             */
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                ctx->logger,
                "Source field class is an ancestor of target field class or vice versa: "
                "lca-index={}, "
                "field-path-1-len={}, "
                "field-path-2-len={}",
                lca_index, field_path1_len, field_path2_len);
            lca_index = -1;
            break;
        }

        target_index = ctf_field_path_borrow_index_by_index(field_path1, lca_index);
        ctx_index = ctf_field_path_borrow_index_by_index(field_path2, lca_index);

        if (target_index != ctx_index) {
            /* LCA index is the previous */
            break;
        }

        lca_index++;
    }

    BT_CPPLOGD_SPEC(ctx->logger, "Found LCA: lca-index={}", lca_index);
    return lca_index;
}

/*
 * Validates a target field path.
 */
static int validate_target_field_path(struct ctf_field_path *target_field_path,
                                      struct ctf_field_class *target_fc,
                                      struct resolve_context *ctx)
{
    int ret = 0;
    struct ctf_field_path ctx_field_path;
    uint64_t target_field_path_len = target_field_path->path->len;
    int64_t lca_index;

    /* Get context field path */
    ctf_field_path_init(&ctx_field_path);
    get_ctx_stack_field_path(ctx, &ctx_field_path);

    /*
     * Make sure the target is not a root.
     */
    if (target_field_path_len == 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Target field path's length is 0 (targeting the root).");
        ret = -1;
        goto end;
    }

    /*
     * Make sure the root of the target field path is not located
     * after the context field path's root.
     */
    if (target_field_path->root > ctx_field_path.root) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Target field class is located after source field class: "
                                     "target-root={}, source-root={}",
                                     target_field_path->root, ctx_field_path.root);
        ret = -1;
        goto end;
    }

    if (target_field_path->root == ctx_field_path.root) {
        int64_t target_index, ctx_index;

        /*
         * Find the index of the lowest common ancestor of both field
         * paths.
         */
        lca_index = get_field_paths_lca_index(target_field_path, &ctx_field_path, ctx);
        if (lca_index < 0) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger, "Cannot get least common ancestor.");
            ret = -1;
            goto end;
        }

        /*
         * Make sure the target field path is located before the
         * context field path.
         */
        target_index =
            ctf_field_path_borrow_index_by_index(target_field_path, (uint64_t) lca_index);
        ctx_index = ctf_field_path_borrow_index_by_index(&ctx_field_path, (uint64_t) lca_index);

        if (target_index >= ctx_index) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                ctx->logger,
                "Target field class's index is greater than or equal to source field class's index in LCA: "
                "lca-index={}, "
                "target-index={}, "
                "source-index={}",
                lca_index, target_index, ctx_index);
            ret = -1;
            goto end;
        }
    }

    /*
     * Make sure the target class has the right class and properties.
     */
    switch (ctx->cur_fc->type) {
    case CTF_FIELD_CLASS_TYPE_VARIANT:
        if (target_fc->type != CTF_FIELD_CLASS_TYPE_ENUM) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                ctx->logger,
                "Variant field class's tag field class is not an enumeration field class: "
                "tag-fc-addr={}, tag-fc-id={}",
                fmt::ptr(target_fc), (int) target_fc->type);
            ret = -1;
            goto end;
        }
        break;
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    {
        if (target_fc->type != CTF_FIELD_CLASS_TYPE_INT &&
            target_fc->type != CTF_FIELD_CLASS_TYPE_ENUM) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                ctx->logger,
                "Sequence field class's length field class is not an unsigned integer field class: "
                "length-fc-addr={}, length-fc-id={}",
                fmt::ptr(target_fc), (int) target_fc->type);
            ret = -1;
            goto end;
        }

        ctf_field_class_int *int_fc = ctf_field_class_as_int(target_fc);

        if (int_fc->is_signed) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                ctx->logger,
                "Sequence field class's length field class is not an unsigned integer field class: "
                "length-fc-addr={}, length-fc-id={}",
                fmt::ptr(target_fc), (int) target_fc->type);
            ret = -1;
            goto end;
        }
        break;
    }
    default:
        bt_common_abort();
    }

end:
    ctf_field_path_fini(&ctx_field_path);
    return ret;
}

/*
 * Resolves a variant or sequence field class `fc`.
 */
static int resolve_sequence_or_variant_field_class(struct ctf_field_class *fc,
                                                   struct resolve_context *ctx)
{
    int ret = 0;
    const char *pathstr;
    struct ctf_field_path target_field_path;
    struct ctf_field_class *target_fc = NULL;

    ctf_field_path_init(&target_field_path);

    /* Get path string */
    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    {
        struct ctf_field_class_sequence *seq_fc = ctf_field_class_as_sequence(fc);
        pathstr = seq_fc->length_ref->str;
        break;
    }
    case CTF_FIELD_CLASS_TYPE_VARIANT:
    {
        struct ctf_field_class_variant *var_fc = ctf_field_class_as_variant(fc);
        pathstr = var_fc->tag_ref->str;
        break;
    }
    default:
        bt_common_abort();
    }

    if (!pathstr) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger, "Cannot get path string.");
        ret = -1;
        goto end;
    }

    /* Get target field path out of path string */
    ret = pathstr_to_field_path(pathstr, &target_field_path, ctx);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Cannot get target field path for path string: "
                                     "path=\"{}\"",
                                     pathstr);
        goto end;
    }

    /* Get target field class */
    target_fc = field_path_to_field_class(&target_field_path, ctx);
    if (!target_fc) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Cannot get target field class for path string: "
                                     "path=\"{}\", target-field-path=\"{}\"",
                                     pathstr, target_field_path);
        ret = -1;
        goto end;
    }

    ret = validate_target_field_path(&target_field_path, target_fc, ctx);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Invalid target field path for path string: "
                                     "path=\"{}\", target-field-path=\"{}\"",
                                     pathstr, target_field_path);
        goto end;
    }

    /* Set target field path and target field class */
    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    {
        ctf_field_class_sequence *seq_fc = ctf_field_class_as_sequence(fc);

        ctf_field_path_copy_content(&seq_fc->length_path, &target_field_path);
        seq_fc->length_fc = ctf_field_class_as_int(target_fc);
        break;
    }
    case CTF_FIELD_CLASS_TYPE_VARIANT:
    {
        ctf_field_class_variant *var_fc = ctf_field_class_as_variant(fc);

        ctf_field_path_copy_content(&var_fc->tag_path, &target_field_path);
        ctf_field_class_variant_set_tag_field_class(var_fc, ctf_field_class_as_enum(target_fc));
        break;
    }
    default:
        bt_common_abort();
    }

end:
    ctf_field_path_fini(&target_field_path);
    return ret;
}

/*
 * Resolves a field class `fc`.
 */
static int resolve_field_class(struct ctf_field_class *fc, struct resolve_context *ctx)
{
    int ret = 0;

    if (!fc) {
        /* Field class is not available; still valid */
        goto end;
    }

    ctx->cur_fc = fc;

    /* Resolve sequence/variant field class */
    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    case CTF_FIELD_CLASS_TYPE_VARIANT:
        ret = resolve_sequence_or_variant_field_class(fc, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                ctx->logger,
                "Cannot resolve sequence field class's length or variant field class's tag: "
                "ret={}, fc-addr={}",
                ret, fmt::ptr(fc));
            goto end;
        }

        break;
    default:
        break;
    }

    /* Recurse into compound classes */
    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_STRUCT:
    case CTF_FIELD_CLASS_TYPE_VARIANT:
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    case CTF_FIELD_CLASS_TYPE_ARRAY:
    {
        uint64_t i;
        uint64_t field_count = ctf_field_class_compound_get_field_class_count(fc);

        ret = field_class_stack_push(ctx->field_class_stack, fc, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot push field class on context's stack: "
                                         "fc-addr={}",
                                         fmt::ptr(fc));
            goto end;
        }

        for (i = 0; i < field_count; i++) {
            struct ctf_field_class *child_fc =
                ctf_field_class_compound_borrow_field_class_by_index(fc, i);

            BT_ASSERT(child_fc);

            if (fc->type == CTF_FIELD_CLASS_TYPE_ARRAY ||
                fc->type == CTF_FIELD_CLASS_TYPE_SEQUENCE) {
                field_class_stack_peek(ctx->field_class_stack)->index = -1;
            } else {
                field_class_stack_peek(ctx->field_class_stack)->index = (int64_t) i;
            }

            BT_CPPLOGD_SPEC(ctx->logger,
                            "Resolving field class's child field class: "
                            "parent-fc-addr={}, child-fc-addr={}, "
                            "index={}, count={}",
                            fmt::ptr(fc), fmt::ptr(child_fc), i, field_count);
            ret = resolve_field_class(child_fc, ctx);
            if (ret) {
                goto end;
            }
        }

        field_class_stack_pop(ctx->field_class_stack, ctx);
        break;
    }
    default:
        break;
    }

end:
    return ret;
}

/*
 * Resolves the root field class corresponding to the scope `root_scope`.
 */
static int resolve_root_class(enum ctf_scope root_scope, struct resolve_context *ctx)
{
    int ret;

    BT_ASSERT(field_class_stack_size(ctx->field_class_stack) == 0);
    ctx->root_scope = root_scope;
    ret = resolve_field_class(borrow_class_from_ctx(ctx, root_scope), ctx);
    ctx->root_scope = CTF_SCOPE_PACKET_UNKNOWN;
    return ret;
}

static int resolve_event_class_field_classes(struct resolve_context *ctx,
                                             struct ctf_event_class *ec)
{
    int ret = 0;

    BT_ASSERT(!ctx->scopes.event_spec_context);
    BT_ASSERT(!ctx->scopes.event_payload);

    if (ec->is_translated) {
        goto end;
    }

    ctx->ec = ec;
    ctx->scopes.event_spec_context = ec->spec_context_fc;
    ret = resolve_root_class(CTF_SCOPE_EVENT_COMMON_CONTEXT, ctx);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Cannot resolve event specific context field class: "
                                     "ret={}",
                                     ret);
        goto end;
    }

    ctx->scopes.event_payload = ec->payload_fc;
    ret = resolve_root_class(CTF_SCOPE_EVENT_PAYLOAD, ctx);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                     "Cannot resolve event payload field class: "
                                     "ret={}",
                                     ret);
        goto end;
    }

end:
    ctx->scopes.event_spec_context = NULL;
    ctx->scopes.event_payload = NULL;
    ctx->ec = NULL;
    return ret;
}

static int resolve_stream_class_field_classes(struct resolve_context *ctx,
                                              struct ctf_stream_class *sc)
{
    int ret = 0;
    uint64_t i;

    BT_ASSERT(!ctx->scopes.packet_context);
    BT_ASSERT(!ctx->scopes.event_header);
    BT_ASSERT(!ctx->scopes.event_common_context);
    ctx->sc = sc;

    if (!sc->is_translated) {
        ctx->scopes.packet_context = sc->packet_context_fc;
        ret = resolve_root_class(CTF_SCOPE_PACKET_CONTEXT, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot resolve packet context field class: "
                                         "ret={}",
                                         ret);
            goto end;
        }

        ctx->scopes.event_header = sc->event_header_fc;
        ret = resolve_root_class(CTF_SCOPE_EVENT_HEADER, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot resolve event header field class: "
                                         "ret={}",
                                         ret);
            goto end;
        }

        ctx->scopes.event_common_context = sc->event_common_context_fc;
        ret = resolve_root_class(CTF_SCOPE_EVENT_COMMON_CONTEXT, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot resolve event common context field class: "
                                         "ret={}",
                                         ret);
            goto end;
        }
    }

    ctx->scopes.packet_context = sc->packet_context_fc;
    ctx->scopes.event_header = sc->event_header_fc;
    ctx->scopes.event_common_context = sc->event_common_context_fc;

    for (i = 0; i < sc->event_classes->len; i++) {
        ctf_event_class *ec = (ctf_event_class *) sc->event_classes->pdata[i];

        ret = resolve_event_class_field_classes(ctx, ec);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot resolve event class's field classes: "
                                         "ec-id={}, ec-name=\"{}\"",
                                         ec->id, ec->name->str);
            goto end;
        }
    }

end:
    ctx->scopes.packet_context = NULL;
    ctx->scopes.event_header = NULL;
    ctx->scopes.event_common_context = NULL;
    ctx->sc = NULL;
    return ret;
}

int ctf_trace_class_resolve_field_classes(struct ctf_trace_class *tc,
                                          const bt2c::Logger& parentLogger)
{
    int ret = 0;
    uint64_t i;

    resolve_context local_ctx(parentLogger);
    local_ctx.tc = tc;
    local_ctx.scopes.packet_header = tc->packet_header_fc;
    local_ctx.root_scope = CTF_SCOPE_PACKET_HEADER;

    struct resolve_context *ctx = &local_ctx;

    /* Initialize class stack */
    ctx->field_class_stack = field_class_stack_create();
    if (!ctx->field_class_stack) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger, "Cannot create field class stack.");
        ret = -1;
        goto end;
    }

    if (!tc->is_translated) {
        ctx->scopes.packet_header = tc->packet_header_fc;
        ret = resolve_root_class(CTF_SCOPE_PACKET_HEADER, ctx);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot resolve packet header field class: "
                                         "ret={}",
                                         ret);
            goto end;
        }
    }

    ctx->scopes.packet_header = tc->packet_header_fc;

    for (i = 0; i < tc->stream_classes->len; i++) {
        ctf_stream_class *sc = (ctf_stream_class *) tc->stream_classes->pdata[i];

        ret = resolve_stream_class_field_classes(ctx, sc);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ctx->logger,
                                         "Cannot resolve stream class's field classes: "
                                         "sc-id={}",
                                         sc->id);
            goto end;
        }
    }

end:
    field_class_stack_destroy(ctx->field_class_stack);
    return ret;
}
