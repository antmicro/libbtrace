/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 *
 * BabelTrace - CTF on File System Component
 */

#ifndef BABELTRACE_PLUGINS_CTF_FS_SRC_FS_HPP
#define BABELTRACE_PLUGINS_CTF_FS_SRC_FS_HPP

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/logging.hpp"

#include "../common/src/metadata/metadata-stream-parser-utils.hpp"
#include "../common/src/msg-iter.hpp"
#include "data-stream-file.hpp"

#define CTF_FS_METADATA_FILENAME "metadata"

extern bool ctf_fs_debug;

struct ctf_fs_trace
{
    using UP = std::unique_ptr<ctf_fs_trace>;

    explicit ctf_fs_trace(const ctf::src::ClkClsCfg& clkClsCfg,
                          const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                          const bt2c::Logger& parentLogger) :
        _mLogger {parentLogger, "PLUGIN/SRC.CTF.FS/TRACE"}, _mClkClsCfg {clkClsCfg},
        _mSelfComp {selfComp}
    {
    }

    const ctf::src::TraceCls *cls() const
    {
        BT_ASSERT(_mParseRet);
        BT_ASSERT(_mParseRet->traceCls);
        return _mParseRet->traceCls.get();
    }

    const bt2s::optional<bt2c::Uuid>& metadataStreamUuid() const noexcept
    {
        BT_ASSERT(_mParseRet);
        return _mParseRet->uuid;
    }

    ctf::src::MetadataStreamMajorVersion metadataVersion() const noexcept
    {
        BT_ASSERT(_mParseRet);
        return _mParseRet->metadataVersion;
    }

    void parseMetadata(const bt2c::ConstBytes buffer)
    {
        _mParseRet = ctf::src::parseMetadataStream(_mSelfComp, _mClkClsCfg, buffer, _mLogger);
    }

    bt2::Trace::Shared trace;

    std::vector<ctf_fs_ds_file_group::UP> ds_file_groups;

    std::string path;

    /* Next automatic stream ID when not provided by packet header */
    uint64_t next_stream_id = 0;

private:
    bt2c::Logger _mLogger;
    ctf::src::ClkClsCfg _mClkClsCfg;
    bt2::OptionalBorrowedObject<bt2::SelfComponent> _mSelfComp;
    bt2s::optional<ctf::src::MetadataStreamParser::ParseRet> _mParseRet;
};

struct ctf_fs_port_data
{
    using UP = std::unique_ptr<ctf_fs_port_data>;

    /* Weak, belongs to ctf_fs_trace */
    struct ctf_fs_ds_file_group *ds_file_group = nullptr;

    /* Weak */
    struct ctf_fs_component *ctf_fs = nullptr;
};

struct ctf_fs_component
{
    using UP = std::unique_ptr<ctf_fs_component>;

    explicit ctf_fs_component(const ctf::src::ClkClsCfg& clkClsCfgParam,
                              const bt2c::Logger& parentLogger) noexcept :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/COMP"}, clkClsCfg {clkClsCfgParam}
    {
    }

    bt2c::Logger logger;

    std::vector<ctf_fs_port_data::UP> port_data;

    ctf_fs_trace::UP trace;

    ctf::src::ClkClsCfg clkClsCfg;
    ctf::src::MsgIterQuirks quirks;
};

struct ctf_fs_msg_iter_data
{
    using UP = std::unique_ptr<ctf_fs_msg_iter_data>;

    explicit ctf_fs_msg_iter_data(const bt2::SelfMessageIterator selfMsgIterParam) :
        selfMsgIter {selfMsgIterParam}, logger {selfMsgIter, "PLUGIN/SRC.CTF.FS/MSG-ITER"}
    {
    }

    bt2::SelfMessageIterator selfMsgIter;

    bt2c::Logger logger;

    /* Weak, belongs to ctf_fs_component */
    ctf_fs_port_data *port_data = nullptr;

    bt2s::optional<ctf::src::MsgIter> msgIter;

    /*
     * Saved error.  If we hit an error in the _next method, but have some
     * messages ready to return, we save the error here and return it on
     * the next _next call.
     */
    bt_message_iterator_class_next_method_status next_saved_status =
        BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
    const struct bt_error *next_saved_error = nullptr;
};

bt_component_class_get_supported_mip_versions_method_status
ctf_fs_get_supported_mip_versions(bt_self_component_class_source *selfCompClsSrc,
                                  const bt_value *params, void *data, bt_logging_level logLevel,
                                  bt_integer_range_set_unsigned *supportedVersions);

bt_component_class_initialize_method_status
ctf_fs_init(bt_self_component_source *source, bt_self_component_source_configuration *config,
            const bt_value *params, void *init_method_data);

void ctf_fs_finalize(bt_self_component_source *component);

bt_component_class_query_method_status ctf_fs_query(bt_self_component_class_source *comp_class,
                                                    bt_private_query_executor *priv_query_exec,
                                                    const char *object, const bt_value *params,
                                                    void *method_data, const bt_value **result);

bt_message_iterator_class_initialize_method_status
ctf_fs_iterator_init(bt_self_message_iterator *self_msg_iter,
                     bt_self_message_iterator_configuration *config,
                     bt_self_component_port_output *self_port);

void ctf_fs_iterator_finalize(bt_self_message_iterator *it);

bt_message_iterator_class_next_method_status
ctf_fs_iterator_next(bt_self_message_iterator *iterator, bt_message_array_const msgs,
                     uint64_t capacity, uint64_t *count);

bt_message_iterator_class_seek_beginning_method_status
ctf_fs_iterator_seek_beginning(bt_self_message_iterator *message_iterator);

/*
 * Create one `struct ctf_fs_trace` from one trace, or multiple traces sharing
 * the same UUID.
 *
 * `paths_value` must be an array of strings,
 *
 * The created `struct ctf_fs_trace` is assigned to `ctf_fs->trace`.
 */

int ctf_fs_component_create_ctf_fs_trace(struct ctf_fs_component *ctf_fs,
                                         bt2::ConstArrayValue pathsValue, const char *traceName,
                                         bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp);

namespace ctf {
namespace src {
namespace fs {

/* `src.ctf.fs` parameters */

struct Parameters
{
    explicit Parameters(const bt2::ConstArrayValue inputsParam) noexcept : inputs {inputsParam}
    {
    }

    bt2::ConstArrayValue inputs;
    bt2s::optional<std::string> traceName;
    ClkClsCfg clkClsCfg;
};

} /* namespace fs */
} /* namespace src */
} /* namespace ctf */

/*
 * Read and validate parameters taken by the src.ctf.fs plugin.
 *
 * Throw if any parameter doesn't pass validation.
 */

ctf::src::fs::Parameters read_src_fs_parameters(bt2::ConstValue params, const bt2c::Logger& logger);

/*
 * Generate the port name to be used for a given data stream file group.
 */

std::string ctf_fs_make_port_name(ctf_fs_ds_file_group *ds_file_group);

#endif /* BABELTRACE_PLUGINS_CTF_FS_SRC_FS_HPP */
