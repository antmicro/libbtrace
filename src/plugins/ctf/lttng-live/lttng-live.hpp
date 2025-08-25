/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * BabelTrace - LTTng-live client Component
 */

#ifndef BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_LTTNG_LIVE_HPP
#define BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_LTTNG_LIVE_HPP

#include <glib.h>
#include <stdint.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/message.hpp"
#include "cpp-common/vendor/fmt/format.h" /* IWYU pragma: keep */

#include "plugins/common/muxing/muxing.hpp"

#include "../common/src/metadata/metadata-stream-parser-utils.hpp"
#include "../common/src/metadata/metadata-stream-parser.hpp"
#include "../common/src/msg-iter.hpp"
#include "lttng-viewer-abi.hpp"
#include "viewer-connection.hpp"

/*
 * bt_common_lttng_live_url_parts is defined in common code, and is also used
 * by C code, so it can't be C++-ified yet.  Use this separate deleter object
 * in the mean time.
 */
struct bt_common_lttng_live_url_parts_deleter
{
    explicit bt_common_lttng_live_url_parts_deleter(bt_common_lttng_live_url_parts& obj) noexcept :
        _mObj {&obj}
    {
    }

    bt_common_lttng_live_url_parts_deleter(const bt_common_lttng_live_url_parts_deleter&) = delete;
    bt_common_lttng_live_url_parts&
    operator=(const bt_common_lttng_live_url_parts_deleter&) = delete;

    ~bt_common_lttng_live_url_parts_deleter()
    {
        bt_common_destroy_lttng_live_url_parts(_mObj);
    }

private:
    bt_common_lttng_live_url_parts *_mObj;
};

enum lttng_live_stream_state
{
    /* This stream won't have data until some known time in the future. */
    LTTNG_LIVE_STREAM_QUIESCENT,
    /*
     * This stream won't have data until some known time in the future and
     * the message iterator inactivity message was already sent downstream.
     */
    LTTNG_LIVE_STREAM_QUIESCENT_NO_DATA, /* */
    /* This stream has data ready to be consumed. */
    LTTNG_LIVE_STREAM_ACTIVE_DATA,
    /*
     * This stream has no data left to consume. We should asked the relay
     * for more.
     */
    LTTNG_LIVE_STREAM_ACTIVE_NO_DATA,
    /* This stream won't have anymore data, ever. */
    LTTNG_LIVE_STREAM_EOF,
};

inline const char *format_as(const lttng_live_stream_state state) noexcept
{
    switch (state) {
    case LTTNG_LIVE_STREAM_ACTIVE_NO_DATA:
        return "ACTIVE_NO_DATA";

    case LTTNG_LIVE_STREAM_QUIESCENT_NO_DATA:
        return "QUIESCENT_NO_DATA";

    case LTTNG_LIVE_STREAM_QUIESCENT:
        return "QUIESCENT";

    case LTTNG_LIVE_STREAM_ACTIVE_DATA:
        return "ACTIVE_DATA";

    case LTTNG_LIVE_STREAM_EOF:
        return "EOF";
    }

    bt_common_abort();
}

/* Iterator over a live stream. */
struct lttng_live_stream_iterator
{
    using UP = std::unique_ptr<lttng_live_stream_iterator>;

    explicit lttng_live_stream_iterator(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.LTTNG-LIVE/STREAM-ITER"}
    {
    }

    ~lttng_live_stream_iterator();

    bt2c::Logger logger;

    bt2::Stream::Shared stream;

    /* Weak reference. */
    struct lttng_live_trace *trace = nullptr;

    /*
     * Since only a single iterator per viewer connection, we have
     * only a single message iterator per stream.
     */
    bt2s::optional<ctf::src::MsgIter> msg_iter;

    uint64_t viewer_stream_id = 0;

    struct
    {
        bool is_set = false;
        uint64_t value = 0;
    } ctf_stream_class_id;

    /*
     * Clock Snapshot value of the last message iterator inactivity message
     * sent downstream.
     */
    struct
    {
        bool is_set = false;
        uint64_t value = 0;
    } last_inactivity_ts;

    /*
     * Clock Snapshot value of the current message iterator inactivity
     * message we might want to send downstream.
     */
    uint64_t current_inactivity_ts = 0;

    enum lttng_live_stream_state state = LTTNG_LIVE_STREAM_QUIESCENT;

    /* The current message produced by this live stream iterator. */
    bt2::ConstMessage::Shared current_msg;

    /* Timestamp in nanoseconds of the current message (current_msg). */
    int64_t current_msg_ts_ns = 0;

    std::string name;

    bool has_stream_hung_up = false;

    struct CurPktInfo
    {
        bt2c::DataLen offsetInRelay;
        bt2c::DataLen len;
    };

    bt2s::optional<CurPktInfo> curPktInfo;
};

struct lttng_live_metadata
{
    using UP = std::unique_ptr<lttng_live_metadata>;

    explicit lttng_live_metadata(const bt2::SelfComponent selfComp,
                                 const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.LTTNG-LIVE/METADATA"}, _mSelfComp {selfComp}

    {
    }

    const ctf::src::TraceCls *traceCls() const
    {
        return _mMetadataStreamParser->traceCls();
    }

    const bt2s::optional<bt2c::Uuid>& metadataStreamUuid() const noexcept
    {
        return _mMetadataStreamParser->metadataStreamUuid();
    }

    void parseSection(const bt2c::ConstBytes data, const int32_t minor)
    {
        if (!_mMetadataStreamParser) {
            /* Some sanity check */
            BT_ASSERT((ctf::src::getMetadataStreamMajorVersion(data) ==
                           ctf::src::MetadataStreamMajorVersion::V1 ||
                       minor >= LTTNG_LIVE_MINOR_15));

            _mMetadataStreamParser =
                ctf::src::createMetadataStreamParser(data, _mSelfComp, {}, logger);
        }

        _mMetadataStreamParser->parseSection(data);
    }

    bt2::SelfComponent selfComp() const noexcept
    {
        return _mSelfComp;
    }

    bt2c::Logger logger;

    uint64_t stream_id = 0;

private:
    bt2::SelfComponent _mSelfComp;
    ctf::src::MetadataStreamParser::UP _mMetadataStreamParser;
};

enum lttng_live_metadata_stream_state
{
    /*
     * The metadata needs to be updated. This is either because we just
     * created the trace and haven't asked yet, or the relay specifically
     * told us that new metadata is available.
     */
    LTTNG_LIVE_METADATA_STREAM_STATE_NEEDED,
    /*
     * The metadata was updated and the relay has not told us we need to
     * update it yet.
     */
    LTTNG_LIVE_METADATA_STREAM_STATE_NOT_NEEDED,
    /*
     * The relay has closed this metadata stream. We set this in reaction
     * to a LTTNG_VIEWER_METADATA_ERR reply to a LTTNG_VIEWER_GET_METADATA
     * command to the relay. If this field is set, we have received all the
     * metadata that we are ever going to get for that metadata stream.
     */
    LTTNG_LIVE_METADATA_STREAM_STATE_CLOSED,
};

struct lttng_live_trace
{
    using UP = std::unique_ptr<lttng_live_trace>;

    explicit lttng_live_trace(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.LTTNG-LIVE/TRACE"}
    {
    }

    bt2c::Logger logger;

    /* Back reference to session. */
    struct lttng_live_session *session = nullptr;

    /* ctf trace ID within the session. */
    uint64_t id = 0;

    bt2::Trace::Shared trace;

    lttng_live_metadata::UP metadata;

    bt2::OptionalBorrowedObject<bt2::ConstClockClass> clock_class;

    std::vector<lttng_live_stream_iterator::UP> stream_iterators;

    enum lttng_live_metadata_stream_state metadata_stream_state =
        LTTNG_LIVE_METADATA_STREAM_STATE_NEEDED;
};

struct lttng_live_session
{
    using UP = std::unique_ptr<lttng_live_session>;

    explicit lttng_live_session(const bt2c::Logger& parentLogger,
                                const bt2::SelfComponent selfCompParam) :
        logger {parentLogger, "PLUGIN/SRC.CTF.LTTNG-LIVE/SESSION"}, selfComp {selfCompParam}
    {
    }

    ~lttng_live_session();

    bt2c::Logger logger;

    bt2::SelfComponent selfComp;

    /* Weak reference. */
    struct lttng_live_msg_iter *lttng_live_msg_iter = nullptr;

    std::string hostname;

    std::string session_name;

    lttng_live_trace_format traceFmt;

    uint64_t id = 0;

    std::vector<lttng_live_trace::UP> traces;

    bool attached = false;
    bool new_streams_needed = false;
    bool closed = false;
};

enum session_not_found_action
{
    SESSION_NOT_FOUND_ACTION_CONTINUE,
    SESSION_NOT_FOUND_ACTION_FAIL,
    SESSION_NOT_FOUND_ACTION_END,
};

/*
 * A component instance is an iterator on a single session.
 */
struct lttng_live_component
{
    using UP = std::unique_ptr<lttng_live_component>;

    explicit lttng_live_component(bt2c::Logger loggerParam,
                                  const bt2::SelfComponent selfCompParam) noexcept :
        logger {std::move(loggerParam)}, selfComp {selfCompParam}
    {
    }

    bt2c::Logger logger;

    bt2::SelfComponent selfComp;

    struct
    {
        std::string url;
        enum session_not_found_action sess_not_found_act = SESSION_NOT_FOUND_ACTION_CONTINUE;
    } params;

    size_t max_query_size = 0;

    /*
     * Keeps track of whether the downstream component already has a
     * message iterator on this component.
     */
    bool has_msg_iter = false;
};

struct lttng_live_msg_iter
{
    using UP = std::unique_ptr<lttng_live_msg_iter>;

    explicit lttng_live_msg_iter(const bt2c::Logger& parentLogger,
                                 const bt2::SelfComponent selfCompParam,
                                 const bt2::SelfMessageIterator selfMsgIter) :
        logger {parentLogger, "PLUGIN/SRC.CTF.LTTNG-LIVE/MSG-ITER"}, selfComp {selfCompParam},
        selfMsgIter {selfMsgIter}, msgComparator {selfComp.graphMipVersion()}
    {
    }

    ~lttng_live_msg_iter();

    bt2c::Logger logger;

    bt2::SelfComponent selfComp;

    /* Weak reference. */
    struct lttng_live_component *lttng_live_comp = nullptr;

    bt2::SelfMessageIterator selfMsgIter;

    live_viewer_connection::UP viewer_connection;

    std::vector<lttng_live_session::UP> sessions;

    /* Number of live stream iterator this message iterator has.*/
    uint64_t active_stream_iter = 0;

    /* Timestamp in nanosecond of the last message sent downstream. */
    int64_t last_msg_ts_ns = 0;

    /* True if the iterator was interrupted. */
    bool was_interrupted = false;

    muxing::MessageComparator msgComparator;
};

enum lttng_live_iterator_status
{
    /** Iterator state has progressed. Continue iteration immediately. */
    LTTNG_LIVE_ITERATOR_STATUS_CONTINUE = 3,
    /** No message available for now. Try again later. */
    LTTNG_LIVE_ITERATOR_STATUS_AGAIN = 2,
    /** No more CTF_LTTNG_LIVEs to be delivered. */
    LTTNG_LIVE_ITERATOR_STATUS_END = 1,
    /** No error, okay. */
    LTTNG_LIVE_ITERATOR_STATUS_OK = 0,
    /** Invalid arguments. */
    LTTNG_LIVE_ITERATOR_STATUS_INVAL = -1,
    /** General error. */
    LTTNG_LIVE_ITERATOR_STATUS_ERROR = -2,
    /** Out of memory. */
    LTTNG_LIVE_ITERATOR_STATUS_NOMEM = -3,
    /** Unsupported iterator feature. */
    LTTNG_LIVE_ITERATOR_STATUS_UNSUPPORTED = -4,
};

inline const char *format_as(const lttng_live_iterator_status status) noexcept
{
    switch (status) {
    case LTTNG_LIVE_ITERATOR_STATUS_CONTINUE:
        return "LTTNG_LIVE_ITERATOR_STATUS_CONTINUE";

    case LTTNG_LIVE_ITERATOR_STATUS_AGAIN:
        return "LTTNG_LIVE_ITERATOR_STATUS_AGAIN";

    case LTTNG_LIVE_ITERATOR_STATUS_END:
        return "LTTNG_LIVE_ITERATOR_STATUS_END";

    case LTTNG_LIVE_ITERATOR_STATUS_OK:
        return "LTTNG_LIVE_ITERATOR_STATUS_OK";

    case LTTNG_LIVE_ITERATOR_STATUS_INVAL:
        return "LTTNG_LIVE_ITERATOR_STATUS_INVAL";

    case LTTNG_LIVE_ITERATOR_STATUS_ERROR:
        return "LTTNG_LIVE_ITERATOR_STATUS_ERROR";

    case LTTNG_LIVE_ITERATOR_STATUS_NOMEM:
        return "LTTNG_LIVE_ITERATOR_STATUS_NOMEM";

    case LTTNG_LIVE_ITERATOR_STATUS_UNSUPPORTED:
        return "LTTNG_LIVE_ITERATOR_STATUS_UNSUPPORTED";
    }

    bt_common_abort();
}

bt_component_class_initialize_method_status
lttng_live_component_init(bt_self_component_source *self_comp,
                          bt_self_component_source_configuration *config, const bt_value *params,
                          void *init_method_data);

bt_component_class_get_supported_mip_versions_method_status
lttng_live_get_supported_mip_versions(bt_self_component_class_source *selfCompClsSrc,
                                      const bt_value *params, void *data, bt_logging_level logLevel,
                                      bt_integer_range_set_unsigned *supportedVersions);

bt_component_class_query_method_status lttng_live_query(bt_self_component_class_source *comp_class,
                                                        bt_private_query_executor *priv_query_exec,
                                                        const char *object, const bt_value *params,
                                                        void *method_data, const bt_value **result);

void lttng_live_component_finalize(bt_self_component_source *component);

bt_message_iterator_class_next_method_status
lttng_live_msg_iter_next(bt_self_message_iterator *self_msg_it, bt_message_array_const msgs,
                         uint64_t capacity, uint64_t *count);

bt_message_iterator_class_initialize_method_status
lttng_live_msg_iter_init(bt_self_message_iterator *self_msg_it,
                         bt_self_message_iterator_configuration *config,
                         bt_self_component_port_output *self_port);

void lttng_live_msg_iter_finalize(bt_self_message_iterator *it);

enum lttng_live_viewer_status lttng_live_session_attach(struct lttng_live_session *session);

enum lttng_live_viewer_status lttng_live_session_detach(struct lttng_live_session *session);

enum lttng_live_iterator_status
lttng_live_session_get_new_streams(struct lttng_live_session *session);

struct lttng_live_trace *
lttng_live_session_borrow_or_create_trace_by_id(struct lttng_live_session *session,
                                                uint64_t trace_id);

int lttng_live_add_session(struct lttng_live_msg_iter *lttng_live_msg_iter, uint64_t session_id,
                           std::string hostname, std::string session_name,
                           lttng_live_trace_format traceFmt);

/*
 * lttng_live_get_one_metadata_packet() asks the Relay Daemon for new metadata.
 * If new metadata is received, the function writes it to the provided file
 * handle and updates the reply_len output parameter. This function should be
 * called in loop until _END status is received to ensure all metadata is
 * written to the file.
 */
enum lttng_live_get_one_metadata_status
lttng_live_get_one_metadata_packet(struct lttng_live_trace *trace, std::vector<uint8_t>& buf);

enum lttng_live_iterator_status
lttng_live_get_next_index(struct lttng_live_msg_iter *lttng_live_msg_iter,
                          struct lttng_live_stream_iterator *stream, struct packet_index *index);

bool lttng_live_graph_is_canceled(struct lttng_live_msg_iter *msg_iter);

void lttng_live_stream_iterator_set_state(struct lttng_live_stream_iterator *stream_iter,
                                          enum lttng_live_stream_state new_state);

void lttng_live_stream_iterator_set_stream_class(lttng_live_stream_iterator *streamIter,
                                                 uint64_t ctfStreamClsId);

#endif /* BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_LTTNG_LIVE_HPP */
