/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_METADATA_STREAM_DECODER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_METADATA_STREAM_DECODER_HPP

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/data-len.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2s/optional.hpp"

#include "../../metadata/ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Packet information of a metadata stream.
 */
class MetadataStreamPacketInfo final
{
public:
    explicit MetadataStreamPacketInfo(const ByteOrder byteOrder, const unsigned int major,
                                      const unsigned int minor, const bt2c::Uuid& uuid) noexcept :
        _mByteOrder {byteOrder}, _mMajor {major}, _mMinor {minor}, _mUuid {uuid}
    {
    }

    bool operator==(const MetadataStreamPacketInfo& other) const noexcept
    {
        return _mByteOrder == other._mByteOrder && _mMajor == other._mMajor &&
               _mMinor == other._mMinor && _mUuid == other._mUuid;
    }

    bool operator!=(const MetadataStreamPacketInfo& other) const noexcept
    {
        return !(*this == other);
    }

    ByteOrder byteOrder() const noexcept
    {
        return _mByteOrder;
    }

    unsigned int majorVersion() const noexcept
    {
        return _mMajor;
    }

    unsigned int minorVersion() const noexcept
    {
        return _mMinor;
    }

    const bt2c::Uuid& uuid() const noexcept
    {
        return _mUuid;
    }

private:
    ByteOrder _mByteOrder;
    unsigned int _mMajor;
    unsigned int _mMinor;
    bt2c::Uuid _mUuid;
};

/*
 * A metadata stream decoder offers the decode() method to convert
 * either a plain text metadata stream or multiple packets of a
 * packetized metadata stream to plain text.
 *
 * The first call to decode() determines the permanent mode, based on
 * the data, of the decoder amongst:
 *
 * Plain text mode:
 *     The next calls to decode() only accept plain text metadata stream
 *     data, throwing `bt2c::Error` otherwise.
 *
 *     pktInfo() returns `bt2s::nullopt`.
 *
 * Packetized mode:
 *     The next calls to decode() only accept packetized metadata stream
 *     data, throwing `bt2c::Error` otherwise.
 *
 *     Furthermore, the next calls to decode() validate that each
 *     metadata stream packet has the same UUID, again throwing
 *     `bt2c::Error` otherwise.
 *
 *     pktInfo() returns a value.
 */
class MetadataStreamDecoder final
{
public:
    explicit MetadataStreamDecoder(const bt2c::Logger& parentLogger) noexcept;

    /*
     * Decodes the next metadata stream section `buffer`, appending a
     * cause to the error of the current thread and throwing
     * `bt2c::Error` on error.
     *
     * `buffer.size()` must be greater than or equal to 4.
     */
    std::string decode(bt2c::ConstBytes buffer);

    const bt2s::optional<MetadataStreamPacketInfo>& pktInfo() const noexcept
    {
        return _mPktInfo;
    }

private:
    /*
     * Type of metadata stream.
     */
    enum class _MetadataStreamType
    {
        Packetized,
        PlainText,
    };

    /*
     * Container of metadata stream packet header information.
     *
     * This structure is not to be used as a direct memory mapping of
     * such a header.
     */
    struct _PktHeader final
    {
        explicit _PktHeader(std::uint32_t magicParam, const bt2c::Uuid& uuidParam,
                            std::uint32_t checksumParam, bt2c::DataLen contentLenParam,
                            bt2c::DataLen totalLenParam, std::uint8_t compressionSchemeParam,
                            std::uint8_t encryptionSchemeParam, std::uint8_t checksumSchemeParam,
                            std::uint8_t majorVersionParam, std::uint8_t minorVersionParam);

        bool versionIsValid() const noexcept
        {
            return majorVersion == 1 && minorVersion == 8;
        }

        static const bt2c::DataLen len;
        std::uint32_t magic;
        bt2c::Uuid uuid;
        std::uint32_t checksum;
        bt2c::DataLen contentLen;
        bt2c::DataLen totalLen;
        std::uint8_t compressionScheme;
        std::uint8_t encryptionScheme;
        std::uint8_t checksumScheme;
        std::uint8_t majorVersion;
        std::uint8_t minorVersion;
    };

    /*
     * Returns the byte order of the metadata stream `buffer`, or
     * `bt2s::nullopt` if `buffer` doesn't look like a packet header.
     *
     * `buffer.size()` must be greater than or equal to 4.
     */
    bt2s::optional<ByteOrder> _getByteOrder(bt2c::ConstBytes buffer) const noexcept;

    /*
     * Reads and returns one metadata stream packet header having the
     * byte order `byteOrder` from `buf` at the offset `curOffset`
     * within some metadata stream section.
     *
     * `buf` must offer at least `_PktHeader::len.bytes()` bytes
     * of data.
     *
     * `curOffset.hasExtraBits()` must return false.
     */
    _PktHeader _readPktHeader(const std::uint8_t *buf, ByteOrder byteOrder,
                              bt2c::DataLen curOffset) const;

    /*
     * Validates the packet header `header`, throwing
     * `bt2c::Error` if it's invalid.
     */
    void _validatePktHeader(const _PktHeader& header) const;

    /*
     * Returns the plain text data from the packetized metadata
     * stream `buffer`.
     */
    std::string _textFromPacketizedMetadata(bt2c::ConstBytes buffer);

    /*
     * Sets the current metadata stream type from `buffer` if not
     * already done.
     */
    void _maybeSetMetadataStreamType(bt2c::ConstBytes buffer);

    bt2c::Logger _mLogger;
    bt2s::optional<MetadataStreamPacketInfo> _mPktInfo;
    std::size_t _mPktIdx = 0;
    bt2s::optional<_MetadataStreamType> _mStreamType;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_METADATA_STREAM_DECODER_HPP */
