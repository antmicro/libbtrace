/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2024 Philippe Proulx <pproulx@efficios.com>
 */

#include <cstdint>

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/read-fixed-len-int.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "metadata-stream-decoder.hpp"

namespace ctf {
namespace src {

const bt2c::DataLen MetadataStreamDecoder::_PktHeader::len = bt2c::DataLen::fromBytes(37);

MetadataStreamDecoder::_PktHeader::_PktHeader(
    const std::uint32_t magicParam, const bt2c::Uuid& uuidParam, const std::uint32_t checksumParam,
    const bt2c::DataLen contentLenParam, const bt2c::DataLen totalLenParam,
    const std::uint8_t compressionSchemeParam, const std::uint8_t encryptionSchemeParam,
    const std::uint8_t checksumSchemeParam, const std::uint8_t majorVersionParam,
    const std::uint8_t minorVersionParam) :
    magic {magicParam}, uuid {uuidParam}, checksum {checksumParam}, contentLen {contentLenParam},
    totalLen {totalLenParam}, compressionScheme {compressionSchemeParam},
    encryptionScheme {encryptionSchemeParam}, checksumScheme {checksumSchemeParam},
    majorVersion {majorVersionParam}, minorVersion {minorVersionParam}
{
}

void MetadataStreamDecoder::_validatePktHeader(const _PktHeader& header) const
{
    if (header.compressionScheme != 0) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "Metadata stream packet compression is not supported as of this version: "
            "compression-scheme={}",
            header.compressionScheme);
    }

    if (header.encryptionScheme != 0) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "Metadata stream packet encryption is not supported as of this version: "
            "encryption-scheme={}",
            header.encryptionScheme);
    }

    if (header.checksum != 0 || header.checksumScheme != 0) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "Metadata stream packet checksum verification is not supported as of this version: "
            "checksum-scheme={}, checksum={:x}",
            header.checksumScheme, header.checksum);
    }

    if (!header.versionIsValid()) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                          "Expecting metadata stream packet version 1.8: "
                                          "actual-version={}.{}",
                                          header.majorVersion, header.minorVersion);
    }

    try {
        if (header.contentLen < _PktHeader::len) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "Packet content length is less than the header length.");
        }

        if (header.contentLen.hasExtraBits()) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                              "Packet content length is not a multiple of 8.");
        }
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
            "Invalid metadata stream packet content length: content-len-bits={}",
            header.contentLen.bits());
    }

    try {
        if (header.totalLen < header.contentLen) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "Packet total length is less than packet content length.");
        }

        if (header.totalLen.hasExtraBits()) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                              "Packet total length is not a multiple of 8.");
        }
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
            "Invalid metadata stream packet total length: total-len-bits={}",
            header.totalLen.bits());
    }
}

bt2s::optional<ByteOrder>
MetadataStreamDecoder::_getByteOrder(const bt2c::ConstBytes buffer) const noexcept
{
    /* We need to read a 32-bit magic number */
    BT_ASSERT(buffer.size() >= sizeof(std::uint32_t));

    static constexpr std::uint32_t expectedMagic = 0x75d11d57U;
    static constexpr auto nativeByteOrder =
        BYTE_ORDER == BIG_ENDIAN ? ByteOrder::Big : ByteOrder::Little;

    /* Read magic number */
    const auto magic = bt2c::readFixedLenInt<std::uint32_t>(buffer.data());

    /* Dedude byte order of the metadata stream packet header */
    if (magic == expectedMagic) {
        return nativeByteOrder;
    } else if (magic == GUINT32_SWAP_LE_BE(expectedMagic)) {
        return nativeByteOrder == ByteOrder::Big ? ByteOrder::Little : ByteOrder::Big;
    } else {
        /* Doesn't look like a metadata stream packet */
        return bt2s::nullopt;
    }
}

namespace {

/*
 * Stateful reader of packet header fields.
 */
class PktHeaderReader final
{
public:
    explicit PktHeaderReader(const ByteOrder byteOrder, const std::uint8_t * const buf) :
        _mByteOrder {byteOrder}, _mBuf {buf}
    {
    }

    std::uint32_t readNextUInt32Field() noexcept
    {
        return this->_readNextIntAndAdvance<std::uint32_t>();
    }

    std::uint8_t readNextUInt8Field() noexcept
    {
        return this->_readNextIntAndAdvance<std::uint8_t>();
    }

    bt2c::Uuid readNextUuidField() noexcept
    {
        const bt2c::Uuid uuid {_mBuf};

        _mBuf += uuid.size();
        return uuid;
    }

private:
    template <typename IntT>
    IntT _readNextInt() const noexcept
    {
        if (_mByteOrder == ByteOrder::Big) {
            return bt2c::readFixedLenIntBe<IntT>(_mBuf);
        } else {
            BT_ASSERT(_mByteOrder == ByteOrder::Little);
            return bt2c::readFixedLenIntLe<IntT>(_mBuf);
        }
    }

    template <typename IntT>
    IntT _readNextIntAndAdvance() noexcept
    {
        const auto res = this->_readNextInt<IntT>();

        _mBuf += sizeof(res);
        return res;
    }

    ByteOrder _mByteOrder;
    const std::uint8_t *_mBuf;
};

} /* namespace */

MetadataStreamDecoder::_PktHeader
MetadataStreamDecoder::_readPktHeader(const std::uint8_t * const buf, const ByteOrder byteOrder,
                                      const bt2c::DataLen curOffset) const
{
    BT_ASSERT(!curOffset.hasExtraBits());

    PktHeaderReader reader {byteOrder, buf};

    const auto magic = reader.readNextUInt32Field();
    const auto uuid = reader.readNextUuidField();
    const auto checksum = reader.readNextUInt32Field();
    const auto contentLen = bt2c::DataLen::fromBits(reader.readNextUInt32Field());
    const auto totalLen = bt2c::DataLen::fromBits(reader.readNextUInt32Field());
    const auto compressionScheme = reader.readNextUInt8Field();
    const auto encryptionScheme = reader.readNextUInt8Field();
    const auto checksumScheme = reader.readNextUInt8Field();
    const auto majorVersion = reader.readNextUInt8Field();
    const auto minorVersion = reader.readNextUInt8Field();

    const _PktHeader header {magic,
                             uuid,
                             checksum,
                             contentLen,
                             totalLen,
                             compressionScheme,
                             encryptionScheme,
                             checksumScheme,
                             majorVersion,
                             minorVersion};

    try {
        this->_validatePktHeader(header);
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("Invalid packet header: offset-bytes={}",
                                            curOffset.bytes());
    }

    return header;
}

MetadataStreamDecoder::MetadataStreamDecoder(const bt2c::Logger& parentLogger) noexcept :
    _mLogger {parentLogger, "PLUGIN/CTF/META/DECODER"}
{
    BT_CPPLOGD("Creating TSDL metadata stream decoder.");
}

std::string MetadataStreamDecoder::_textFromPacketizedMetadata(const bt2c::ConstBytes buffer)
{
    const auto byteOrder = this->_getByteOrder(buffer);

    /* It's a packetized metadata stream section */
    BT_ASSERT(byteOrder);

    std::string plainTextMetadata;
    auto curOffset = bt2c::DataLen::fromBits(0);

    while (curOffset.bytes() < buffer.size()) {
        try {
            const auto pktData = buffer.data() + curOffset.bytes();

            if (curOffset + _PktHeader::len > bt2c::DataLen::fromBytes(buffer.size())) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, "Remaining buffer isn't large enough to hold a packet header.");
            }

            const auto header = this->_readPktHeader(pktData, *byteOrder, curOffset);

            if (_mPktInfo) {
                if (_mPktInfo->uuid() != header.uuid) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                        bt2c::Error,
                        "Metadata UUID mismatch between packets of the same metadata stream: "
                        "pkt-uuid=\"" BT_UUID_FMT "\", "
                        "expected-uuid=\"" BT_UUID_FMT "\"",
                        BT_UUID_FMT_VALUES(header.uuid), BT_UUID_FMT_VALUES(_mPktInfo->uuid()));
                }
            } else {
                _mPktInfo = MetadataStreamPacketInfo {*byteOrder, header.majorVersion,
                                                      header.minorVersion, header.uuid};
            }

            /* Copy the packet payload */
            const auto payload = pktData + _PktHeader::len.bytes();
            const auto payloadLen = header.contentLen - _PktHeader::len;

            plainTextMetadata.append(reinterpret_cast<const char *>(payload), payloadLen.bytes());

            /* Advance offset to the next packet */
            curOffset += header.totalLen;
            ++_mPktIdx;
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
                "Failed to read a metadata stream packet: offset-bytes={}, pkt-idx={}",
                curOffset.bytes(), _mPktIdx);
        }
    }

    return plainTextMetadata;
}

void MetadataStreamDecoder::_maybeSetMetadataStreamType(const bt2c::ConstBytes buffer)
{
    if (this->_getByteOrder(buffer)) {
        if (!_mStreamType) {
            _mStreamType = _MetadataStreamType::Packetized;
        } else if (*_mStreamType != _MetadataStreamType::Packetized) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                              "Expecting a packetized metadata stream section.");
        }
    } else {
        if (!_mStreamType) {
            _mStreamType = _MetadataStreamType::PlainText;
        } else if (*_mStreamType != _MetadataStreamType::PlainText) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                              "Expecting a plain text metadata stream section.");
        }
    }
}

std::string MetadataStreamDecoder::decode(const bt2c::ConstBytes buffer)
{
    this->_maybeSetMetadataStreamType(buffer);

    try {
        if (*_mStreamType == _MetadataStreamType::Packetized) {
            return this->_textFromPacketizedMetadata(buffer);
        } else {
            BT_ASSERT(*_mStreamType == _MetadataStreamType::PlainText);
            return std::string {reinterpret_cast<const char *>(buffer.data()), buffer.size()};
        }
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
            "Failed to decode metadata stream section: data-ptr={}, data-len-bytes={}",
            fmt::ptr(buffer.data()), buffer.size());
    }
}

} /* namespace src */
} /* namespace ctf */
