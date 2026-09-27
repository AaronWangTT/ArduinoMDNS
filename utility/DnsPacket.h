#ifndef ARDUINO_MDNS_DNS_PACKET_H
#define ARDUINO_MDNS_DNS_PACKET_H

#include <stddef.h>
#include <stdint.h>

namespace mdns {

enum ParseStatus {
    ParseOk,
    ParseTruncated,
    ParseInvalidLabel,
    ParseInvalidPointer,
    ParseNameTooLong,
    ParseInvalidRdata,
    ParseOutputTooSmall,
    ParseResourceLimit,
    ParseInvalidArgument,
    ParseTrailingData
};

enum { MaxNameLength = 255 };

struct PacketView {
    const uint8_t* data;
    size_t length;
    PacketView() : data(0), length(0) {}
    PacketView(const uint8_t* bytes, size_t size) : data(bytes), length(size) {}
};

// Failed operations preserve the cursor and all output arguments.
class PacketCursor {
public:
    explicit PacketCursor(PacketView packet = PacketView());
    PacketCursor(PacketView packet, size_t start, size_t end);
    PacketView packet() const { return packet_; }
    size_t position() const { return position_; }
    size_t end() const { return end_; }
    size_t remaining() const { return end_ - position_; }
    ParseStatus readU8(uint8_t& value);
    ParseStatus readU16BE(uint16_t& value);
    ParseStatus readU32BE(uint32_t& value);
    ParseStatus take(size_t length, PacketView& value);
    ParseStatus skip(size_t length);
    // value must be a different cursor; aliasing is an invalid argument.
    ParseStatus subcursor(size_t length, PacketCursor& value);
private:
    ParseStatus check(size_t length) const;
    PacketView packet_;
    size_t position_;
    size_t end_;
    bool valid_;
};

// Wire output preserves length-prefixed labels, original case, and the root.
// On failure lengths are unchanged; output bytes are uncommitted scratch.
// A null output with zero capacity requests validation without materialization.
// Output must not overlap packet storage.
ParseStatus decodeName(PacketView packet, size_t start, size_t encodedEnd,
                       uint8_t* output, size_t capacity,
                       size_t& encodedBytes, size_t& expandedBytes);
bool namesEqual(const uint8_t* left, size_t leftLength,
                const uint8_t* right, size_t rightLength);

// Dotted input has no escape syntax; "" and "." encode the root. A final dot
// is optional. For a literal service-instance label, use prependLabel instead.
ParseStatus encodeDottedName(const char* dotted, uint8_t* output,
                            size_t capacity, size_t& outputLength);
// Inputs must not overlap output. suffix is a complete uncompressed wire name.
ParseStatus prependLabel(const uint8_t* label, size_t labelLength,
                         const uint8_t* suffix, size_t suffixLength,
                         uint8_t* output, size_t capacity, size_t& outputLength);

struct DnsHeader {
    uint16_t id, flags, questions, answers, authorities, additionals;
};
struct Question {
    size_t nameOffset;
    uint16_t type, klass;
};
struct ResourceRecord {
    size_t nameOffset;
    uint16_t type, klass;
    uint32_t ttl;
    size_t rdataOffset, rdataLength;
};

ParseStatus readHeader(PacketCursor& cursor, DnsHeader& header);
ParseStatus readQuestion(PacketCursor& cursor, Question& question);
// Reads a complete envelope; validateRecord checks supported RDATA separately.
ParseStatus readRecord(PacketCursor& cursor, ResourceRecord& record);
ParseStatus validateRecord(PacketView packet, const ResourceRecord& record);
// Validates every declared section, known RDATA, and absence of trailing bytes.
// Header is published only on success. No callbacks, allocation, or I/O.
ParseStatus validatePacket(PacketView packet, DnsHeader& header);

} // namespace mdns

#endif
