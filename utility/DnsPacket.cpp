#include "DnsPacket.h"

#include <string.h>

namespace mdns {

PacketCursor::PacketCursor(PacketView packet)
    : packet_(packet), position_(0), end_(packet.length),
      valid_(packet.data != 0 || packet.length == 0) {}

PacketCursor::PacketCursor(PacketView packet, size_t start, size_t end)
    : packet_(packet), position_(0), end_(0),
      valid_((packet.data != 0 || packet.length == 0) &&
             start <= end && end <= packet.length) {
    if (valid_) {
        position_ = start;
        end_ = end;
    }
}

ParseStatus PacketCursor::check(size_t length) const {
    if (!valid_) return ParseInvalidArgument;
    return length <= remaining() ? ParseOk : ParseTruncated;
}

ParseStatus PacketCursor::take(size_t length, PacketView& value) {
    ParseStatus status = check(length);
    if (status != ParseOk) return status;
    PacketView result(packet_.data ? packet_.data + position_ : 0, length);
    position_ += length;
    value = result;
    return ParseOk;
}

ParseStatus PacketCursor::skip(size_t length) {
    ParseStatus status = check(length);
    if (status == ParseOk) position_ += length;
    return status;
}

ParseStatus PacketCursor::subcursor(size_t length, PacketCursor& value) {
    if (&value == this) return ParseInvalidArgument;
    ParseStatus status = check(length);
    if (status != ParseOk) return status;
    PacketCursor result(packet_, position_, position_ + length);
    position_ += length;
    value = result;
    return ParseOk;
}

ParseStatus PacketCursor::readU8(uint8_t& value) {
    ParseStatus status = check(1);
    if (status != ParseOk) return status;
    value = packet_.data[position_++];
    return ParseOk;
}

ParseStatus PacketCursor::readU16BE(uint16_t& value) {
    ParseStatus status = check(2);
    if (status != ParseOk) return status;
    value = (uint16_t)((uint16_t)packet_.data[position_] << 8) |
            packet_.data[position_ + 1];
    position_ += 2;
    return ParseOk;
}

ParseStatus PacketCursor::readU32BE(uint32_t& value) {
    ParseStatus status = check(4);
    if (status != ParseOk) return status;
    value = ((uint32_t)packet_.data[position_] << 24) |
            ((uint32_t)packet_.data[position_ + 1] << 16) |
            ((uint32_t)packet_.data[position_ + 2] << 8) |
            packet_.data[position_ + 3];
    position_ += 4;
    return ParseOk;
}

ParseStatus decodeName(PacketView packet, size_t start, size_t encodedEnd,
                       uint8_t* output, size_t capacity,
                       size_t& encodedBytes, size_t& expandedBytes) {
    if ((!packet.data && packet.length) || start > encodedEnd ||
        encodedEnd > packet.length || (!output && capacity))
        return ParseInvalidArgument;
    size_t position = start;
    size_t bound = encodedEnd;
    size_t consumed = 0;
    size_t expanded = 0;
    size_t budget = packet.length;
    bool jumped = false;
    for (;;) {
        if (position >= bound) return ParseTruncated;
        if (!budget) return ParseResourceLimit;
        --budget;
        uint8_t tag = packet.data[position];
        if ((tag & 0xc0) == 0xc0) {
            if (bound - position < 2) return ParseTruncated;
            if (!budget) return ParseResourceLimit;
            --budget;
            size_t target = ((size_t)(tag & 0x3f) << 8) |
                            packet.data[position + 1];
            if (target >= packet.length || target >= position)
                return ParseInvalidPointer;
            if (!jumped) consumed = position - start + 2;
            jumped = true;
            position = target;
            bound = packet.length;
            continue;
        }
        if (tag & 0xc0) return ParseInvalidLabel;
        ++position;
        if ((size_t)tag > bound - position) return ParseTruncated;
        if ((size_t)tag + 1 > (size_t)MaxNameLength - expanded)
            return ParseNameTooLong;
        if ((size_t)tag > budget) return ParseResourceLimit;
        budget -= tag;
        if (output) {
            if (expanded > capacity || (size_t)tag + 1 > capacity - expanded)
                return ParseOutputTooSmall;
            output[expanded] = tag;
            if (tag) memcpy(output + expanded + 1, packet.data + position, tag);
        }
        expanded += (size_t)tag + 1;
        position += tag;
        if (!tag) {
            if (!jumped) consumed = position - start;
            encodedBytes = consumed;
            expandedBytes = expanded;
            return ParseOk;
        }
    }
}

static bool validWireName(const uint8_t* name, size_t length) {
    if (!name || !length || length > MaxNameLength) return false;
    size_t position = 0;
    while (position < length) {
        uint8_t label = name[position++];
        if (label > 63 || (size_t)label > length - position) return false;
        if (!label) return position == length;
        position += label;
    }
    return false;
}

static uint8_t foldAscii(uint8_t value) {
    return value >= 'A' && value <= 'Z' ? (uint8_t)(value + ('a' - 'A')) : value;
}

bool namesEqual(const uint8_t* left, size_t leftLength,
                const uint8_t* right, size_t rightLength) {
    if (leftLength != rightLength || !validWireName(left, leftLength) ||
        !validWireName(right, rightLength)) return false;
    size_t position = 0;
    while (position < leftLength) {
        uint8_t label = left[position];
        if (label != right[position]) return false;
        ++position;
        for (uint8_t i = 0; i < label; ++i, ++position)
            if (foldAscii(left[position]) != foldAscii(right[position])) return false;
    }
    return true;
}

ParseStatus encodeDottedName(const char* dotted, uint8_t* output,
                            size_t capacity, size_t& outputLength) {
    if (!dotted || !output) return ParseInvalidArgument;
    size_t expanded = 0;
    const char* label = dotted;
    if (label[0] == '.' && label[1] == '\0') ++label;
    while (*label) {
        size_t length = 0;
        while (label[length] && label[length] != '.') {
            if (length == 63) return ParseInvalidLabel;
            ++length;
        }
        if (!length) return ParseInvalidLabel;
        if (length + 1 >= (size_t)MaxNameLength - expanded)
            return ParseNameTooLong;
        if (expanded > capacity || length + 1 > capacity - expanded)
            return ParseOutputTooSmall;
        output[expanded++] = (uint8_t)length;
        memcpy(output + expanded, label, length);
        expanded += length;
        label += length;
        if (*label == '.') ++label;
    }
    if (expanded >= capacity) return ParseOutputTooSmall;
    output[expanded++] = 0;
    outputLength = expanded;
    return ParseOk;
}

ParseStatus prependLabel(const uint8_t* label, size_t labelLength,
                         const uint8_t* suffix, size_t suffixLength,
                         uint8_t* output, size_t capacity, size_t& outputLength) {
    if (!label || !output) return ParseInvalidArgument;
    if (!labelLength || labelLength > 63 || !validWireName(suffix, suffixLength))
        return ParseInvalidLabel;
    if (labelLength + 1 > (size_t)MaxNameLength - suffixLength)
        return ParseNameTooLong;
    size_t length = labelLength + 1 + suffixLength;
    if (length > capacity) return ParseOutputTooSmall;
    output[0] = (uint8_t)labelLength;
    memcpy(output + 1, label, labelLength);
    memcpy(output + labelLength + 1, suffix, suffixLength);
    outputLength = length;
    return ParseOk;
}

ParseStatus readHeader(PacketCursor& cursor, DnsHeader& header) {
    PacketCursor next = cursor;
    DnsHeader result;
    ParseStatus status;
    if ((status = next.readU16BE(result.id)) != ParseOk ||
        (status = next.readU16BE(result.flags)) != ParseOk ||
        (status = next.readU16BE(result.questions)) != ParseOk ||
        (status = next.readU16BE(result.answers)) != ParseOk ||
        (status = next.readU16BE(result.authorities)) != ParseOk ||
        (status = next.readU16BE(result.additionals)) != ParseOk) return status;
    cursor = next;
    header = result;
    return ParseOk;
}

static ParseStatus skipName(PacketCursor& cursor) {
    size_t encoded, expanded;
    ParseStatus status = decodeName(cursor.packet(), cursor.position(), cursor.end(),
                                   0, 0, encoded, expanded);
    return status == ParseOk ? cursor.skip(encoded) : status;
}

ParseStatus readQuestion(PacketCursor& cursor, Question& question) {
    PacketCursor next = cursor;
    Question result;
    result.nameOffset = next.position();
    ParseStatus status = skipName(next);
    if (status != ParseOk ||
        (status = next.readU16BE(result.type)) != ParseOk ||
        (status = next.readU16BE(result.klass)) != ParseOk) return status;
    cursor = next;
    question = result;
    return ParseOk;
}

ParseStatus readRecord(PacketCursor& cursor, ResourceRecord& record) {
    PacketCursor next = cursor;
    ResourceRecord result;
    result.nameOffset = next.position();
    uint16_t length;
    ParseStatus status = skipName(next);
    if (status != ParseOk ||
        (status = next.readU16BE(result.type)) != ParseOk ||
        (status = next.readU16BE(result.klass)) != ParseOk ||
        (status = next.readU32BE(result.ttl)) != ParseOk ||
        (status = next.readU16BE(length)) != ParseOk) return status;
    result.rdataOffset = next.position();
    result.rdataLength = length;
    if ((status = next.skip(length)) != ParseOk) return status;
    cursor = next;
    record = result;
    return ParseOk;
}

ParseStatus validateRecord(PacketView packet, const ResourceRecord& record) {
    if ((!packet.data && packet.length) || record.rdataOffset > packet.length)
        return ParseInvalidArgument;
    if (record.rdataLength > packet.length - record.rdataOffset)
        return ParseTruncated;
    size_t end = record.rdataOffset + record.rdataLength;
    if (record.type == 1)
        return record.rdataLength == 4 ? ParseOk : ParseInvalidRdata;
    if (record.type == 12 || record.type == 33) {
        size_t fixed = record.type == 33 ? 6 : 0;
        if (record.rdataLength <= fixed) return ParseInvalidRdata;
        size_t encoded, expanded;
        ParseStatus status = decodeName(packet, record.rdataOffset + fixed, end,
                                       0, 0, encoded, expanded);
        if (status != ParseOk) return status;
        return encoded == record.rdataLength - fixed ? ParseOk : ParseInvalidRdata;
    }
    if (record.type == 16) {
        PacketCursor cursor(packet, record.rdataOffset, end);
        while (cursor.remaining()) {
            uint8_t length;
            ParseStatus status = cursor.readU8(length);
            if (status != ParseOk) return status;
            if (cursor.skip(length) != ParseOk) return ParseInvalidRdata;
        }
    }
    return ParseOk;
}

ParseStatus validatePacket(PacketView packet, DnsHeader& header) {
    PacketCursor cursor(packet);
    DnsHeader result;
    ParseStatus status = readHeader(cursor, result);
    if (status != ParseOk) return status;
    for (uint16_t i = 0; i < result.questions; ++i) {
        Question question;
        if ((status = readQuestion(cursor, question)) != ParseOk) return status;
    }
    const uint16_t counts[] = { result.answers, result.authorities, result.additionals };
    for (uint8_t section = 0; section < 3; ++section) {
        for (uint16_t i = 0; i < counts[section]; ++i) {
            ResourceRecord record;
            if ((status = readRecord(cursor, record)) != ParseOk ||
                (status = validateRecord(packet, record)) != ParseOk) return status;
        }
    }
    if (cursor.remaining()) return ParseTrailingData;
    header = result;
    return ParseOk;
}

} // namespace mdns
