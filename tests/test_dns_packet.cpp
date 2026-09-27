#include "../utility/DnsPacket.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>

using namespace mdns;
typedef std::vector<uint8_t> Bytes;

static PacketView view(const Bytes& bytes) {
    return PacketView(bytes.empty() ? 0 : &bytes[0], bytes.size());
}

static void append16(Bytes& bytes, uint16_t value) {
    bytes.push_back((uint8_t)(value >> 8));
    bytes.push_back((uint8_t)value);
}

static void appendRecord(Bytes& bytes, uint16_t type, const Bytes& rdata) {
    bytes.push_back(0);
    append16(bytes, type);
    append16(bytes, 0x8001);
    append16(bytes, 0);
    append16(bytes, 120);
    append16(bytes, (uint16_t)rdata.size());
    bytes.insert(bytes.end(), rdata.begin(), rdata.end());
}

static ParseStatus decode(const Bytes& bytes, size_t start, size_t end,
                          uint8_t* output, size_t capacity,
                          size_t& encoded, size_t& expanded) {
    return decodeName(view(bytes), start, end, output, capacity, encoded, expanded);
}

static void testCursor() {
    const uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
    PacketCursor cursor(PacketView(bytes, sizeof bytes));
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    assert(cursor.readU8(u8) == ParseOk && u8 == 0x12);
    assert(cursor.readU16BE(u16) == ParseOk && u16 == 0x3456);
    assert(cursor.readU32BE(u32) == ParseOk && u32 == 0x789abcdeUL);
    assert(cursor.readU32BE(u32) == ParseTruncated && u32 == 0x789abcdeUL);
    assert(cursor.readU16BE(u16) == ParseTruncated && u16 == 0x3456);
    assert(cursor.readU8(u8) == ParseTruncated && u8 == 0x12);
    assert(cursor.position() == sizeof bytes);
    assert(cursor.skip((size_t)-1) == ParseTruncated);
    PacketView span(bytes, 3);
    assert(cursor.take(1, span) == ParseTruncated && span.length == 3);
    assert(cursor.take(0, span) == ParseOk && span.length == 0);

    PacketCursor parent(PacketView(bytes, sizeof bytes));
    PacketCursor child;
    assert(parent.subcursor(3, child) == ParseOk);
    assert(parent.position() == 3 && child.position() == 0 && child.end() == 3);
    assert(parent.subcursor((size_t)-1, child) == ParseTruncated);
    assert(parent.position() == 3 && child.end() == 3);
    assert(parent.subcursor(1, parent) == ParseInvalidArgument && parent.position() == 3);
    assert(child.readU32BE(u32) == ParseTruncated && child.position() == 0);
    assert(child.take(3, span) == ParseOk && span.data == bytes && span.length == 3);
    PacketCursor empty;
    assert(empty.take(0, span) == ParseOk && !span.data && span.length == 0);
    assert(empty.readU8(u8) == ParseTruncated);
    PacketCursor invalid(PacketView(bytes, sizeof bytes), (size_t)-1, 1);
    assert(invalid.remaining() == 0 && invalid.skip(0) == ParseInvalidArgument);
    PacketCursor nullData(PacketView(0, 1));
    assert(nullData.skip(0) == ParseInvalidArgument);
}

static Bytes longName(size_t last) {
    Bytes name;
    for (unsigned i = 0; i < 4; ++i) {
        size_t length = i == 3 ? last : 63;
        name.push_back((uint8_t)length);
        name.insert(name.end(), length, (uint8_t)('a' + i));
    }
    name.push_back(0);
    return name;
}

static void testNames() {
    uint8_t output[MaxNameLength];
    size_t encoded = 999, expanded = 999;
    Bytes root(1, 0);
    assert(decode(root, 0, 1, output, sizeof output, encoded, expanded) == ParseOk);
    assert(encoded == 1 && expanded == 1 && output[0] == 0);
    encoded = expanded = 999;
    assert(decode(root, 0, 0, output, sizeof output, encoded, expanded) == ParseTruncated);
    assert(encoded == 999 && expanded == 999);
    assert(decode(root, 1, 0, output, sizeof output, encoded, expanded) == ParseInvalidArgument);
    assert(decode(root, 0, (size_t)-1, output, sizeof output, encoded, expanded) == ParseInvalidArgument);
    assert(decode(root, 0, 1, output, 0, encoded, expanded) == ParseOutputTooSmall);
    assert(decode(root, 0, 1, 0, 1, encoded, expanded) == ParseInvalidArgument);
    for (unsigned tag = 64; tag < 192; ++tag) {
        Bytes reserved(1, (uint8_t)tag);
        assert(decode(reserved, 0, 1, output, sizeof output, encoded, expanded) == ParseInvalidLabel);
    }
    for (size_t last = 60; last <= 62; ++last) {
        Bytes name = longName(last);
        ParseStatus status = decode(name, 0, name.size(), output, sizeof output, encoded, expanded);
        assert(status == (last == 62 ? ParseNameTooLong : ParseOk));
        if (status == ParseOk) assert(expanded == name.size() && encoded == name.size());
    }
    const uint8_t compressed[] = {1, 'x', 0, 1, 'y', 0xc0, 0};
    Bytes packet(compressed, compressed + sizeof compressed);
    assert(decode(packet, 3, 7, output, sizeof output, encoded, expanded) == ParseOk);
    const uint8_t expected[] = {1, 'y', 1, 'x', 0};
    assert(encoded == 4 && expanded == sizeof expected && !memcmp(output, expected, expanded));
    assert(decode(packet, 3, 6, output, sizeof output, encoded, expanded) == ParseTruncated);
    // The pointer lies inside the field; its target is outside it.
    assert(decode(packet, 5, 7, output, sizeof output, encoded, expanded) == ParseOk);
    assert(encoded == 2 && expanded == 3);

    Bytes high(302, 0);
    high[256] = 1; high[257] = 'A';
    high[300] = 0xc1; high[301] = 0;
    assert(decode(high, 300, 302, output, sizeof output, encoded, expanded) == ParseOk);
    assert(output[1] == 'A' && expanded == 3);
    high[300] = 0xff; high[301] = 0xff;
    assert(decode(high, 300, 302, output, sizeof output, encoded, expanded) == ParseInvalidPointer);
    high.assign(16387, 0);
    high[16383] = 1; high[16384] = 'Z';
    high[16385] = 0xff; high[16386] = 0xff;
    // The target's label runs into the pointer: a backward label/pointer cycle.
    assert(decode(high, 16385, high.size(), output, sizeof output, encoded, expanded) == ParseNameTooLong);
    high.insert(high.begin() + 16385, 0);
    assert(decode(high, 16386, high.size(), output, sizeof output, encoded, expanded) == ParseOk);
    assert(output[1] == 'Z' && encoded == 2 && expanded == 3);

    const uint8_t forward[] = {0xc0, 2, 0};
    packet.assign(forward, forward + sizeof forward);
    assert(decode(packet, 0, 3, output, sizeof output, encoded, expanded) == ParseInvalidPointer);
    packet[1] = 0;
    assert(decode(packet, 0, 3, output, sizeof output, encoded, expanded) == ParseInvalidPointer);
    const uint8_t cycle[] = {1, 'a', 0xc0, 0};
    packet.assign(cycle, cycle + sizeof cycle);
    assert(decode(packet, 2, 4, output, sizeof output, encoded, expanded) == ParseResourceLimit);
    // A chain longer than common arbitrary 16/32/128-hop caps remains valid.
    Bytes chain(1, 0);
    size_t previous = 0;
    for (unsigned i = 0; i < 200; ++i) {
        size_t start = chain.size();
        chain.push_back((uint8_t)(0xc0 | (previous >> 8)));
        chain.push_back((uint8_t)previous);
        previous = start;
    }
    assert(decode(chain, previous, chain.size(), output, sizeof output, encoded, expanded) == ParseOk);
    assert(encoded == 2 && expanded == 1);

    uint8_t other[MaxNameLength];
    size_t length, otherLength;
    assert(encodeDottedName("Host.LOCAL.", output, sizeof output, length) == ParseOk);
    assert(encodeDottedName("host.local", other, sizeof other, otherLength) == ParseOk);
    assert(namesEqual(output, length, other, otherLength));
    assert(!namesEqual(output, length - 1, other, otherLength));
    assert(!namesEqual(0, 0, 0, 0));
    assert(encodeDottedName("_http._tcp.local", other, sizeof other, otherLength) == ParseOk);
    const uint8_t instance[] = {'A', '.', 'B', 0, 0xff};
    assert(prependLabel(instance, sizeof instance, other, otherLength,
                        output, sizeof output, length) == ParseOk);
    assert(output[0] == sizeof instance && !memcmp(output + 1, instance, sizeof instance));
    assert(namesEqual(output, length, output, length));
    const uint8_t oneLabel[] = {3, 'a', '.', 'b', 0};
    const uint8_t twoLabels[] = {1, 'a', 1, 'b', 0};
    assert(!namesEqual(oneLabel, sizeof oneLabel, twoLabels, sizeof twoLabels));
    const uint8_t binaryUpper[] = {2, 0xc0, 'A', 0};
    const uint8_t binaryLower[] = {2, 0xe0, 'a', 0};
    assert(!namesEqual(binaryUpper, sizeof binaryUpper, binaryLower, sizeof binaryLower));
    const char* invalid[] = {"..", "a..b", ".a", "a.."};
    for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        length = 999;
        assert(encodeDottedName(invalid[i], output, sizeof output, length) == ParseInvalidLabel);
        assert(length == 999);
    }
    assert(encodeDottedName("", output, sizeof output, length) == ParseOk && length == 1);
    assert(encodeDottedName(".", output, sizeof output, length) == ParseOk && length == 1);
    Bytes max = longName(61);
    length = 999;
    assert(prependLabel(instance, sizeof instance, &max[0], max.size(), output,
                        sizeof output, length) == ParseNameTooLong && length == 999);
}

static void testRecords() {
    DnsHeader header;
    memset(&header, 0, sizeof header);
    header.id = 77;
    Bytes packet(12, 0);
    for (size_t length = 0; length < 12; ++length) {
        assert(validatePacket(PacketView(&packet[0], length), header) == ParseTruncated);
        assert(header.id == 77);
    }
    packet[2] = 0x84;
    assert(validatePacket(view(packet), header) == ParseOk && header.flags == 0x8400);
    packet.push_back(0);
    assert(validatePacket(view(packet), header) == ParseTrailingData);
    packet.resize(12);
    // Each RR section is independently traversed, including otherwise unrelated RDATA.
    packet[7] = packet[9] = packet[11] = 1;
    appendRecord(packet, 1, Bytes(4, 42));
    appendRecord(packet, 12, Bytes(1, 0));
    appendRecord(packet, 16, Bytes());
    assert(validatePacket(view(packet), header) == ParseOk);
    assert(header.answers == 1 && header.authorities == 1 && header.additionals == 1);
    for (size_t length = 12; length < packet.size(); ++length)
        assert(validatePacket(PacketView(&packet[0], length), header) != ParseOk);

    for (unsigned typeIndex = 0; typeIndex < 5; ++typeIndex) {
        const uint16_t types[] = {1, 12, 16, 33, 999};
        uint16_t type = types[typeIndex];
        for (size_t size = 0; size <= 8; ++size) {
            packet.assign(12, 0);
            packet[7] = 1;
            appendRecord(packet, type, Bytes(size, 0));
            bool valid = type == 1 ? size == 4 : type == 12 ? size == 1 :
                         type == 33 ? size == 7 : true;
            assert((validatePacket(view(packet), header) == ParseOk) == valid);
        }
    }
    packet.assign(12, 0);
    packet[7] = 1;
    Bytes txt;
    txt.push_back(3); txt.push_back('a'); txt.push_back(0); txt.push_back(0xff);
    appendRecord(packet, 16, txt);
    assert(validatePacket(view(packet), header) == ParseOk);
    packet[23] = 4;
    assert(validatePacket(view(packet), header) == ParseInvalidRdata);

    packet.assign(12, 0);
    packet[5] = 1; packet[7] = 2;
    packet.push_back(1); packet.push_back('x'); packet.push_back(0);
    append16(packet, 1); append16(packet, 0x8001);
    Bytes pointer;
    pointer.push_back(0xc0); pointer.push_back(12);
    appendRecord(packet, 12, pointer);
    Bytes srv(6, 0);
    srv[5] = 80;
    srv.insert(srv.end(), pointer.begin(), pointer.end());
    appendRecord(packet, 33, srv);
    assert(validatePacket(view(packet), header) == ParseOk);
    PacketCursor cursor(view(packet));
    assert(readHeader(cursor, header) == ParseOk);
    Question question;
    assert(readQuestion(cursor, question) == ParseOk && question.klass == 0x8001);
    ResourceRecord record;
    assert(readRecord(cursor, record) == ParseOk && record.klass == 0x8001);
    assert(record.ttl == 120 && record.rdataLength == 2);
    assert(validateRecord(view(packet), record) == ParseOk);
    record.rdataLength = (size_t)-1;
    assert(validateRecord(view(packet), record) == ParseTruncated);
    record.rdataOffset = (size_t)-1;
    assert(validateRecord(view(packet), record) == ParseInvalidArgument);
    packet.assign(12, 0);
    packet[4] = packet[5] = packet[6] = packet[7] = 255;
    assert(validatePacket(view(packet), header) == ParseTruncated);

    const uint8_t truncatedRecord[] = {0, 0, 1};
    PacketCursor shortCursor(PacketView(truncatedRecord, sizeof truncatedRecord));
    record.type = 999;
    assert(readRecord(shortCursor, record) == ParseTruncated);
    assert(shortCursor.position() == 0 && record.type == 999);
    question.type = 999;
    assert(readQuestion(shortCursor, question) == ParseTruncated);
    assert(shortCursor.position() == 0 && question.type == 999);
}

static uint32_t randomState = 0x3166cafeUL;
static uint32_t nextRandom() {
    randomState ^= randomState << 13;
    randomState ^= randomState >> 17;
    randomState ^= randomState << 5;
    return randomState;
}

static void testGenerated() {
    for (unsigned iteration = 0; iteration < 20000; ++iteration) {
        Bytes wire;
        unsigned labels = nextRandom() % 7;
        for (unsigned i = 0; i < labels; ++i) {
            size_t length = 1 + nextRandom() % 63;
            if (length + 2 > MaxNameLength - wire.size()) break;
            wire.push_back((uint8_t)length);
            for (size_t j = 0; j < length; ++j) wire.push_back((uint8_t)nextRandom());
        }
        wire.push_back(0);
        uint8_t output[MaxNameLength], folded[MaxNameLength];
        size_t encoded = 999, expanded = 999;
        assert(decode(wire, 0, wire.size(), output, sizeof output, encoded, expanded) == ParseOk);
        assert(encoded == wire.size() && expanded == wire.size());
        assert(!memcmp(output, &wire[0], expanded));
        memcpy(folded, output, expanded);
        size_t position = 0;
        while (folded[position]) {
            uint8_t length = folded[position++];
            for (uint8_t i = 0; i < length; ++i, ++position)
                if (folded[position] >= 'A' && folded[position] <= 'Z')
                    folded[position] += 'a' - 'A';
        }
        assert(namesEqual(output, expanded, folded, expanded));
        size_t cut = nextRandom() % wire.size();
        encoded = expanded = 999;
        assert(decode(wire, 0, cut, output, sizeof output, encoded, expanded) != ParseOk);
        assert(encoded == 999 && expanded == 999);
        assert(decode(wire, 0, wire.size(), output, wire.size() - 1, encoded, expanded) == ParseOutputTooSmall);
        assert(encoded == 999 && expanded == 999);
        size_t offset = 256 + nextRandom() % 12000;
        Bytes compressed(offset, 0);
        compressed.insert(compressed.end(), wire.begin(), wire.end());
        size_t start = compressed.size();
        compressed.push_back((uint8_t)(0xc0 | (offset >> 8)));
        compressed.push_back((uint8_t)offset);
        assert(decode(compressed, start, compressed.size(), output, sizeof output, encoded, expanded) == ParseOk);
        assert(encoded == 2 && expanded == wire.size());
        assert(namesEqual(output, expanded, &wire[0], wire.size()));
        // Arbitrary data also exercises all failure exits with immutable metadata.
        Bytes arbitrary(nextRandom() % 384);
        for (size_t i = 0; i < arbitrary.size(); ++i) arbitrary[i] = (uint8_t)nextRandom();
        start = arbitrary.empty() ? 0 : nextRandom() % arbitrary.size();
        size_t end = start + (nextRandom() % (arbitrary.size() - start + 1));
        encoded = expanded = 999;
        ParseStatus status = decode(arbitrary, start, end, output, sizeof output, encoded, expanded);
        if (status == ParseOk) {
            assert(encoded && encoded <= end - start);
            assert(expanded && expanded <= MaxNameLength);
            assert(namesEqual(output, expanded, output, expanded));
            size_t plainEncoded, plainExpanded;
            assert(decodeName(PacketView(output, expanded), 0, expanded, folded,
                              sizeof folded, plainEncoded, plainExpanded) == ParseOk);
            assert(plainEncoded == expanded && plainExpanded == expanded);
            assert(!memcmp(output, folded, expanded));
        } else {
            assert(encoded == 999 && expanded == 999);
        }
        DnsHeader header;
        (void)validatePacket(view(arbitrary), header);
    }
}

int main() {
    testCursor();
    testNames();
    testRecords();
    testGenerated();
    puts("dns_packet: boundary tests and 20000 deterministic generated cases passed");
    return 0;
}
