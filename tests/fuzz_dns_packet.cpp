#include "../utility/DnsPacket.h"

#include <assert.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mdns::PacketView packet(data, size);
    mdns::DnsHeader header;
    (void)mdns::validatePacket(packet, header);
    uint8_t output[mdns::MaxNameLength], roundtrip[mdns::MaxNameLength];
    const size_t starts[] = {0, size / 2, size ? size - 1 : 0};
    for (unsigned i = 0; i < sizeof starts / sizeof starts[0]; ++i) {
        size_t start = starts[i];
        size_t ends[] = {size, start + (size - start) / 2};
        for (unsigned j = 0; j < 2; ++j) {
            size_t encoded = (size_t)-1, expanded = (size_t)-1;
            mdns::ParseStatus status = mdns::decodeName(packet, start, ends[j],
                output, sizeof output, encoded, expanded);
            size_t checkEncoded = (size_t)-1, checkExpanded = (size_t)-1;
            mdns::ParseStatus checked = mdns::decodeName(packet, start, ends[j],
                0, 0, checkEncoded, checkExpanded);
            assert(status == checked);
            if (status == mdns::ParseOk) {
                assert(encoded && encoded <= ends[j] - start);
                assert(expanded && expanded <= mdns::MaxNameLength);
                assert(checkEncoded == encoded && checkExpanded == expanded);
                assert(mdns::namesEqual(output, expanded, output, expanded));
                size_t plainEncoded = 0, plainExpanded = 0;
                assert(mdns::decodeName(mdns::PacketView(output, expanded), 0,
                    expanded, roundtrip, sizeof roundtrip,
                    plainEncoded, plainExpanded) == mdns::ParseOk);
                assert(plainEncoded == expanded && plainExpanded == expanded);
                assert(!memcmp(output, roundtrip, expanded));
            } else {
                assert(encoded == (size_t)-1 && expanded == (size_t)-1);
                assert(checkEncoded == (size_t)-1 && checkExpanded == (size_t)-1);
            }
        }
    }
    return 0;
}
