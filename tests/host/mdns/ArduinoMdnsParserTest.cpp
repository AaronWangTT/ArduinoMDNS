#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

#include <ArduinoMDNS.h>

static_assert(
    !std::is_copy_constructible<MDNS>::value,
    "MDNS must not copy owned allocations or its borrowed transport");
static_assert(
    !std::is_copy_assignable<MDNS>::value,
    "MDNS must not copy owned allocations or its borrowed transport");

unsigned long testMillis = 4000;
int serviceCallbacks = 0;
unsigned short lastServicePort = 0;
bool failNextMalloc = false;
int mallocCalls = 0;
MDNS* callbackMdns = NULL;
int nameCallbacks = 0;

extern "C" void *__real_malloc(size_t size);

extern "C" void *__wrap_malloc(size_t size)
{
    if (failNextMalloc) {
        failNextMalloc = false;
        return NULL;
    }
    ++mallocCalls;
    return __real_malloc(size);
}

unsigned long millis()
{
    return testMillis;
}

void delay(unsigned long milliseconds)
{
    testMillis += milliseconds;
}

class PacketTransport {
public:
    PacketTransport()
        : offset(0), sender(192, 0, 2, 20), senderPort(5353),
          sends(0), writes(0), open(false), allowSend(true),
          shortWriteOnCall(0) {}

    uint8_t beginMulticast(IPAddress, uint16_t) {
        open = true;
        return 1;
    }

    void stop() {
        open = false;
        packet.clear();
        offset = 0;
    }

    int beginPacket(IPAddress, uint16_t) {
        output.clear();
        return open ? 1 : 0;
    }

    size_t write(const uint8_t *buffer, size_t size) {
        ++writes;
        size_t written = size;
        if (writes == shortWriteOnCall && size > 0) {
            written = size - 1;
        }
        output.insert(output.end(), buffer, buffer + written);
        return written;
    }

    int endPacket() {
        ++sends;
        return allowSend ? 1 : 0;
    }

    int parsePacket() {
        return static_cast<int>(packet.size());
    }

    int read(uint8_t *buffer, size_t size) {
        size_t available = packet.size() - offset;
        size = std::min(size, available);
        std::memcpy(buffer, packet.data() + offset, size);
        offset += size;
        return static_cast<int>(size);
    }

    void flush() {
        packet.clear();
        offset = 0;
    }

    IPAddress remoteIP() {
        return sender;
    }

    uint16_t remotePort() {
        return senderPort;
    }

    void queue(const uint8_t *data, size_t size) {
        packet.assign(data, data + size);
        offset = 0;
    }

    std::vector<uint8_t> packet;
    std::vector<uint8_t> output;
    size_t offset;
    IPAddress sender;
    uint16_t senderPort;
    int sends;
    int writes;
    bool open;
    bool allowSend;
    int shortWriteOnCall;
};

#define REQUIRE(condition) \
    do { \
        if (!(condition)) { \
            std::fprintf(stderr, "%s:%d: requirement failed: %s\n", \
                         __FILE__, __LINE__, #condition); \
            return false; \
        } \
    } while (0)

void ignoreService(
    const char *, MDNSServiceProtocol_t, const char *,
    IPAddress, unsigned short port, const char *)
{
    ++serviceCallbacks;
    lastServicePort = port;
}

void ignoreName(const char *, IPAddress)
{
}

void restartNameFromCallback(const char *, IPAddress)
{
    ++nameCallbacks;
    callbackMdns->resolveName("replacement", 1000);
}

void stopDiscoveryFromCallback(
    const char *, MDNSServiceProtocol_t, const char *,
    IPAddress, unsigned short port, const char *)
{
    ++serviceCallbacks;
    lastServicePort = port;
    callbackMdns->stopDiscoveringService();
}

void restartServiceFromCallback(
    const char *, MDNSServiceProtocol_t, const char *,
    IPAddress, unsigned short, const char *)
{
    ++serviceCallbacks;
    callbackMdns->startDiscoveringService("_ssh", MDNSServiceTCP, 1000);
}

void append16(std::vector<uint8_t> &packet, uint16_t value)
{
    packet.push_back(static_cast<uint8_t>(value >> 8));
    packet.push_back(static_cast<uint8_t>(value));
}

void append32(std::vector<uint8_t> &packet, uint32_t value)
{
    packet.push_back(static_cast<uint8_t>(value >> 24));
    packet.push_back(static_cast<uint8_t>(value >> 16));
    packet.push_back(static_cast<uint8_t>(value >> 8));
    packet.push_back(static_cast<uint8_t>(value));
}

void appendPointer(std::vector<uint8_t> &packet, uint16_t offset)
{
    packet.push_back(static_cast<uint8_t>(0xc0 | ((offset >> 8) & 0x3f)));
    packet.push_back(static_cast<uint8_t>(offset));
}

bool containsBytes(
    const std::vector<uint8_t> &buffer,
    const uint8_t *expected,
    size_t expectedSize)
{
    return std::search(
        buffer.begin(), buffer.end(),
        expected, expected + expectedSize) != buffer.end();
}

void writeHeader(
    std::vector<uint8_t> &packet,
    uint16_t questions,
    uint16_t answers,
    uint16_t additional = 0)
{
    const uint8_t header[] = {
        0x00, 0x00, 0x80, 0x00,
        static_cast<uint8_t>(questions >> 8),
        static_cast<uint8_t>(questions),
        static_cast<uint8_t>(answers >> 8),
        static_cast<uint8_t>(answers),
        0x00, 0x00,
        static_cast<uint8_t>(additional >> 8),
        static_cast<uint8_t>(additional)
    };
    packet.assign(header, header + sizeof(header));
}

bool removingMissingServiceRecordIsSafe()
{
    PacketTransport transport;
    MDNS mdns(transport, false);

    mdns.removeServiceRecord(80, MDNSServiceTCP);
    mdns.removeServiceRecord("missing._http", 80, MDNSServiceTCP);
    return true;
}

bool failedNameReplacementPreservesObject()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.setName("first") == 1);

    failNextMalloc = true;
    REQUIRE(mdns.setName("replacement") == 0);
    REQUIRE(mdns.setName("working") == 1);
    return true;
}

bool invalidServiceNamesAreRejected()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    int sendsBeforeInvalidNames = transport.sends;

    REQUIRE(mdns.addServiceRecord("http", 80, MDNSServiceTCP) == 0);
    REQUIRE(mdns.addServiceRecord(".http", 80, MDNSServiceTCP) == 0);
    REQUIRE(mdns.addServiceRecord("http.", 80, MDNSServiceTCP) == 0);
    REQUIRE(mdns.addServiceRecord(
        "device._http", 80, static_cast<MDNSServiceProtocol_t>(99)) == 0);
    REQUIRE(transport.sends == sendsBeforeInvalidNames);
    REQUIRE(mdns.addServiceRecord("device._http", 80, MDNSServiceTCP) == 1);
    return true;
}

bool invalidDnsNamesAreRejected()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    std::string oversizedLabel(64, 'a');
    std::string oversizedName;
    for (int i = 0; i < 4; ++i) {
        if (!oversizedName.empty()) {
            oversizedName += '.';
        }
        oversizedName += std::string(63, static_cast<char>('a' + i));
    }

    REQUIRE(mdns.setName(NULL) == 0);
    REQUIRE(mdns.setName("") == 0);
    REQUIRE(mdns.setName(oversizedLabel.c_str()) == 0);
    REQUIRE(mdns.setName(oversizedName.c_str()) == 0);
    REQUIRE(mdns.resolveName(NULL, 1000) == 0);
    mdns.setServiceFoundCallback(ignoreService);
    REQUIRE(mdns.startDiscoveringService(NULL, MDNSServiceTCP, 1000) == 0);
    REQUIRE(mdns.startDiscoveringService(
        oversizedLabel.c_str(), MDNSServiceTCP, 1000) == 0);
    return true;
}

bool serviceTxtUsesDnsCharacterStringEncoding()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    REQUIRE(mdns.addServiceRecord(
        "device._http", 80, MDNSServiceTCP, "path=/") == 1);

    const uint8_t expected[] = {
        0x00, 0x10, 0x80, 0x01,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x07, 0x06,
        'p', 'a', 't', 'h', '=', '/'
    };
    REQUIRE(containsBytes(transport.output, expected, sizeof(expected)));

    std::vector<char> oversized(257, 'x');
    oversized[256] = '\0';
    int sendsBeforeOversizedText = transport.sends;
    REQUIRE(mdns.addServiceRecord(
        "other._http", 80, MDNSServiceTCP, oversized.data()) == 0);
    REQUIRE(transport.sends == sendsBeforeOversizedText);
    return true;
}

bool failedRegistrationReleasesServiceSlot()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    transport.allowSend = false;
    REQUIRE(mdns.addServiceRecord(
        "failed._http", 80, MDNSServiceTCP) == 0);

    transport.allowSend = true;
    const char* names[] = {
        "one._http", "two._http", "three._http", "four._http",
        "five._http", "six._http", "seven._http", "eight._http"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        REQUIRE(mdns.addServiceRecord(names[i], 80, MDNSServiceTCP) == 1);
    }
    return true;
}

bool failedInitialQueriesReleaseState()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setNameResolvedCallback(ignoreName);
    mdns.setServiceFoundCallback(ignoreService);
    transport.allowSend = false;

    REQUIRE(mdns.resolveName("device", 0) == 0);
    REQUIRE(mdns.isResolvingName() == 0);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 0) == 0);
    REQUIRE(mdns.isDiscoveringService() == 0);
    return true;
}

bool timeoutCallbacksPreserveReplacementQueries()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    callbackMdns = &mdns;

    nameCallbacks = 0;
    mdns.setNameResolvedCallback(restartNameFromCallback);
    REQUIRE(mdns.resolveName("first", 1) == 1);
    testMillis += 2;
    mdns.run();
    REQUIRE(nameCallbacks == 1);
    REQUIRE(mdns.isResolvingName() == 1);
    mdns.cancelResolveName();

    serviceCallbacks = 0;
    mdns.setServiceFoundCallback(restartServiceFromCallback);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1) == 1);
    testMillis += 2;
    mdns.run();
    REQUIRE(serviceCallbacks == 1);
    REQUIRE(mdns.isDiscoveringService() == 1);
    mdns.stopDiscoveringService();
    callbackMdns = NULL;
    return true;
}

bool serviceQueryUsesFourByteTrailer()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setServiceFoundCallback(ignoreService);

    REQUIRE(mdns.startDiscoveringService(
        "_http", MDNSServiceTCP, 1000) == 1);
    REQUIRE(transport.output.size() == 34);
    const uint8_t expectedTrailer[] = {0x00, 0x0c, 0x00, 0x01};
    REQUIRE(std::equal(
        expectedTrailer, expectedTrailer + sizeof(expectedTrailer),
        transport.output.end() - sizeof(expectedTrailer)));
    return true;
}

bool compressedQueryUsesFullPersistentOffset()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);

    const uint8_t addressQuery[] = {
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        6, 'a', 'z', '3', '1', '6', '6',
        5, 'l', 'o', 'c', 'a', 'l', 0,
        0, 1, 0, 1
    };
    transport.queue(addressQuery, sizeof(addressQuery));
    mdns.run();
    REQUIRE(transport.sends == 1);

    PacketTransport compressedTransport;
    MDNS compressedMdns(compressedTransport, false);
    REQUIRE(compressedMdns.begin(
        IPAddress(192, 0, 2, 10), "az3166") == 1);
    std::vector<uint8_t> packet;
    writeHeader(packet, 2, 0);
    packet[2] = 0;
    const uint8_t firstQuestion[] = {
        0x06, 'a', 'z', '3', '1', '6', '6',
        0x05, 'l', 'o', 'c', 'a', 'l',
        0x00,
        0x00, 0x02,
        0x00, 0x01
    };
    packet.insert(
        packet.end(), firstQuestion,
        firstQuestion + sizeof(firstQuestion));
    appendPointer(packet, 12);
    append16(packet, 1);
    append16(packet, 1);
    compressedTransport.queue(packet.data(), packet.size());
    int sendsBeforeQuery = compressedTransport.sends;
    compressedMdns.run();

    REQUIRE(compressedTransport.sends == sendsBeforeQuery + 1);
    return true;
}

bool truncatedResponseNameIsRejected()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setServiceFoundCallback(ignoreService);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1000) == 1);
    serviceCallbacks = 0;
    int sendsBeforeMalformedPacket = transport.sends;

    std::vector<uint8_t> packet;
    writeHeader(packet, 0, 1);
    packet.push_back(5);
    packet.push_back('a');
    transport.queue(packet.data(), packet.size());
    mdns.run();

    REQUIRE(transport.sends == sendsBeforeMalformedPacket);
    return true;
}

bool undersizedPtrRecordIsRejected()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setServiceFoundCallback(ignoreService);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1000) == 1);

    std::vector<uint8_t> packet;
    writeHeader(packet, 0, 1);
    const uint8_t record[] = {
        0xc0, 0x0c,
        0x00, 0x0c,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x01,
        0x00
    };
    packet.insert(packet.end(), record, record + sizeof(record));
    transport.queue(packet.data(), packet.size());
    mdns.run();

    REQUIRE(serviceCallbacks == 0);
    return true;
}

bool ptrInstanceCannotCrossRdataBoundary()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setServiceFoundCallback(ignoreService);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1000) == 1);

    std::vector<uint8_t> packet;
    writeHeader(packet, 0, 1);
    const uint8_t record[] = {
        0xc0, 0x0c,
        0x00, 0x0c,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x02,
        0x03, 'f',
        'o', 'o'
    };
    packet.insert(packet.end(), record, record + sizeof(record));
    int allocationsBeforePacket = mallocCalls;
    transport.queue(packet.data(), packet.size());
    mdns.run();

    REQUIRE(mallocCalls == allocationsBeforePacket + 1);
    REQUIRE(serviceCallbacks == 0);
    return true;
}

bool failedAnnouncementsAreRetried()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    REQUIRE(mdns.addServiceRecord("device._http", 80, MDNSServiceTCP) == 1);

    testMillis = 100000;
    transport.allowSend = false;
    REQUIRE(mdns.announce() == 0);
    int sendsAfterFailure = transport.sends;

    transport.allowSend = true;
    mdns.run();
    REQUIRE(transport.sends == sendsAfterFailure + 1);
    return true;
}

bool shortWritesFailTheSend()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setNameResolvedCallback(ignoreName);

    transport.shortWriteOnCall = 2;
    REQUIRE(mdns.resolveName("device", 1000) == 0);
    REQUIRE(mdns.isResolvingName() == 0);
    REQUIRE(transport.sends == 0);
    return true;
}

bool undersizedSrvRecordIsRejected()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    mdns.setServiceFoundCallback(ignoreService);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1000) == 1);
    serviceCallbacks = 0;

    std::vector<uint8_t> packet;
    writeHeader(packet, 0, 1, 1);
    packet[11] = 1;
    const uint8_t ptrRecord[] = {
        0xc0, 0x0c,
        0x00, 0x0c, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x06,
        0x03, 'f', 'o', 'o', 0xc0, 0x0c
    };
    packet.insert(packet.end(), ptrRecord, ptrRecord + sizeof(ptrRecord));
    const uint8_t srvRecord[] = {
        0xc0, 0x18,
        0x00, 0x21, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00
    };
    packet.insert(packet.end(), srvRecord, srvRecord + sizeof(srvRecord));
    transport.queue(packet.data(), packet.size());
    mdns.run();

    REQUIRE(serviceCallbacks == 0);
    return true;
}

bool preservesFullCompressionOffsets()
{
    PacketTransport transport;
    MDNS mdns(transport, false);
    REQUIRE(mdns.begin(IPAddress(192, 0, 2, 10), "az3166") == 1);
    callbackMdns = &mdns;
    mdns.setServiceFoundCallback(stopDiscoveryFromCallback);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1000) == 1);
    serviceCallbacks = 0;
    lastServicePort = 0;

    std::vector<uint8_t> packet;
    writeHeader(packet, 1, 1, 2);
    packet.push_back(3);
    packet.push_back('f');
    packet.push_back('o');
    packet.push_back('o');
    for (int label = 0; label < 4; ++label) {
        packet.push_back(61);
        packet.insert(packet.end(), 61, static_cast<uint8_t>('a' + label));
    }
    packet.push_back(0);
    append16(packet, 1);
    append16(packet, 1);

    appendPointer(packet, 12);
    append16(packet, 12);
    append16(packet, 1);
    append32(packet, 120);
    append16(packet, 2);
    uint16_t ptrNameOffset = static_cast<uint16_t>(packet.size());
    appendPointer(packet, 12);
    REQUIRE(ptrNameOffset > 255);

    appendPointer(packet, 12);
    append16(packet, 33);
    append16(packet, 1);
    append32(packet, 120);
    append16(packet, 8);
    append16(packet, 0);
    append16(packet, 0);
    append16(packet, 80);
    const uint16_t targetOffset = 0x0123;
    appendPointer(packet, targetOffset);

    appendPointer(packet, targetOffset);
    append16(packet, 1);
    append16(packet, 1);
    append32(packet, 120);
    append16(packet, 4);
    packet.push_back(192);
    packet.push_back(0);
    packet.push_back(2);
    packet.push_back(55);

    transport.queue(packet.data(), packet.size());
    mdns.run();

    REQUIRE(serviceCallbacks == 1);
    REQUIRE(lastServicePort == 80);
    REQUIRE(mdns.isDiscoveringService() == 0);

    callbackMdns = &mdns;
    mdns.setServiceFoundCallback(stopDiscoveryFromCallback);
    REQUIRE(mdns.startDiscoveringService("_http", MDNSServiceTCP, 1000) == 1);
    serviceCallbacks = 0;
    packet[packet.size() - 6] = 0;
    packet[packet.size() - 5] = 3;
    packet.pop_back();
    transport.queue(packet.data(), packet.size());
    mdns.run();
    REQUIRE(serviceCallbacks == 0);
    callbackMdns = NULL;
    return true;
}

struct TestCase {
    const char *name;
    bool (*run)();
};

int main()
{
    const TestCase tests[] = {
        {"compressed query uses persistent offset", compressedQueryUsesFullPersistentOffset},
        {"removing missing service record is safe", removingMissingServiceRecordIsSafe},
        {"failed name replacement preserves object", failedNameReplacementPreservesObject},
        {"invalid service names are rejected", invalidServiceNamesAreRejected},
        {"invalid DNS names are rejected", invalidDnsNamesAreRejected},
        {"service TXT uses DNS character-string encoding", serviceTxtUsesDnsCharacterStringEncoding},
        {"failed registration releases service slot", failedRegistrationReleasesServiceSlot},
        {"failed initial queries release state", failedInitialQueriesReleaseState},
        {"timeout callbacks preserve replacement queries", timeoutCallbacksPreserveReplacementQueries},
        {"service query uses four-byte trailer", serviceQueryUsesFourByteTrailer},
        {"truncated response name is rejected", truncatedResponseNameIsRejected},
        {"undersized PTR record is rejected", undersizedPtrRecordIsRejected},
        {"PTR instance stays within RDATA", ptrInstanceCannotCrossRdataBoundary},
        {"failed announcements are retried", failedAnnouncementsAreRetried},
        {"short writes fail the send", shortWritesFailTheSend},
        {"undersized SRV record is rejected", undersizedSrvRecordIsRejected},
        {"preserves full compression offsets", preservesFullCompressionOffsets},
    };

    int failures = 0;
    for (size_t index = 0; index < sizeof(tests) / sizeof(tests[0]); ++index) {
        if (tests[index].run()) {
            std::printf("PASS: %s\n", tests[index].name);
        } else {
            std::fprintf(stderr, "FAIL: %s\n", tests[index].name);
            ++failures;
        }
    }

    std::printf(
        "%u tests, %d failures\n",
        static_cast<unsigned>(sizeof(tests) / sizeof(tests[0])), failures);
    return failures == 0 ? 0 : 1;
}
