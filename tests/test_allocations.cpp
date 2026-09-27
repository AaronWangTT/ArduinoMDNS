#include "host/FakeUDP.h"
#include <MDNS.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Link with --wrap=malloc,--wrap=calloc,--wrap=free. Disable allocator builtins
// for every production translation unit so optimization cannot evade wrapping.
extern "C" void* __real_malloc(size_t);
extern "C" void* __real_calloc(size_t, size_t);
extern "C" void __real_free(void*);

uint32_t mdnsTestMillis = 3000;

namespace {
struct Allocation {
    void* pointer;
    size_t bytes;
};
Allocation allocations[128] = {};
size_t liveCount = 0, liveBytes = 0;
size_t attempts = 0, failAt = 0, injectedFailures = 0;
size_t peakLiveCount = 0, peakLiveBytes = 0, maxSingleAllocation = 0;

bool failAllocation() {
    ++attempts;
    if (failAt && attempts == failAt) {
        ++injectedFailures;
        return true;
    }
    return false;
}

void remember(void* pointer, size_t bytes) {
    assert(pointer);
    for (size_t i = 0; i < sizeof allocations / sizeof allocations[0]; ++i) {
        if (!allocations[i].pointer) {
            allocations[i].pointer = pointer;
            allocations[i].bytes = bytes;
            ++liveCount;
            liveBytes += bytes;
            if (liveCount > peakLiveCount) peakLiveCount = liveCount;
            if (liveBytes > peakLiveBytes) peakLiveBytes = liveBytes;
            if (bytes > maxSingleAllocation) maxSingleAllocation = bytes;
            return;
        }
    }
    assert(!"allocation tracking table exhausted");
    abort();
}

void arm(size_t position) {
    attempts = 0;
    injectedFailures = 0;
    failAt = position;
    peakLiveCount = liveCount;
    peakLiveBytes = liveBytes;
    maxSingleAllocation = 0;
    for (size_t i = 0; i < sizeof allocations / sizeof allocations[0]; ++i)
        if (allocations[i].pointer && allocations[i].bytes > maxSingleAllocation)
            maxSingleAllocation = allocations[i].bytes;
}

void disarm() { failAt = 0; }

void printHeap(const char* scenario) {
    printf("heap: %s: peak_live_bytes=%zu peak_live_allocations=%zu max_single=%zu\n",
           scenario, peakLiveBytes, peakLiveCount, maxSingleAllocation);
}

void assertEmpty() {
    assert(liveCount == 0 && liveBytes == 0);
    for (size_t i = 0; i < sizeof allocations / sizeof allocations[0]; ++i)
        assert(!allocations[i].pointer);
}

typedef std::vector<uint8_t> Bytes;

void u16(Bytes& bytes, unsigned value) {
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

Bytes wire(const char* dotted) {
    Bytes bytes;
    while (*dotted) {
        const char* dot = strchr(dotted, '.');
        size_t length = dot ? static_cast<size_t>(dot - dotted) : strlen(dotted);
        assert(length && length <= 63);
        bytes.push_back(static_cast<uint8_t>(length));
        bytes.insert(bytes.end(), dotted, dotted + length);
        dotted += length;
        if (*dotted) ++dotted;
    }
    bytes.push_back(0);
    return bytes;
}

void record(Bytes& packet, const char* owner, unsigned type, const Bytes& rdata) {
    Bytes name = wire(owner);
    packet.insert(packet.end(), name.begin(), name.end());
    u16(packet, type);
    u16(packet, 1);
    u16(packet, 0);
    u16(packet, 120);
    u16(packet, static_cast<unsigned>(rdata.size()));
    packet.insert(packet.end(), rdata.begin(), rdata.end());
}

Bytes hostQuestion(const char* name) {
    Bytes packet(12, 0);
    packet[5] = 1;
    Bytes owner = wire(name);
    packet.insert(packet.end(), owner.begin(), owner.end());
    u16(packet, 1);
    u16(packet, 1);
    return packet;
}

Bytes hostResponse() {
    Bytes packet(12, 0);
    packet[2] = 0x84;
    packet[7] = 1;
    const uint8_t address[] = {192, 168, 1, 42};
    record(packet, "target.local", 1, Bytes(address, address + sizeof address));
    return packet;
}

Bytes serviceResponse(size_t txtLength = 4) {
    Bytes packet(12, 0);
    packet[2] = 0x84;
    packet[7] = 4;
    record(packet, "_http._tcp.local", 12, wire("Printer._http._tcp.local"));
    Bytes srv(6, 0);
    srv[5] = 80;
    Bytes target = wire("peer.local");
    srv.insert(srv.end(), target.begin(), target.end());
    record(packet, "Printer._http._tcp.local", 33, srv);
    const uint8_t txt[] = {3, 'x', '=', 'y'};
    record(packet, "Printer._http._tcp.local", 16,
           txtLength == sizeof txt ? Bytes(txt, txt + sizeof txt) : Bytes(txtLength, 0));
    const uint8_t address[] = {192, 168, 1, 42};
    record(packet, "peer.local", 1, Bytes(address, address + sizeof address));
    assert(packet.size() <= MDNS_MAX_PACKET_SIZE);
    return packet;
}

void ignoreHost(const char*, IPAddress) {}
void ignoreService(const char*, MDNSServiceProtocol_t, const char*, IPAddress,
                   unsigned short, const uint8_t*, size_t) {}

void verifyHostName(MDNS& node, FakeUDP& udp, const char* dotted) {
    const size_t count = udp.sent.size();
    udp.enqueue(hostQuestion(dotted));
    node.run();
    assert(node.lastError() == MDNSSuccess);
    assert(udp.sent.size() == count + 1);
    Bytes expected = wire(dotted);
    const Bytes& response = udp.sent.back();
    assert(response.size() >= 12 + expected.size());
    assert(!memcmp(&response[12], &expected[0], expected.size()));
}

enum Operation { Begin, SetName, AddService, Resolve, Discover };
const char* operationNames[] = {"begin", "setName", "addServiceRecord", "resolveName",
                                "startDiscoveringService"};

size_t operationCase(Operation operation, size_t failure) {
    assertEmpty();
    mdnsTestMillis = 3000;
    size_t measured = 0;
    FakeUDP udp;
    {
        MDNS node(udp);
        node.setNameResolvedCallback(ignoreHost);
        node.setServiceFoundBinaryCallback(ignoreService);
        if (operation != Begin) assert(node.begin(IPAddress(192, 168, 1, 1), "original"));
        if (operation == SetName)
            assert(node.addServiceRecord("Existing._http", 80, MDNSServiceTCP));
        const size_t beforeCount = liveCount, beforeBytes = liveBytes;
        const size_t sentBefore = udp.sent.size();
        arm(failure);
        int result = 0;
        const uint8_t txt[] = {3, 'a', '=', 'b'};
        switch (operation) {
        case Begin:
            result = node.begin(IPAddress(192, 168, 1, 1), "original");
            break;
        case SetName:
            result = node.setName("replacement");
            break;
        case AddService:
            result = node.addServiceRecord("Printer._http", 80, MDNSServiceTCP, txt, sizeof txt);
            break;
        case Resolve:
            result = node.resolveName("target", 60000);
            break;
        case Discover:
            result = node.startDiscoveringService("_http", MDNSServiceTCP, 60000);
            break;
        }
        measured = attempts;
        disarm();
        if (!failure) printHeap(operationNames[operation]);
        if (failure) {
            assert(injectedFailures == 1 && result == 0);
            assert(node.lastError() == MDNSOutOfMemory);
            assert(liveCount == beforeCount && liveBytes == beforeBytes);
            assert(udp.sent.size() == sentBefore);
            assert(!node.isResolvingName() && !node.isDiscoveringService());
            if (operation == SetName) {
                verifyHostName(node, udp, "original.local");
                const size_t count = udp.sent.size();
                udp.enqueue(hostQuestion("replacement.local"));
                node.run();
                assert(udp.sent.size() == count);
            }
            if (operation == AddService) {
                node.removeServiceRecord("Printer._http", 80, MDNSServiceTCP);
                assert(node.lastError() == MDNSNotFound);
                assert(node.addServiceRecord("Printer._http", 80, MDNSServiceTCP, txt, sizeof txt));
                node.removeAllServiceRecords();
                assert(liveCount == beforeCount && liveBytes == beforeBytes);
            }
            if (operation == Resolve) {
                assert(node.resolveName("target", 60000));
                assert(node.isResolvingName());
                node.cancelResolveName();
                assert(liveCount == beforeCount && liveBytes == beforeBytes);
            }
            if (operation == Discover) {
                assert(node.startDiscoveringService("_http", MDNSServiceTCP, 60000));
                assert(node.isDiscoveringService());
                node.stopDiscoveringService();
                assert(liveCount == beforeCount && liveBytes == beforeBytes);
            }
            if (operation == Begin) {
                assert(node.begin(IPAddress(192, 168, 1, 1), "original"));
                verifyHostName(node, udp, "original.local");
            }
        } else {
            assert(result != 0 && injectedFailures == 0);
            assert(node.lastError() == MDNSSuccess);
            assert(node.isResolvingName() == (operation == Resolve));
            assert(node.isDiscoveringService() == (operation == Discover));
            if (operation == SetName) verifyHostName(node, udp, "replacement.local");
            // Successful operations intentionally remain owned until destruction.
        }
    }
    assertEmpty();
    return measured;
}

MDNS* callbackNode = 0;
bool restartInCallback = false;
size_t callbackCount = 0, callbackAllocationPosition = 0;
int restartResult = -1;

void foundHost(const char* name, IPAddress address) {
    ++callbackCount;
    callbackAllocationPosition = attempts;
    assert(strcmp(name, "target") == 0);
    assert(address[0] == 192 && address[3] == 42);
    assert(!callbackNode->isResolvingName());
    if (restartInCallback) {
        restartResult = callbackNode->resolveName("replacement", 60000);
        assert(strcmp(name, "target") == 0);
    }
}

void foundService(const char* type, MDNSServiceProtocol_t protocol,
                  const char* instance, IPAddress address, unsigned short port,
                  const uint8_t* txt, size_t txtLength) {
    ++callbackCount;
    callbackAllocationPosition = attempts;
    assert(strcmp(type, "_http") == 0 && strcmp(instance, "Printer") == 0);
    assert(protocol == MDNSServiceTCP && port == 80 && address[3] == 42);
    const uint8_t expected[] = {3, 'x', '=', 'y'};
    assert(txt && txtLength == sizeof expected && !memcmp(txt, expected, sizeof expected));
    if (restartInCallback) {
        callbackNode->stopDiscoveringService();
        restartResult = callbackNode->startDiscoveringService("_ssh", MDNSServiceTCP, 60000);
        assert(strcmp(type, "_http") == 0 && strcmp(instance, "Printer") == 0);
        assert(!memcmp(txt, expected, sizeof expected));
    }
}

struct ReceiveCounts {
    size_t total, beforeCallback;
};

ReceiveCounts receiveCase(bool service, bool restart, size_t failure,
                          size_t expectedBeforeCallback) {
    assertEmpty();
    mdnsTestMillis = 3000;
    callbackCount = callbackAllocationPosition = 0;
    restartResult = -1;
    restartInCallback = restart;
    ReceiveCounts measured = {};
    FakeUDP udp;
    {
        MDNS node(udp);
        callbackNode = &node;
        assert(node.begin(IPAddress(192, 168, 1, 1), "original"));
        const size_t idleCount = liveCount, idleBytes = liveBytes;
        node.setNameResolvedCallback(foundHost);
        node.setServiceFoundBinaryCallback(foundService);
        if (service) assert(node.startDiscoveringService("_http", MDNSServiceTCP, 60000));
        else assert(node.resolveName("target", 60000));
        const size_t activeCount = liveCount, activeBytes = liveBytes;
        const Bytes response = service ? serviceResponse() : hostResponse();
        udp.enqueue(response);
        arm(failure);
        node.run();
        measured.total = attempts;
        measured.beforeCallback = callbackAllocationPosition;
        disarm();
        if (!failure)
            printHeap(service ? (restart ? "service RX + callback restart" : "service RX")
                              : (restart ? "host RX + callback restart" : "host RX"));
        if (failure) {
            assert(injectedFailures == 1 && node.lastError() == MDNSOutOfMemory);
            if (failure <= expectedBeforeCallback) {
                assert(callbackCount == 0);
                assert(liveCount == activeCount && liveBytes == activeBytes);
                assert(service ? node.isDiscoveringService() : node.isResolvingName());
                udp.enqueue(response);
                node.run();
                assert(node.lastError() == MDNSSuccess && callbackCount == 1);
                if (restart) assert(restartResult != 0);
            } else {
                assert(restart && callbackCount == 1 && restartResult == 0);
                assert(!node.isResolvingName() && !node.isDiscoveringService());
                assert(liveCount == idleCount && liveBytes == idleBytes);
            }
        } else {
            assert(injectedFailures == 0 && node.lastError() == MDNSSuccess);
            assert(callbackCount == 1);
            if (restart) assert(restartResult != 0);
        }
        if (!restart && !service) {
            assert(!node.isResolvingName());
            assert(liveCount == idleCount && liveBytes == idleBytes);
        }
        if (!restart && service) {
            assert(node.isDiscoveringService());
            assert(liveCount == activeCount && liveBytes == activeBytes);
        }
        node.cancelResolveName();
        node.stopDiscoveringService();
        assert(liveCount == idleCount && liveBytes == idleBytes);
    }
    callbackNode = 0;
    assertEmpty();
    return measured;
}

void failedBeginReplacement() {
    assertEmpty();
    FakeUDP udp;
    {
        MDNS node(udp);
        assert(node.begin(IPAddress(192, 168, 1, 1), "original"));
        node.setNameResolvedCallback(ignoreHost);
        assert(node.resolveName("target", 60000));
        const size_t beforeCount = liveCount, beforeBytes = liveBytes;
        arm(1);
        assert(!node.begin(IPAddress(192, 168, 1, 2), "replacement"));
        disarm();
        assert(injectedFailures == 1 && node.lastError() == MDNSOutOfMemory);
        assert(node.isResolvingName());
        assert(liveCount == beforeCount && liveBytes == beforeBytes);
        printHeap("failed begin replacement");
        verifyHostName(node, udp, "original.local");
    }
    assertEmpty();
}

void populatedDestructor() {
    assertEmpty();
    arm(0);
    FakeUDP udp;
    {
        MDNS node(udp);
        assert(node.begin(IPAddress(192, 168, 1, 1), "original"));
        node.setNameResolvedCallback(ignoreHost);
        node.setServiceFoundBinaryCallback(ignoreService);
        const uint8_t txt[] = {3, 'a', '=', 'b'};
        for (unsigned i = 0; i < NumMDNSServiceRecords; ++i) {
            char name[32];
            snprintf(name, sizeof name, "Printer%u._http", i);
            assert(node.addServiceRecord(name, static_cast<uint16_t>(8000 + i),
                                         MDNSServiceTCP, txt, sizeof txt));
        }
        const size_t beforeCount = liveCount, beforeBytes = liveBytes;
        assert(!node.addServiceRecord("Overflow._http", 9000, MDNSServiceTCP));
        assert(node.lastError() == MDNSResourceLimit);
        assert(liveCount == beforeCount && liveBytes == beforeBytes);
        assert(node.resolveName("target", 60000));
        assert(node.startDiscoveringService("_http", MDNSServiceTCP, 60000));
        assert(node.isResolvingName() && node.isDiscoveringService());
        printHeap("full registrations + both queries");
    }
    assertEmpty();
}

size_t maximumCallbackCount = 0;

void maximumService(const char* type, MDNSServiceProtocol_t protocol,
                    const char* instance, IPAddress address, unsigned short port,
                    const uint8_t* txt, size_t txtLength) {
    ++maximumCallbackCount;
    assert(!strcmp(type, "_http") && !strcmp(instance, "Printer"));
    assert(protocol == MDNSServiceTCP && address[3] == 42 && port == 80);
    assert(txt && txtLength == MDNS_MAX_TXT_SIZE);
    if (txtLength == 4) {
        const uint8_t expected[] = {3, 'x', '=', 'y'};
        assert(!memcmp(txt, expected, sizeof expected));
    } else {
        for (size_t i = 0; i < txtLength; ++i) assert(txt[i] == 0);
    }
    callbackNode->stopDiscoveringService();
    assert(callbackNode->startDiscoveringService("_ssh", MDNSServiceTCP, 60000));
    assert(!strcmp(type, "_http") && !strcmp(instance, "Printer"));
    printHeap("maximum packet/TXT inside callback restart");
}

void maximumReceive() {
    assertEmpty();
    mdnsTestMillis = 3000;
    maximumCallbackCount = 0;
    FakeUDP udp;
    {
        MDNS node(udp);
        callbackNode = &node;
        assert(node.begin(IPAddress(192, 168, 1, 1), "original"));
        node.setServiceFoundBinaryCallback(maximumService);
        assert(node.startDiscoveringService("_http", MDNSServiceTCP, 60000));
        Bytes packet = serviceResponse(MDNS_MAX_TXT_SIZE);
        // An unsupported RR pads to the exact accepted packet cap without
        // inventing undeclared trailing bytes or changing the discovered service.
        assert(packet.size() + 11 <= MDNS_MAX_PACKET_SIZE);
        record(packet, "", 65000, Bytes(MDNS_MAX_PACKET_SIZE - packet.size() - 11, 0));
        packet[7] = 5;
        assert(packet.size() == MDNS_MAX_PACKET_SIZE);
        udp.enqueue(packet);
        arm(0);
        node.run();
        assert(node.lastError() == MDNSSuccess);
        assert(maximumCallbackCount == 1 && node.isDiscoveringService());
        printHeap("maximum packet/TXT complete RX");
    }
    callbackNode = 0;
    assertEmpty();
}
} // namespace

extern "C" void* __wrap_malloc(size_t bytes) {
    if (failAllocation()) return 0;
    void* pointer = __real_malloc(bytes);
    remember(pointer, bytes);
    return pointer;
}

extern "C" void* __wrap_calloc(size_t count, size_t bytes) {
    if (failAllocation()) return 0;
    assert(!bytes || count <= static_cast<size_t>(-1) / bytes);
    void* pointer = __real_calloc(count, bytes);
    remember(pointer, count * bytes);
    return pointer;
}

extern "C" void __wrap_free(void* pointer) {
    if (!pointer) return;
    for (size_t i = 0; i < sizeof allocations / sizeof allocations[0]; ++i) {
        if (allocations[i].pointer == pointer) {
            --liveCount;
            liveBytes -= allocations[i].bytes;
            allocations[i].pointer = 0;
            allocations[i].bytes = 0;
            __real_free(pointer);
            return;
        }
    }
    assert(!"free of untracked or already freed production allocation");
    abort();
}

int main() {
    size_t failuresTested = 0;
    printf("heap ABI: pointer=%zu size_t=%zu MDNS=%zu packet_cap=%u TXT_cap=%u"
           " (requested production heap only; excludes allocator/FakeUDP/stack)\n",
           sizeof(void*), sizeof(size_t), sizeof(MDNS),
           unsigned(MDNS_MAX_PACKET_SIZE), unsigned(MDNS_MAX_TXT_SIZE));
    for (unsigned operation = Begin; operation <= Discover; ++operation) {
        const size_t count = operationCase(static_cast<Operation>(operation), 0);
        assert(count);
        for (size_t failure = 1; failure <= count; ++failure) {
            operationCase(static_cast<Operation>(operation), failure);
            ++failuresTested;
        }
        printf("allocations: %s: all %zu failure positions passed\n", operationNames[operation], count);
    }
    for (unsigned service = 0; service < 2; ++service) {
        for (unsigned restart = 0; restart < 2; ++restart) {
            ReceiveCounts counts = receiveCase(service != 0, restart != 0, 0, 0);
            assert(counts.total && counts.beforeCallback);
            for (size_t failure = 1; failure <= counts.total; ++failure) {
                receiveCase(service != 0, restart != 0, failure, counts.beforeCallback);
                ++failuresTested;
            }
            printf("allocations: %s RX%s: all %zu failure positions passed\n",
                   service ? "service" : "host", restart ? " + callback restart" : "",
                   counts.total);
        }
    }
    failedBeginReplacement();
    populatedDestructor();
    maximumReceive();
    assertEmpty();
    printf("allocations: %zu injected positions, failed begin replacement, and full destructor passed\n",
           failuresTested);
    return 0;
}
