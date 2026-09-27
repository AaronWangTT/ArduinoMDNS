#include "host/FakeUDP.h"
#include <MDNS.h>
#include "utility/DnsPacket.h"
#include <algorithm>
#include <assert.h>
#include <map>
#include <stdio.h>
#include <string>

#ifdef MDNS_TEST_ALLOCATIONS
extern "C" void* __real_malloc(size_t);
extern "C" void* __real_calloc(size_t, size_t);
extern "C" void __real_free(void*);
static int failAllocation = -1;
static void* liveAllocations[1024];
static size_t allocationSizes[1024], liveCount, liveBytes, peakBytes;
static bool shouldFail()
{
   if (failAllocation < 0) return false;
   if (!failAllocation--) { failAllocation = -1; return true; }
   return false;
}
static void* track(void* pointer, size_t size)
{
   if (pointer) {
      assert(liveCount < 1024); liveAllocations[liveCount] = pointer;
      allocationSizes[liveCount++] = size; liveBytes += size;
      peakBytes = std::max(peakBytes, liveBytes);
   }
   return pointer;
}
extern "C" void* __wrap_malloc(size_t size)
{
   return shouldFail() ? NULL : track(__real_malloc(size), size);
}
extern "C" void* __wrap_calloc(size_t count, size_t size)
{
   return shouldFail() ? NULL : track(__real_calloc(count, size), count * size);
}
extern "C" void __wrap_free(void* pointer)
{
   if (pointer) {
      size_t i = 0;
      while (i < liveCount && liveAllocations[i] != pointer) ++i;
      assert(i < liveCount);
      liveBytes -= allocationSizes[i];
      liveAllocations[i] = liveAllocations[--liveCount];
      allocationSizes[i] = allocationSizes[liveCount];
   }
   __real_free(pointer);
}
#endif

uint32_t mdnsTestMillis = 3000;
typedef std::vector<uint8_t> Bytes;

static Bytes dotted(const char* text)
{
   uint8_t wire[255]; size_t length = 0;
   assert(mdns::encodeDottedName(text, wire, sizeof(wire), length) == mdns::ParseOk);
   return Bytes(wire, wire + length);
}
static Bytes instance(const char* text)
{
   Bytes suffix = dotted("_http._tcp.local");
   uint8_t wire[255]; size_t length = 0;
   assert(mdns::prependLabel(reinterpret_cast<const uint8_t*>(text), strlen(text),
                            suffix.data(), suffix.size(), wire, sizeof(wire), length) == mdns::ParseOk);
   return Bytes(wire, wire + length);
}
struct Packet {
   Bytes bytes;
   std::map<std::string, size_t> offsets;
   uint16_t answers = 0;
   explicit Packet(uint16_t flags = 0x8400) : bytes(12, 0) { patch(2, flags); }
   void patch(size_t at, uint16_t n) { bytes[at] = uint8_t(n >> 8); bytes[at + 1] = uint8_t(n); }
   void u16(uint16_t n) { bytes.push_back(uint8_t(n >> 8)); bytes.push_back(uint8_t(n)); }
   void u32(uint32_t n) { u16(uint16_t(n >> 16)); u16(uint16_t(n)); }
   void name(const Bytes& wire) {
      for (size_t p = 0; p < wire.size();) {
         std::string key(reinterpret_cast<const char*>(wire.data() + p), wire.size() - p);
         std::map<std::string, size_t>::iterator found = offsets.find(key);
         if (found != offsets.end()) { u16(uint16_t(0xc000 | found->second)); return; }
         offsets[key] = bytes.size();
         size_t count = wire[p] ? size_t(wire[p]) + 1 : 1;
         bytes.insert(bytes.end(), wire.begin() + p, wire.begin() + p + count);
         p += count;
      }
   }
   size_t rr(const Bytes& owner, uint16_t type, uint32_t ttl = 120) {
      name(owner); u16(type); u16(type == 12 ? 1 : 0x8001); u32(ttl);
      size_t at = bytes.size(); u16(0); ++answers; patch(6, answers); return at;
   }
   void end(size_t at) { patch(at, uint16_t(bytes.size() - at - 2)); }
   void ptr(const char* display = "Printer", uint32_t ttl = 120) {
      size_t at = rr(dotted("_http._tcp.local"), 12, ttl); name(instance(display)); end(at);
   }
   void srv(const char* display = "Printer", const char* host = "device.local",
            uint16_t port = 80, uint32_t ttl = 120) {
      size_t at = rr(instance(display), 33, ttl);
      u16(0); u16(0); u16(port); name(dotted(host)); end(at);
   }
   void txt(const Bytes& value, const char* display = "Printer", uint32_t ttl = 120) {
      size_t at = rr(instance(display), 16, ttl);
      bytes.insert(bytes.end(), value.begin(), value.end()); end(at);
   }
   void a(const char* host = "device.local", uint8_t last = 4, uint32_t ttl = 120) {
      size_t at = rr(dotted(host), 1, ttl);
      bytes.push_back(1); bytes.push_back(2); bytes.push_back(3); bytes.push_back(last); end(at);
   }
   void question(const Bytes& wire, uint16_t type) {
      patch(4, 1); name(wire); u16(type); u16(1);
   }
};
static Packet fullPacket(const char* display = "Printer")
{
   Packet p; p.ptr(display); p.srv(display); p.txt(Bytes{3, 'a', 0, 'b', 0}, display); p.a();
   return p;
}
struct Event {
   std::string type, name;
   uint16_t port;
   uint8_t last;
   bool present, timeout;
   Bytes txt;
};
static std::vector<Event> events;
static std::vector<std::string> hostEvents;
static MDNS* active;
static int action, alternateCalls;
static void alternate(const char*, MDNSServiceProtocol_t, const char*, IPAddress,
                      unsigned short, const uint8_t*, size_t) { ++alternateCalls; }
static void binary(const char* type, MDNSServiceProtocol_t proto, const char* name,
                   IPAddress ip, unsigned short port, const uint8_t* txt, size_t length)
{
   assert(proto == MDNSServiceTCP);
   Event e; e.type = type; e.name = name ? name : ""; e.port = port; e.last = ip[3];
   e.present = txt != NULL; e.timeout = name == NULL;
   if (length) e.txt.assign(txt, txt + length);
   events.push_back(e);
   int perform = action; action = 0;
   if (perform == 1) active->stopDiscoveringService();
   if (perform == 2) {
      active->stopDiscoveringService();
      assert(active->startDiscoveringService("_http", MDNSServiceTCP, 100));
      assert(strcmp(type, "_http") == 0 && name && strcmp(name, "Printer") == 0);
   }
   if (perform == 3) active->run();
   if (perform == 4) active->setServiceFoundBinaryCallback(alternate);
   if (perform == 5) {
      active->removeAllServiceRecords();
      assert(active->addServiceRecord("Replacement._http", 81, MDNSServiceTCP));
   }
   if (perform == 6) {
      mdnsTestMillis += 500;
      assert(active->startDiscoveringService("_http", MDNSServiceTCP, 100));
   }
}
static void legacy(const char* type, MDNSServiceProtocol_t proto, const char* name,
                   IPAddress ip, unsigned short port, const char* txt)
{
   binary(type, proto, name, ip, port, reinterpret_cast<const uint8_t*>(txt),
          txt ? strlen(txt) : 0);
}
static void host(const char* name, IPAddress address)
{
   hostEvents.push_back(name);
   if (action == 7) {
      action = 0;
      assert(active->resolveName("next", 100));
   }
   if (action == 8) {
      action = 0; assert(address[3] == 255);
      mdnsTestMillis += 500;
      assert(active->resolveName("next", 100));
   }
   if (action == 9) {
      action = 0;
      assert(active->startDiscoveringService("_http", MDNSServiceTCP, 100));
   }
}
struct Session {
   FakeUDP udp;
   MDNS mdns;
   Session() : mdns(udp) {
      mdnsTestMillis = 3000; events.clear(); hostEvents.clear(); action = 0; alternateCalls = 0;
      active = &mdns;
      assert(mdns.begin(IPAddress(10, 0, 0, 1), "localHost"));
      mdns.setServiceFoundBinaryCallback(binary); mdns.setNameResolvedCallback(host);
   }
   void discover() { assert(mdns.startDiscoveringService("_http", MDNSServiceTCP, 0)); udp.sent.clear(); }
   void feed(const Packet& p) { udp.enqueue(p.bytes); mdns.run(); }
};
static void validateSent(const FakeUDP& udp)
{
   for (size_t i = 0; i < udp.sent.size(); ++i) {
      mdns::DnsHeader h;
      assert(mdns::validatePacket(mdns::PacketView(udp.sent[i].data(), udp.sent[i].size()), h) == mdns::ParseOk);
   }
}
static Bytes sentTxt(const Bytes& packet)
{
   mdns::PacketCursor cursor(mdns::PacketView(packet.data(), packet.size()));
   mdns::DnsHeader h; assert(mdns::readHeader(cursor, h) == mdns::ParseOk);
   for (uint16_t i = 0; i < h.answers; ++i) {
      mdns::ResourceRecord r; assert(mdns::readRecord(cursor, r) == mdns::ParseOk);
      if (r.type == 16) return Bytes(packet.begin() + r.rdataOffset,
                                     packet.begin() + r.rdataOffset + r.rdataLength);
   }
   assert(false); return Bytes();
}
static void ownershipAndTxt()
{
   Session s;
   s.mdns.removeServiceRecord(80, MDNSServiceTCP);
   assert(s.mdns.lastError() == MDNSNotFound);
   assert(s.mdns.addServiceRecord("Living.Room._http", 80, MDNSServiceTCP, "\x07" "path=/2"));
   assert(sentTxt(s.udp.sent.back()) == Bytes({7,'p','a','t','h','=','/','2'}));
   s.mdns.removeAllServiceRecords();
   Bytes encoded{3, 'a', 0, 'b', 0};
   assert(s.mdns.addServiceRecord("Binary._http", 81, MDNSServiceTCP, encoded.data(), encoded.size()));
   assert(sentTxt(s.udp.sent.back()) == encoded);
   s.mdns.removeServiceRecord("Binary._http", 81, MDNSServiceTCP);
   for (int i = 0; i < 3; ++i) {
      int ok = i == 0 ? s.mdns.addServiceRecord("Empty._http", 82, MDNSServiceTCP) :
         s.mdns.addServiceRecord("Empty._http", 82, MDNSServiceTCP, i == 1 ? NULL : "");
      assert(ok); assert(sentTxt(s.udp.sent.back()) == Bytes(1, 0));
      s.mdns.removeAllServiceRecords();
   }
   assert(s.mdns.addServiceRecord("Null._http", 82, MDNSServiceTCP, NULL));
   assert(sentTxt(s.udp.sent.back()) == Bytes(1, 0));
   s.mdns.removeAllServiceRecords();
   assert(s.mdns.addServiceRecord("Null._http", 82, MDNSServiceTCP, nullptr));
   assert(sentTxt(s.udp.sent.back()) == Bytes(1, 0));
   s.mdns.removeAllServiceRecords();
   assert(s.mdns.addServiceRecord("Null._http", 82, MDNSServiceTCP, NULL, 0));
   assert(sentTxt(s.udp.sent.back()) == Bytes(1, 0));
   s.mdns.removeAllServiceRecords();
   assert(!s.mdns.setName(""));
   assert(!s.mdns.resolveName("", 0));
   assert(!s.mdns.startDiscoveringService("", MDNSServiceTCP, 0));
   assert(!s.mdns.addServiceRecord("Instance.", 80, MDNSServiceTCP));
   assert(!s.mdns.addServiceRecord("Invalid._http", 80, MDNSServiceTCP, "\x05" "bad"));
   assert(!s.mdns.addServiceRecord("Invalid._http", 80, MDNSServiceTCP, static_cast<const uint8_t*>(NULL), 1));
   assert(!s.mdns.addServiceRecord("Invalid", 80, MDNSServiceTCP));
   assert(!s.mdns.addServiceRecord("._http", 80, MDNSServiceTCP));
   assert(!s.mdns.addServiceRecord("a.._http", 80, static_cast<MDNSServiceProtocol_t>(42)));
   assert(!s.mdns.setName("bad.name"));
   assert(!s.mdns.startDiscoveringService("http", MDNSServiceTCP, 0));
   std::string boundary(63, 'a');
   assert(s.mdns.setName(boundary.c_str()));
   assert(!s.mdns.setName((boundary + "b").c_str()));
   assert(s.mdns.resolveName("device", 0));
   assert(s.udp.sent.back().size() == 12 + dotted("device.local").size() + 4);
   validateSent(s.udp);
   s.mdns.setName("localHost");
   Bytes limit(MDNS_MAX_TXT_SIZE, 'x'); limit[0] = uint8_t(limit.size() - 1);
   assert(s.mdns.addServiceRecord("Limit._http", 80, MDNSServiceTCP, limit.data(), limit.size()));
   limit.push_back(0);
   assert(!s.mdns.addServiceRecord("TooLarge._http", 81, MDNSServiceTCP, limit.data(), limit.size()));
   assert(s.mdns.lastError() == MDNSResourceLimit);
}
static void sourcePortFiltering()
{
   for (int kind = 0; kind < 3; ++kind) {
      Session s;
      Packet packet;
      if (kind == 0) {
         s.discover();
         packet = fullPacket();
      } else if (kind == 1) {
         assert(s.mdns.resolveName("device", 0));
         packet.a();
      } else {
         packet = Packet(0);
         packet.question(dotted("localHost.local"), 1);
      }
      s.udp.sent.clear();
      s.udp.enqueue(packet.bytes);
      s.udp.incoming.back().port = 9999;
      s.mdns.run();
      assert(events.empty() && hostEvents.empty() && s.udp.sent.empty());
      assert(s.udp.available() == 0 && s.mdns.lastError() == MDNSSuccess);
      s.feed(packet);
      if (kind == 0) assert(events.size() == 1);
      if (kind == 1) assert(hostEvents.size() == 1);
      if (kind == 2) assert(s.udp.sent.size() == 1);
   }
}
static void permutationsAndAssociation()
{
   int order[] = {0,1,2,3};
   do {
      Session s; s.discover(); Packet p;
      for (int i = 0; i < 4; ++i) {
         if (order[i] == 0) p.ptr("Living.Room");
         if (order[i] == 1) p.srv("Living.Room");
         if (order[i] == 2) p.txt(Bytes{3,'a',0,'b',0}, "Living.Room");
         if (order[i] == 3) p.a();
      }
      s.feed(p);
      assert(events.size() == 1 && events[0].name == "Living.Room" && events[0].port == 80);
      assert(events[0].txt == Bytes({3,'a',0,'b',0}) && events[0].last == 4);
      assert(s.mdns.lastError() == MDNSSuccess);
   } while (std::next_permutation(order, order + 4));
   for (int missing = 0; missing < 4; ++missing) {
      Session s; s.discover(); Packet p;
      if (missing != 0) p.ptr();
      if (missing != 1) p.srv();
      if (missing != 2) p.a();
      if (missing != 3) p.txt(Bytes{0});
      s.feed(p);
      assert(events.size() == (missing == 3 ? 1u : 0u));
   }
   { Session s; s.discover(); Packet p; p.ptr(); p.srv(); p.a("unrelated.local"); s.feed(p); assert(events.empty()); }
   { Session s; s.discover(); Packet p; p.ptr(); p.srv("Printer", "."); p.a(); s.feed(p); assert(events.empty()); }
   { Session s; s.discover(); Packet p; p.ptr(); p.srv("Printer", "device.local", 0); p.a();
      s.feed(p); assert(events.empty() && s.mdns.isDiscoveringService());
      assert(s.mdns.lastError() == MDNSSuccess);
      s.feed(fullPacket()); assert(events.size() == 1 && events[0].port == 80); }
   { Session s; s.discover(); Packet p = fullPacket(); p.patch(6, 1); p.patch(10, 3); s.feed(p); assert(events.size() == 1); }
   { Session s; s.discover(); Packet p; p.ptr(); p.srv(); p.a(); p.txt(Bytes()); s.feed(p);
      assert(events.size() == 1 && events[0].present && events[0].txt.empty()); }
   { Session s; s.discover(); Packet p; p.ptr(); p.srv(); p.a(); p.txt(Bytes{0}); s.feed(p);
      assert(events[0].present && events[0].txt == Bytes{0}); }
   for (int zero = 0; zero < 3; ++zero) {
      Session s; s.discover(); Packet p;
      p.ptr("Printer", zero == 0 ? 0 : 120); p.srv("Printer", "device.local", 80, zero == 1 ? 0 : 120);
      p.a("device.local", 4, zero == 2 ? 0 : 120); s.feed(p); assert(events.empty());
   }
   { Session s; s.discover(); Packet p = fullPacket(); p.ptr(); p.srv(); p.a(); p.txt(Bytes{3,'a',0,'b',0});
      s.feed(p); assert(events.size() == 1); s.feed(p); assert(events.size() == 2); }
   { Session s; s.discover(); Packet p;
      for (int i = 0; i < 10; ++i) p.ptr();
      p.srv(); p.a(); s.feed(p);
      assert(events.size() == 1 && s.mdns.lastError() == MDNSSuccess); }
   for (int conflict = 0; conflict < 3; ++conflict) {
      Session s; s.discover(); Packet p = fullPacket();
      if (!conflict) p.srv("Printer", "device.local", 81);
      if (conflict == 1) p.a("device.local", 5);
      if (conflict == 2) p.txt(Bytes{0});
      s.feed(p); assert(events.empty()); assert(s.mdns.lastError() == MDNSConflictingRecords);
   }
   { Session s; s.discover(); Packet p;
      for (int i = 0; i < 7; ++i) { char text[] = {'A', char('0' + i), 0}; p.ptr(text); }
      assert(p.bytes.size() <= MDNS_MAX_PACKET_SIZE); s.feed(p);
      assert(events.empty() && s.mdns.lastError() == MDNSResourceLimit); }
   { Session s; s.discover(); Packet p;
      for (int i = 0; i < 6; ++i) { char text[] = {'A', char('0' + i), 0}; p.ptr(text); p.srv(text); }
      p.a(); assert(p.bytes.size() <= MDNS_MAX_PACKET_SIZE); s.feed(p); assert(events.size() == 6); }
   { Session s; s.discover(); Packet p;
      size_t at = p.rr(dotted("padding.local"), 99); p.bytes.resize(p.bytes.size() + 240, 0); p.end(at);
      assert(p.bytes.size() > 256); p.ptr(); p.srv(); p.a(); s.feed(p);
      assert(events.size() == 1 && events[0].last == 4); }
#if MDNS_MAX_PACKET_SIZE > 512
   { Session s; s.discover(); Packet p;
      size_t at = p.rr(dotted("padding.local"), 99);
      p.bytes.resize(p.bytes.size() + 600, 0); p.end(at);
      assert(p.bytes.size() > 512); p.ptr(); p.srv(); p.a();
      assert(p.bytes.size() <= MDNS_MAX_PACKET_SIZE); s.feed(p);
      assert(events.size() == 1 && events[0].port == 80 && events[0].last == 4);
      assert(s.mdns.lastError() == MDNSSuccess); }
#endif
   { Session s; s.discover(); Packet p; p.ptr(); p.srv(); p.a();
      Bytes huge(256, 'x'); huge[0] = 255; p.txt(huge);
      assert(p.bytes.size() <= MDNS_MAX_PACKET_SIZE); s.feed(p);
      assert(events.empty() && s.mdns.lastError() == MDNSResourceLimit); }
   { Session s; s.discover(); Packet p;
      size_t at = p.rr(dotted("_HTTP._TCP.LOCAL"), 12); p.name(instance("Printer")); p.end(at);
      p.srv("Printer", "DEVICE.LOCAL"); p.a(); s.feed(p); assert(events.size() == 1); }
   { Session s; s.discover(); Packet p;
      std::string longest = std::string(63, 'a') + "." + std::string(63, 'b') +
         "." + std::string(63, 'c') + "." + std::string(61, 'd');
      assert(dotted(longest.c_str()).size() == 255);
      p.ptr(); p.srv("Printer", longest.c_str()); p.a(longest.c_str());
      assert(p.bytes.size() <= MDNS_MAX_PACKET_SIZE); s.feed(p);
      assert(events.size() == 1 && events[0].last == 4);
      Bytes txt(MDNS_MAX_TXT_SIZE, 'x'); txt[0] = uint8_t(txt.size() - 1);
      p.txt(txt);
      size_t at = p.rr(dotted("."), 99);
      assert(p.bytes.size() <= MDNS_MAX_PACKET_SIZE);
      p.bytes.resize(MDNS_MAX_PACKET_SIZE, 0); p.end(at);
      action = 2; s.feed(p);
      assert(events.size() == 2 && events[1].txt == txt && s.mdns.isDiscoveringService()); }
}
static void malformedAndReceive()
{
   Packet full = fullPacket();
   for (size_t size = 0; size < full.bytes.size(); ++size) {
      Session s; s.discover(); Packet p = full; p.bytes.resize(size); s.feed(p);
      assert(events.empty() && s.udp.sent.empty());
   }
   { Session s; s.discover(); Packet p = full; p.bytes.push_back(0); s.feed(p); assert(events.empty()); }
   { Session s; s.discover(); Packet p = full;
      size_t at = p.rr(dotted("other.local"), 1); p.bytes.push_back(1); p.end(at);
      size_t stops = s.udp.stopCalls, joins = s.udp.multicastCalls;
      s.feed(p); assert(events.empty()); assert(s.mdns.lastError() == MDNSMalformedPacket);
      assert(s.udp.stopCalls == stops && s.udp.multicastCalls == joins);
      s.feed(full); assert(events.size() == 1); }
   { Session s; s.discover(); Packet p; p.ptr(); p.srv(); p.a(); p.txt(Bytes{2,1});
      s.feed(p); assert(events.empty()); }
   { Session s; assert(s.mdns.resolveName("device", 0)); Packet p; p.a(); p.bytes.push_back(0);
      s.feed(p); assert(hostEvents.empty() && s.mdns.isResolvingName()); }
   for (int shortRead = 0; shortRead < 3; ++shortRead) {
      Session s; s.discover(); s.udp.shortRead = shortRead == 2 ? int(full.bytes.size() - 1) : shortRead;
      size_t stops = s.udp.stopCalls; s.feed(full);
      assert(events.empty() && s.udp.stopCalls == stops + 1);
      assert(s.mdns.lastError() == MDNSSocketError);
      // Deliver after recovery; a real socket close may discard prequeued packets.
      s.udp.shortRead = -1; s.feed(full); assert(events.size() == 1);
   }
   { Session s; s.discover(); s.udp.failRead = true; s.feed(full); assert(events.empty());
      s.udp.failRead = false; s.feed(full); assert(events.size() == 1); }
   { Session s; s.udp.parseError = -1; s.mdns.run(); assert(s.mdns.lastError() == MDNSSocketError); }
   { Session s; Packet p; p.bytes.resize(MDNS_MAX_PACKET_SIZE + 1);
      s.feed(p); assert(s.mdns.lastError() == MDNSResourceLimit); }
   { Session s; assert(s.mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP)); s.udp.sent.clear();
      Packet p(0); p.question(dotted("_http._tcp.local"), 12);
      size_t at = p.rr(dotted("bad.local"), 1); p.bytes.push_back(0); p.end(at);
      s.feed(p); assert(s.udp.sent.empty());
      Packet valid(0); valid.question(dotted("_http._tcp.local"), 12); s.feed(valid);
      assert(s.udp.sent.size() == 1); validateSent(s.udp); }
}
static void callbacksAndClocks()
{
   for (int a = 1; a <= 5; ++a) {
      Session s; s.discover(); action = a;
      Packet p = fullPacket(); p.ptr("Second"); p.srv("Second"); s.feed(p);
      if (a == 1 || a == 2 || a == 4) assert(events.size() == 1);
      else assert(events.size() == 2);
      if (a == 1) assert(!s.mdns.isDiscoveringService());
      if (a == 2) assert(s.mdns.isDiscoveringService());
      if (a == 3) assert(s.mdns.lastError() == MDNSAlreadyProcessingQuery);
      if (a == 4) assert(alternateCalls == 1);
   }
   { Session s; s.mdns.setServiceFoundCallback(legacy); s.discover(); Packet p;
      p.ptr(); p.srv(); p.a(); p.txt(Bytes{3,'a','b','c'}); s.feed(p);
      assert(events.size() == 1 && events[0].txt == Bytes({3,'a','b','c'}));
      s.mdns.setServiceFoundBinaryCallback(binary); s.feed(p); assert(events.size() == 2); }
   { Session s; action = 7; assert(s.mdns.resolveName("device", 100)); Packet p; p.a();
      s.feed(p); assert(hostEvents.size() == 1 && s.mdns.isResolvingName());
      Packet next; next.a("next.local"); s.feed(next); assert(hostEvents.back() == "next"); }
   { Session s; s.discover(); action = 9; assert(s.mdns.resolveName("device", 100));
      s.feed(fullPacket()); assert(hostEvents.size() == 1 && events.empty());
      s.feed(fullPacket()); assert(events.size() == 1); }
   { Session s; action = 8; assert(s.mdns.resolveName("device", 10)); mdnsTestMillis += 10;
      s.mdns.run(); assert(s.mdns.isResolvingName() && hostEvents.size() == 1);
      s.mdns.run(); assert(hostEvents.size() == 1); }
   { Session s; action = 6; assert(s.mdns.startDiscoveringService("_http", MDNSServiceTCP, 10));
      mdnsTestMillis += 10; s.mdns.run(); assert(events.size() == 1 && events[0].timeout);
      assert(s.mdns.isDiscoveringService()); s.mdns.run(); assert(events.size() == 1); }
   { Session s; mdnsTestMillis = 0xfffffff0u; assert(s.mdns.resolveName("device", 32));
      mdnsTestMillis = 0x0fu; s.mdns.run(); assert(hostEvents.empty());
      mdnsTestMillis = 0x10u; s.mdns.run(); assert(hostEvents.size() == 1);
      assert(s.mdns.lastError() == MDNSTimedOut); }
   { Session s; assert(s.mdns.resolveName("device", 0)); mdnsTestMillis += 0x7fffffffu;
      s.mdns.run(); assert(s.mdns.isResolvingName());
      assert(!s.mdns.resolveName("device", 0x80000000UL)); }
   { Session s; s.discover(); assert(s.mdns.begin(IPAddress(10,0,0,2), "newHost"));
      assert(!s.mdns.isDiscoveringService()); }
   { Session s; s.discover(); s.mdns.setServiceFoundCallback(NULL); s.feed(fullPacket());
      assert(events.empty()); }
}
static void transmitFailures()
{
   for (int kind = 0; kind < 3; ++kind) {
      Session s;
      if (!kind) s.udp.failBeginPacket = true;
      if (kind == 1) s.udp.shortWriteCall = int(s.udp.writeCalls);
      if (kind == 2) s.udp.failEndPacket = true;
      size_t end = s.udp.endCalls;
      assert(!s.mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP));
      assert(s.mdns.lastError() == MDNSSocketError);
      if (kind != 2) assert(s.udp.endCalls == end);
      s.udp.failBeginPacket = s.udp.failEndPacket = false; s.udp.shortWriteCall = -1;
      s.mdns.removeServiceRecord(80, MDNSServiceTCP); assert(s.mdns.lastError() == MDNSNotFound);
      assert(s.mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP));
      validateSent(s.udp);
   }
   { Session s; s.udp.failBeginPacket = true; assert(!s.mdns.resolveName("device", 100));
      assert(!s.mdns.isResolvingName()); }
   { Session s; assert(s.mdns.resolveName("device", 0)); s.udp.failEndPacket = true;
      mdnsTestMillis += 1000; s.mdns.run(); size_t attempts = s.udp.beginCalls;
      s.mdns.run(); assert(s.udp.beginCalls == attempts);
      mdnsTestMillis += 999; s.mdns.run(); assert(s.udp.beginCalls == attempts);
      ++mdnsTestMillis; s.mdns.run(); assert(s.udp.beginCalls == attempts + 1); }
   { Session s; assert(s.mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP));
      s.udp.failEndPacket = true; s.mdns.removeAllServiceRecords();
      assert(s.mdns.lastError() == MDNSSocketError);
      s.mdns.removeServiceRecord(80, MDNSServiceTCP); assert(s.mdns.lastError() == MDNSNotFound); }
   { Session s; s.udp.failBeginMulticast = true; s.udp.failRead = true; s.feed(fullPacket());
      s.udp.failRead = false; s.udp.failBeginMulticast = false;
      assert(!s.mdns.resolveName("device", 0)); assert(s.mdns.begin(IPAddress(1,2,3,4)));
      assert(s.mdns.resolveName("device", 0)); }
   { Session s; assert(s.mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP));
      mdnsTestMillis += 90000; s.udp.failEndPacket = true; s.mdns.run();
      size_t attempts = s.udp.beginCalls; s.mdns.run(); assert(s.udp.beginCalls == attempts);
      mdnsTestMillis += 1000; s.udp.failEndPacket = false; s.mdns.run();
      assert(s.udp.beginCalls == attempts + 1); }
}
#ifdef MDNS_TEST_ALLOCATIONS
static void allocationFailures()
{
   for (int failure = 0; failure < 5; ++failure) {
      Session s; size_t before = liveCount; failAllocation = failure;
      assert(!s.mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP));
      failAllocation = -1;
      assert(s.mdns.lastError() == MDNSOutOfMemory && liveCount == before);
      s.mdns.removeServiceRecord(80, MDNSServiceTCP);
      assert(s.mdns.lastError() == MDNSNotFound);
   }
   { Session s; failAllocation = 0;
      assert(!s.mdns.setName("newHost")); assert(s.mdns.lastError() == MDNSOutOfMemory);
      Packet p(0); p.question(dotted("localHost.local"), 1); s.feed(p);
      assert(s.udp.sent.size() == 1); }
   for (int failure = 0; failure < 3; ++failure) {
      Session s; assert(s.mdns.resolveName("device", 0)); failAllocation = failure;
      assert(!s.mdns.resolveName("replacement", 100)); failAllocation = -1;
      assert(s.mdns.lastError() == MDNSOutOfMemory);
      assert(bool(s.mdns.isResolvingName()) == (failure < 2));
   }
   for (int failure = 0; failure < 2; ++failure) {
      Session s; s.discover(); failAllocation = failure; s.feed(fullPacket()); failAllocation = -1;
      assert(events.empty() && s.mdns.lastError() == MDNSOutOfMemory);
      s.feed(fullPacket()); assert(events.size() == 1);
   }
   assert(liveCount == 0);
   { Session s; s.discover(); assert(s.mdns.resolveName("device", 0));
      for (int i = 0; i < NumMDNSServiceRecords; ++i)
         assert(s.mdns.addServiceRecord("Web._http", uint16_t(80 + i), MDNSServiceTCP));
   }
   assert(liveCount == 0);
   printf("production allocation accounting: peak=%zu bytes, live=%zu bytes\n", peakBytes, liveBytes);
}
#endif
int main()
{
   ownershipAndTxt(); sourcePortFiltering(); permutationsAndAssociation(); malformedAndReceive();
   callbacksAndClocks(); transmitFailures();
#ifdef MDNS_TEST_ALLOCATIONS
   allocationFailures();
#endif
   printf("mDNS API tests passed (sizeof(MDNS)=%zu, packet cap=%d, TXT cap=%d)\n",
          sizeof(MDNS), MDNS_MAX_PACKET_SIZE, MDNS_MAX_TXT_SIZE);
}
