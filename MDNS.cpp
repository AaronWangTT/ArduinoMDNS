// Copyright (C) 2010 Georg Kaindl
// http://gkaindl.com
//
// This file is part of Arduino EthernetBonjour.
//
// EthernetBonjour is free software: you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// EthernetBonjour is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with EthernetBonjour. If not, see
// <http://www.gnu.org/licenses/>.
#include "MDNS.h"
#include "utility/DnsPacket.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

namespace {
const uint16_t kPort = 5353;
const uint32_t kTTL = 120;
const uint32_t kRetry = 1000;
const uint32_t kAnnounce = 90000;
const size_t kCandidates = 6;
uint8_t multicastAddress[] = {224, 0, 0, 251};
const uint8_t localSuffix[] = {5,'l','o','c','a','l',0};
const uint8_t tcpSuffix[] = {4,'_','t','c','p',5,'l','o','c','a','l',0};
const uint8_t udpSuffix[] = {4,'_','u','d','p',5,'l','o','c','a','l',0};
const uint8_t enumerationName[] = {
   9,'_','s','e','r','v','i','c','e','s',7,'_','d','n','s','-','s','d',
   4,'_','u','d','p',5,'l','o','c','a','l',0
};

void* allocateBytes(size_t size, bool zero = false, size_t stackReserve = 192)
{
#if defined(__AVR__)
   // avr-libc checks the current SP when growing the heap. Preserve room for
   // deeper parser/UDP calls instead of relying on its 32-byte default margin.
   size_t previousMargin = __malloc_margin;
   if (__malloc_margin < stackReserve) __malloc_margin = stackReserve;
#else
   (void)stackReserve;
#endif
   void* result = zero ? calloc(1, size) : malloc(size);
#if defined(__AVR__)
   __malloc_margin = previousMargin;
#endif
   return result;
}

size_t wireSize(const uint8_t* name)
{
   size_t n = 0;
   while (name[n]) n += size_t(name[n]) + 1;
   return n + 1;
}

bool validProtocol(MDNSServiceProtocol_t proto)
{
   return proto == MDNSServiceTCP || proto == MDNSServiceUDP;
}

bool printable(const char* text, size_t size)
{
   for (size_t i = 0; i < size; ++i)
      if (uint8_t(text[i]) < 32 || uint8_t(text[i]) == 127) return false;
   return true;
}

// API names are labels, not unescaped DNS presentation strings. Instance dots
// are data; only the last dot separates an instance from its service label.
bool label(const char* text, size_t size, bool service)
{
   if (!size || size > 63 || !printable(text, size)) return false;
   if (service && (size < 2 || text[0] != '_')) return false;
   if (service) {
      for (size_t i = 1; i < size; ++i) {
         char c = text[i];
         if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-')) return false;
      }
   }
   return true;
}

uint8_t* makeName(const char* text, MDNSServiceProtocol_t proto, int kind)
{
   // All callers validate first; the longest locally generated name is 140 bytes.
   size_t n = strlen(text);
   const uint8_t* suffix = kind ? (proto == MDNSServiceTCP ? tcpSuffix : udpSuffix)
                                : localSuffix;
   size_t suffixLength = kind ? sizeof(tcpSuffix) : sizeof(localSuffix);
   size_t total = n + 1 + suffixLength;
   uint8_t* result = static_cast<uint8_t*>(allocateBytes(total));
   if (!result) return NULL;
   result[0] = uint8_t(n);
   memcpy(result + 1, text, n);
   if (kind == 2) {
      size_t first = size_t(strrchr(text, '.') - text);
      result[0] = uint8_t(first);
      result[first + 1] = uint8_t(n - first - 1);
   }
   memcpy(result + n + 1, suffix, suffixLength);
   return result;
}

bool validInputName(const char* text, MDNSServiceProtocol_t proto, int kind)
{
   if (!text || (kind && !validProtocol(proto))) return false;
   if (kind == 2) {
      const char* dot = strrchr(text, '.');
      return dot && label(text, size_t(dot - text), false) &&
             label(dot + 1, strlen(dot + 1), true);
   }
   return label(text, strlen(text), kind == 1) && (kind || !strchr(text, '.'));
}

bool validTxt(const uint8_t* data, size_t size)
{
   if (size && !data) return false;
   size_t pos = 0;
   while (pos < size) {
      size_t count = data[pos++];
      if (count > size - pos) return false;
      pos += count;
   }
   return true;
}

class Writer {
public:
   uint8_t* data;
   size_t size, capacity;
   bool ok;
   Writer(uint8_t* buffer, size_t limit) : data(buffer), size(0), capacity(limit), ok(true) {}
   void bytes(const uint8_t* bytes, size_t count) {
      if (!ok || count > capacity - size) { ok = false; return; }
      if (count) memcpy(data + size, bytes, count);
      size += count;
   }
   void u8(uint8_t n) { bytes(&n, 1); }
   void u16(uint16_t n) {
      const uint8_t value[] = {uint8_t(n >> 8), uint8_t(n)};
      bytes(value, sizeof(value));
   }
   void u32(uint32_t n) {
      const uint8_t value[] = {uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n)};
      bytes(value, sizeof(value));
   }
   void name(const uint8_t* n) { bytes(n, wireSize(n)); }
   void header(uint16_t xid, uint16_t flags, uint16_t questions, uint16_t answers) {
      const uint8_t value[] = {
         uint8_t(xid >> 8), uint8_t(xid), uint8_t(flags >> 8), uint8_t(flags),
         uint8_t(questions >> 8), uint8_t(questions), uint8_t(answers >> 8), uint8_t(answers),
         0, 0, 0, 0
      };
      bytes(value, sizeof(value));
   }
   void rr(const uint8_t* owner, uint16_t type, uint16_t klass,
           uint32_t ttl, size_t length) {
      name(owner);
      if (length > 65535) ok = false;
      const uint8_t value[] = {
         uint8_t(type >> 8), uint8_t(type), uint8_t(klass >> 8), uint8_t(klass),
         uint8_t(ttl >> 24), uint8_t(ttl >> 16), uint8_t(ttl >> 8), uint8_t(ttl),
         uint8_t(length >> 8), uint8_t(length)
      };
      bytes(value, sizeof(value));
   }
};

size_t recordLength(const uint8_t* host, const MDNSServiceRecord_t* service, uint32_t ttl)
{
   if (!service) return 26 + wireSize(host);
   const uint8_t* instance = service->servName;
   size_t typeLength = wireSize(instance + size_t(instance[0]) + 1);
   size_t instanceLength = size_t(instance[0]) + 1 + typeLength;
   if (!ttl) return 22 + typeLength + instanceLength;
   return 72 + 2 * typeLength + 3 * instanceLength + 2 * wireSize(host) +
          sizeof(enumerationName) + service->textLength;
}

void serializeRecord(Writer& w, const uint8_t* host, const IPAddress& ip,
                     const MDNSServiceRecord_t* service, uint32_t ttl, uint16_t xid)
{
   const uint8_t* type = NULL;
   w.header(xid, 0x8400, 0, service && ttl ? 5 : 1);
   if (service) {
      const uint8_t* instance = service->servName;
      type = instance + size_t(instance[0]) + 1;
      w.rr(type, 12, 1, ttl, wireSize(instance)); w.name(instance);
      if (!ttl) return;
      w.rr(instance, 33, 0x8001, ttl, 6 + wireSize(host));
      w.u16(0); w.u16(0); w.u16(service->port); w.name(host);
      w.rr(instance, 16, 0x8001, ttl, service->textLength);
      w.bytes(service->textContent, service->textLength);
   }
   w.rr(host, 1, 0x8001, ttl, 4);
   const uint8_t address[] = {ip[0], ip[1], ip[2], ip[3]};
   w.bytes(address, sizeof(address));
   if (service) {
      w.rr(enumerationName, 12, 1, ttl, wireSize(type)); w.name(type);
   }
}
}

void MDNS::_initialize()
{
   _name = NULL;
   _lastAnnounceMillis = _lastAnnounceAttempt = 0;
   _available = _running = false;
   _error = MDNSSuccess;
   _nameFoundCallback = NULL;
   _serviceFoundCallback = NULL;
   _binaryCallback = NULL;
   memset(_serviceRecords, 0, sizeof(_serviceRecords));
   memset(_queries, 0, sizeof(_queries));
}

MDNS::~MDNS()
{
   _release(false);
}

void MDNS::end()
{
   _resetError();
   _release(true);
}

void MDNS::_release(bool goodbye)
{
   for (int i = 0; i < NumMDNSServiceRecords; ++i) _removeServiceRecord(i, goodbye);
   for (uint8_t i = 0; i < 2; ++i) _cancelQuery(i);
   free(_name); _name = NULL;
   _udp.stop();
   _available = false;
   _lastAnnounceMillis = _lastAnnounceAttempt = 0;
}

int MDNS::announce()
{
   _resetError();
   _lastAnnounceAttempt = uint32_t(millis());
   bool success = _sendRecord(-1, kTTL);
   for (int i = 0; i < NumMDNSServiceRecords; ++i)
      if (_serviceRecords[i] && !_sendRecord(i, kTTL)) success = false;
   if (success) _lastAnnounceMillis = uint32_t(millis());
   return success ? 1 : 0;
}

#if defined(__GNUC__)
__attribute__((noinline))
#endif
void MDNS::_resetError() { if (!_running) _error = MDNSSuccess; }
#if defined(__GNUC__)
__attribute__((noinline))
#endif
void MDNS::_fail(MDNSError_t error) { if (_error == MDNSSuccess) _error = error; }

int MDNS::begin(const IPAddress& ip) { return begin(ip, "arduino"); }

int MDNS::begin(const IPAddress& ip, const char* name)
{
   _resetError();
   if (_running) { _fail(MDNSAlreadyProcessingQuery); return 0; }
   if (!validInputName(name, MDNSServiceTCP, 0)) { _fail(MDNSInvalidArgument); return 0; }
   uint8_t* next = makeName(name, MDNSServiceTCP, 0);
   if (!next) { _fail(MDNSOutOfMemory); return 0; }
   _release(true);
   _name = next;
   // Preserve the original WIZnet startup grace period for immediate announcements.
   if (_waitForNetworkHardware) while (uint32_t(millis()) < 3000) delay(100);
   _ipAddress = ip;
   _available = _udp.beginMulticast(IPAddress(multicastAddress), kPort) == 1;
   if (!_available) { _fail(MDNSSocketError); return 0; }
   _lastAnnounceMillis = _lastAnnounceAttempt = uint32_t(millis());
   return 1;
}

int MDNS::setName(const char* name)
{
   _resetError();
   if (!validInputName(name, MDNSServiceTCP, 0)) { _fail(MDNSInvalidArgument); return 0; }
   uint8_t* next = makeName(name, MDNSServiceTCP, 0);
   if (!next) { _fail(MDNSOutOfMemory); return 0; }
   // An existing registration must remain serializable after a host rename.
   for (int i = 0; i < NumMDNSServiceRecords; ++i) if (_serviceRecords[i]) {
      if (recordLength(next, _serviceRecords[i], kTTL) > MDNS_MAX_PACKET_SIZE) {
         free(next); _fail(MDNSResourceLimit); return 0;
      }
   }
   free(_name); _name = next;
   return 1;
}

bool MDNS::_recover()
{
   _udp.stop();
   _available = _udp.beginMulticast(IPAddress(multicastAddress), kPort) == 1;
   if (!_available) _fail(MDNSSocketError);
   return _available;
}

bool MDNS::_send(const uint8_t* data, size_t length)
{
   if (!_available) { _fail(MDNSSocketError); return false; }
   if (_udp.beginPacket(IPAddress(multicastAddress), kPort) != 1) {
      _fail(MDNSSocketError); _recover(); return false;
   }
   if (_udp.write(data, length) != length) {
      _fail(MDNSSocketError); _recover(); return false;
   }
   if (_udp.endPacket() != 1) {
      _fail(MDNSSocketError); _recover(); return false;
   }
   return true;
}

bool MDNS::_sendRecord(int idx, uint32_t ttl, uint16_t xid)
{
   if (!_name) { _fail(MDNSInvalidArgument); return false; }
   MDNSServiceRecord_t* service = idx < 0 ? NULL : _serviceRecords[idx];
   size_t length = recordLength(_name, service, ttl);
   if (length > MDNS_MAX_PACKET_SIZE) { _fail(MDNSResourceLimit); return false; }
   uint8_t* buffer = static_cast<uint8_t*>(allocateBytes(length));
   if (!buffer) { _fail(MDNSOutOfMemory); return false; }
   Writer out(buffer, length);
   serializeRecord(out, _name, _ipAddress, service, ttl, xid);
   if (!out.ok || out.size != length) {
      free(buffer); _fail(MDNSServerError); return false;
   }
   bool sent = out.ok && _send(buffer, out.size);
   free(buffer);
   return sent;
}

int MDNS::addServiceRecord(const char* name, uint16_t port, MDNSServiceProtocol_t proto)
{
   return addServiceRecord(name, port, proto, static_cast<const uint8_t*>(NULL), 0);
}

int MDNS::addServiceRecord(const char* name, uint16_t port,
                          MDNSServiceProtocol_t proto, const char* txt)
{
   return addServiceRecord(name, port, proto, reinterpret_cast<const uint8_t*>(txt),
                           txt ? strlen(txt) : 0);
}

int MDNS::addServiceRecord(const char* name, uint16_t port,
                          MDNSServiceProtocol_t proto, const uint8_t* txt, size_t length)
{
   _resetError();
   if (!port || !validInputName(name, proto, 2) || !validTxt(txt, length)) {
      _fail(MDNSInvalidArgument); return 0;
   }
   if (!_available || !_name) { _fail(MDNSSocketError); return 0; }
   if (length > MDNS_MAX_TXT_SIZE) { _fail(MDNSResourceLimit); return 0; }
   int slot = 0;
   while (slot < NumMDNSServiceRecords && _serviceRecords[slot]) ++slot;
   if (slot == NumMDNSServiceRecords) { _fail(MDNSResourceLimit); return 0; }
   MDNSServiceRecord_t* r = static_cast<MDNSServiceRecord_t*>(allocateBytes(sizeof(*r), true));
   if (!r) { _fail(MDNSOutOfMemory); return 0; }
   r->name = static_cast<uint8_t*>(allocateBytes(strlen(name) + 1));
   r->servName = makeName(name, proto, 2);
   r->textLength = length ? length : 1;
   r->textContent = static_cast<uint8_t*>(allocateBytes(r->textLength + 1));
   if (!r->name || !r->servName || !r->textContent) {
      free(r->name); free(r->servName); free(r->textContent); free(r);
      _fail(MDNSOutOfMemory); return 0;
   }
   strcpy(reinterpret_cast<char*>(r->name), name);
   if (length) memcpy(r->textContent, txt, length); else r->textContent[0] = 0;
   r->textContent[r->textLength] = 0;
   r->port = port; r->proto = proto;
   _serviceRecords[slot] = r;
   if (!_sendRecord(slot, kTTL)) {
      _removeServiceRecord(slot, false);
      return 0;
   }
   _lastAnnounceMillis = _lastAnnounceAttempt = uint32_t(millis());
   return 1;
}

void MDNS::_removeServiceRecord(int idx, bool goodbye)
{
   MDNSServiceRecord_t* r = _serviceRecords[idx];
   if (!r) return;
   if (goodbye) _sendRecord(idx, 0);
   _serviceRecords[idx] = NULL;
   free(r->name); free(r->servName); free(r->textContent); free(r);
}

void MDNS::removeServiceRecord(uint16_t port, MDNSServiceProtocol_t proto)
{
   removeServiceRecord(NULL, port, proto);
}

void MDNS::removeServiceRecord(const char* name, uint16_t port, MDNSServiceProtocol_t proto)
{
   _resetError();
   for (int i = 0; i < NumMDNSServiceRecords; ++i) {
      MDNSServiceRecord_t* r = _serviceRecords[i];
      if (r && r->port == port && r->proto == proto &&
          (!name || strcmp(name, reinterpret_cast<const char*>(r->name)) == 0)) {
         _removeServiceRecord(i, true); return;
      }
   }
   _fail(MDNSNotFound);
}

void MDNS::removeAllServiceRecords()
{
   _resetError();
   for (int i = 0; i < NumMDNSServiceRecords; ++i) _removeServiceRecord(i, true);
}

void MDNS::setNameResolvedCallback(MDNSNameFoundCallback callback) { _nameFoundCallback = callback; }
void MDNS::setServiceFoundCallback(MDNSServiceFoundCallback callback)
{
   _serviceFoundCallback = callback; _binaryCallback = NULL;
}
void MDNS::setServiceFoundBinaryCallback(MDNSServiceFoundBinaryCallback callback)
{
   _binaryCallback = callback; _serviceFoundCallback = NULL;
}

void MDNS::_cancelQuery(uint8_t idx)
{
   free(_queries[idx].name); free(_queries[idx].display);
   _queries[idx].name = NULL; _queries[idx].display = NULL;
   ++_queries[idx].generation;
}
void MDNS::cancelResolveName() { _resetError(); _cancelQuery(0); }
void MDNS::stopDiscoveringService() { _resetError(); _cancelQuery(1); }
int MDNS::isResolvingName() { return _queries[0].name != NULL; }
int MDNS::isDiscoveringService() { return _queries[1].name != NULL; }

bool MDNS::_sendQuery(uint8_t idx)
{
   Query& q = _queries[idx];
   q.attempted = uint32_t(millis());
   size_t length = 12 + wireSize(q.name) + 4;
   if (length > MDNS_MAX_PACKET_SIZE) { _fail(MDNSResourceLimit); return false; }
   uint8_t* packet = static_cast<uint8_t*>(allocateBytes(length));
   if (!packet) { _fail(MDNSOutOfMemory); return false; }
   Writer w(packet, length);
   w.header(0, 0, 1, 0); w.name(q.name);
   const uint8_t trailer[] = {0, uint8_t(idx ? 12 : 1), 0, 1};
   w.bytes(trailer, sizeof(trailer));
   bool sent = w.ok && _send(packet, w.size);
   free(packet);
   if (sent) q.sent = uint32_t(millis());
   return sent;
}

int MDNS::_initQuery(uint8_t idx, const char* name, MDNSServiceProtocol_t proto,
                     unsigned long timeout)
{
   _resetError();
   if (!validInputName(name, proto, idx) || timeout > 0x7fffffffUL) {
      _fail(MDNSInvalidArgument); return 0;
   }
   if ((!idx && !_nameFoundCallback) || (idx && !_serviceFoundCallback && !_binaryCallback)) {
      _fail(MDNSInvalidArgument); return 0;
   }
   if (!_available) { _fail(MDNSSocketError); return 0; }
   uint8_t* wire = makeName(name, proto, idx);
   char* display = static_cast<char*>(allocateBytes(strlen(name) + 1));
   if (!wire || !display) {
      free(wire); free(display); _fail(MDNSOutOfMemory); return 0;
   }
   strcpy(display, name);
   _cancelQuery(idx);
   Query& q = _queries[idx];
   q.name = wire; q.display = display; q.proto = proto;
   q.started = uint32_t(millis()); q.duration = uint32_t(timeout);
   if (!_sendQuery(idx)) { _cancelQuery(idx); return 0; }
   return 1;
}

int MDNS::resolveName(const char* name, unsigned long timeout)
{
   return _initQuery(0, name, MDNSServiceTCP, timeout);
}
int MDNS::startDiscoveringService(const char* name, MDNSServiceProtocol_t proto,
                                  unsigned long timeout)
{
   return _initQuery(1, name, proto, timeout);
}

void MDNS::_finishName(const uint8_t* address)
{
   uint8_t* oldName = _queries[0].name;
   char* oldDisplay = _queries[0].display;
   _queries[0].name = NULL; _queries[0].display = NULL;
   ++_queries[0].generation;
   MDNSNameFoundCallback callback = _nameFoundCallback;
   if (callback) callback(oldDisplay, address ? IPAddress(address) : IPAddress(uint32_t(0xffffffffUL)));
   free(oldName); free(oldDisplay);
}

void MDNS::_timeoutService()
{
   uint8_t* oldName = _queries[1].name;
   char* oldDisplay = _queries[1].display;
   MDNSServiceProtocol_t oldProto = _queries[1].proto;
   _queries[1].name = NULL; _queries[1].display = NULL;
   ++_queries[1].generation;
   MDNSServiceFoundCallback legacy = _serviceFoundCallback;
   MDNSServiceFoundBinaryCallback binary = _binaryCallback;
   if (binary) binary(oldDisplay, oldProto, NULL, IPAddress(), 0, NULL, 0);
   else if (legacy) legacy(oldDisplay, oldProto, NULL, IPAddress(), 0, NULL);
   free(oldName); free(oldDisplay);
}

void MDNS::_receive()
{
   int advertised = _udp.parsePacket();
   if (!advertised) return;
   if (advertised < 0) { _fail(MDNSSocketError); _recover(); return; }
   const uint16_t peerPort = _udp.remotePort();
   if (advertised < 12 || size_t(advertised) > MDNS_MAX_PACKET_SIZE) {
      _fail(advertised < 12 ? MDNSMalformedPacket : MDNSResourceLimit);
      _recover(); return;
   }
   uint8_t* packet = static_cast<uint8_t*>(allocateBytes(size_t(advertised), false, 320));
   if (!packet) { _fail(MDNSOutOfMemory); _recover(); return; }
   int received = _udp.read(packet, size_t(advertised));
   if (received != advertised) {
      free(packet); _fail(MDNSSocketError); _recover(); return;
   }
   if (peerPort == kPort) _process(packet, size_t(advertised));
   free(packet);
}

namespace {
class Records {
public:
   mdns::PacketCursor cursor;
   const mdns::DnsHeader* header;
   uint16_t remaining;
   uint8_t section;
   Records(mdns::PacketView packet, const mdns::DnsHeader& header)
      : cursor(packet, 12, packet.length), header(&header), remaining(header.answers), section(0)
   {
      for (uint16_t i = 0; i < header.questions; ++i) {
         mdns::Question q;
         if (mdns::readQuestion(cursor, q) != mdns::ParseOk) {
            section = 3; remaining = 0; break;
         }
      }
   }
   bool next(mdns::ResourceRecord& rr) {
      while (!remaining) {
         if (section == 0) { section = 1; remaining = header->authorities; }
         else if (section == 1) { section = 2; remaining = header->additionals; }
         else return false;
      }
      --remaining;
      return mdns::readRecord(cursor, rr) == mdns::ParseOk;
   }
   bool positive(const mdns::ResourceRecord& rr) const {
      return section != 1 && rr.ttl && (rr.klass & 0x7fff) == 1;
   }
};

struct Candidate {
   size_t instance, instanceEnd, srv, srvEnd, txt, txtLength, address;
};
struct Assembly {
   uint8_t* left;
   uint8_t* right;
   size_t nameCapacity;
   Candidate* candidates;
   size_t candidateCapacity;
};

mdns::ParseStatus measureName(mdns::PacketView packet, size_t start, size_t end,
                              size_t& maximum, bool exact = false)
{
   size_t consumed = 0, expanded = 0;
   mdns::ParseStatus status = mdns::decodeName(packet, start, end, NULL, 0, consumed, expanded);
   if (status != mdns::ParseOk) return status;
   if (exact && consumed != end - start) return mdns::ParseInvalidRdata;
   if (expanded > maximum) maximum = expanded;
   return mdns::ParseOk;
}
// Keep traversal frames out of the callback phase on small-stack targets.
#if defined(__GNUC__)
__attribute__((noinline))
#endif
mdns::ParseStatus measureScratch(mdns::PacketView packet, mdns::DnsHeader& header,
                     size_t& names, size_t& txt, size_t& candidates)
{
   mdns::PacketCursor cursor(packet);
   mdns::DnsHeader parsed;
   mdns::ParseStatus status = mdns::readHeader(cursor, parsed);
   if (status != mdns::ParseOk) return status;
   for (uint16_t i = 0; i < parsed.questions; ++i) {
      mdns::Question q;
      status = mdns::readQuestion(cursor, q);
      if (status != mdns::ParseOk) return status;
      status = measureName(packet, q.nameOffset, packet.length, names);
      if (status != mdns::ParseOk) return status;
   }
   const uint16_t counts[] = {parsed.answers, parsed.authorities, parsed.additionals};
   for (size_t section = 0; section < 3; ++section)
      for (uint16_t i = 0; i < counts[section]; ++i) {
         mdns::ResourceRecord rr;
         status = mdns::readRecord(cursor, rr);
         if (status != mdns::ParseOk) return status;
         status = measureName(packet, rr.nameOffset, packet.length, names);
         if (status != mdns::ParseOk) return status;
         if (rr.type == 12 || rr.type == 33) {
            size_t fixed = rr.type == 33 ? 6 : 0;
            if (rr.rdataLength <= fixed) return mdns::ParseInvalidRdata;
            status = measureName(packet, rr.rdataOffset + fixed,
                                 rr.rdataOffset + rr.rdataLength, names, true);
            if (status != mdns::ParseOk) return status;
         }
         if ((rr.type == 1 && rr.rdataLength != 4) ||
             (rr.type == 16 && !validTxt(packet.data + rr.rdataOffset, rr.rdataLength)))
            return mdns::ParseInvalidRdata;
         if (rr.type == 16 && rr.rdataLength <= MDNS_MAX_TXT_SIZE && rr.rdataLength > txt)
            txt = rr.rdataLength;
         if (section != 1 && rr.type == 12 && rr.ttl && (rr.klass & 0x7fff) == 1 &&
             candidates < kCandidates) ++candidates;
      }
   if (cursor.remaining()) return mdns::ParseTrailingData;
   header = parsed;
   return mdns::ParseOk;
}
size_t decode(mdns::PacketView packet, size_t start, size_t end, uint8_t* output, size_t capacity)
{
   size_t consumed = 0, expanded = 0;
   if (mdns::decodeName(packet, start, end, output, capacity, consumed, expanded) != mdns::ParseOk)
      return 0;
   return expanded;
}
bool equalWireNames(const uint8_t* a, size_t aLength, const uint8_t* b, size_t bLength)
{
   if (aLength != bLength) return false;
   // Decoder/registration validation precedes every call. Length bytes <= 63
   // cannot be ASCII uppercase, so folding preserves complete label boundaries.
   for (size_t i = 0; i < aLength; ++i) {
      uint8_t left = a[i], right = b[i];
      if (left >= 'A' && left <= 'Z') left += 'a' - 'A';
      if (right >= 'A' && right <= 'Z') right += 'a' - 'A';
      if (left != right) return false;
   }
   return true;
}
bool equalAt(mdns::PacketView packet, size_t start, size_t end,
             const uint8_t* wire, uint8_t* scratch, size_t capacity)
{
   size_t size = decode(packet, start, end, scratch, capacity);
   return size && equalWireNames(scratch, size, wire, wireSize(wire));
}
bool equalOffsets(mdns::PacketView packet, size_t a, size_t aEnd,
                  size_t b, size_t bEnd, Assembly& work)
{
   size_t aSize = decode(packet, a, aEnd, work.left, work.nameCapacity);
   size_t bSize = decode(packet, b, bEnd, work.right, work.nameCapacity);
   return aSize && bSize && equalWireNames(work.left, aSize, work.right, bSize);
}
MDNSError_t findAddress(mdns::PacketView packet, const mdns::DnsHeader& header,
                        const uint8_t* name, uint8_t* scratch, size_t capacity, size_t& address)
{
   if (!name) return MDNSSuccess;
   Records records(packet, header);
   mdns::ResourceRecord rr;
   while (records.next(rr)) {
      if (!records.positive(rr) || rr.type != 1 ||
          !equalAt(packet, rr.nameOffset, packet.length, name, scratch, capacity)) continue;
      if (address && memcmp(packet.data + address, packet.data + rr.rdataOffset, 4))
         return MDNSConflictingRecords;
      address = rr.rdataOffset;
   }
   return MDNSSuccess;
}

#if defined(__GNUC__)
__attribute__((noinline))
#endif
MDNSError_t assembleServices(mdns::PacketView packet, const mdns::DnsHeader& header,
                             const uint8_t* query, Assembly& work, size_t& count)
{
   const uint8_t* data = packet.data;
   mdns::ResourceRecord rr;
   Records records(packet, header);
   while (records.next(rr)) {
      if (!records.positive(rr) || rr.type != 12 ||
          !equalAt(packet, rr.nameOffset, packet.length, query, work.left, work.nameCapacity)) continue;
      size_t n = decode(packet, rr.rdataOffset, rr.rdataOffset + rr.rdataLength,
                         work.left, work.nameCapacity);
      size_t first = size_t(work.left[0]) + 1;
      if (!n || first >= n || !printable(reinterpret_cast<char*>(work.left + 1), first - 1) ||
          !equalWireNames(work.left + first, n - first, query, wireSize(query)))
         return MDNSUnrepresentableName;
      size_t c = 0;
      for (; c < count; ++c)
         if (equalAt(packet, work.candidates[c].instance, work.candidates[c].instanceEnd,
                      work.left, work.right, work.nameCapacity)) break;
      if (c < count) continue;
      if (count == work.candidateCapacity) return MDNSResourceLimit;
      work.candidates[count].instance = rr.rdataOffset;
      work.candidates[count++].instanceEnd = rr.rdataOffset + rr.rdataLength;
   }
   for (size_t c = 0; c < count; ++c) {
      Candidate& candidate = work.candidates[c];
      Records members(packet, header);
      while (members.next(rr)) {
         if (!members.positive(rr) || (rr.type != 33 && rr.type != 16) ||
             !equalOffsets(packet, rr.nameOffset, packet.length,
                           candidate.instance, candidate.instanceEnd, work)) continue;
         if (rr.type == 16) {
            if (rr.rdataLength > MDNS_MAX_TXT_SIZE) return MDNSResourceLimit;
            if (candidate.txt && (candidate.txtLength != rr.rdataLength ||
                memcmp(data + candidate.txt, data + rr.rdataOffset, rr.rdataLength)))
               return MDNSConflictingRecords;
            candidate.txt = rr.rdataOffset; candidate.txtLength = rr.rdataLength;
         } else {
            if (candidate.srv &&
                (memcmp(data + candidate.srv, data + rr.rdataOffset, 6) ||
                 !equalOffsets(packet, candidate.srv + 6, candidate.srvEnd,
                               rr.rdataOffset + 6, rr.rdataOffset + rr.rdataLength, work)))
               return MDNSConflictingRecords;
            candidate.srv = rr.rdataOffset; candidate.srvEnd = rr.rdataOffset + rr.rdataLength;
         }
      }
      if (!candidate.srv) continue;
      decode(packet, candidate.srv + 6, candidate.srvEnd, work.left, work.nameCapacity);
      if (!work.left[0]) continue;
      MDNSError_t status = findAddress(packet, header, work.left, work.right,
                                       work.nameCapacity, candidate.address);
      if (status != MDNSSuccess) return status;
   }
   return MDNSSuccess;
}
}

void MDNS::_respond(const uint8_t* data, size_t length, size_t nameCapacity)
{
   mdns::PacketView packet(data, length);
   mdns::PacketCursor questions(packet);
   mdns::DnsHeader header;
   if (mdns::readHeader(questions, header) != mdns::ParseOk) {
      _fail(MDNSMalformedPacket); return;
   }
   bool requested[NumMDNSServiceRecords + 1] = {false};
   uint8_t* scratch = static_cast<uint8_t*>(allocateBytes(nameCapacity));
   if (!scratch) { _fail(MDNSOutOfMemory); return; }
   for (uint16_t i = 0; i < header.questions; ++i) {
      mdns::Question q;
      if (mdns::readQuestion(questions, q) != mdns::ParseOk) break;
      if ((q.klass & 0x7fff) != 1) continue;
      if (_name && (q.type == 1 || q.type == 255) &&
          equalAt(packet, q.nameOffset, length, _name, scratch, nameCapacity)) requested[0] = true;
      bool enumerate = (q.type == 12 || q.type == 255) &&
          equalAt(packet, q.nameOffset, length, enumerationName, scratch, nameCapacity);
      for (int j = 0; j < NumMDNSServiceRecords; ++j) {
         const MDNSServiceRecord_t* r = _serviceRecords[j];
         if (!r) continue;
         const uint8_t* type = r->servName + size_t(r->servName[0]) + 1;
         if (enumerate ||
             ((q.type == 12 || q.type == 255) &&
              equalAt(packet, q.nameOffset, length, type, scratch, nameCapacity)) ||
             ((q.type == 33 || q.type == 16 || q.type == 255) &&
              equalAt(packet, q.nameOffset, length, r->servName, scratch, nameCapacity)))
            requested[j + 1] = true;
      }
   }
   free(scratch);
   if (requested[0] && !_sendRecord(-1, kTTL, header.id)) return;
   for (int i = 0; i < NumMDNSServiceRecords; ++i)
      if (requested[i + 1] && _serviceRecords[i] && !_sendRecord(i, kTTL, header.id)) break;
}

void MDNS::_process(const uint8_t* data, size_t length)
{
   mdns::PacketView packet(data, length);
   mdns::DnsHeader header;
   size_t nameCapacity = 1, txtCapacity = 0, candidateCapacity = 0;
   mdns::ParseStatus status = measureScratch(packet, header, nameCapacity, txtCapacity, candidateCapacity);
   if (status != mdns::ParseOk) {
      _fail(status == mdns::ParseResourceLimit ? MDNSResourceLimit : MDNSMalformedPacket);
      return;
   }
   // No opcode/rcode handling or assembly from truncated responses is promised.
   if (header.flags & 0x7a0f) return;
   const bool response = (header.flags & 0x8000) != 0;
   if (response && !_queries[0].name && !_queries[1].name) return;
   if (!response) {
      _respond(data, length, nameCapacity); return;
   }
   size_t hostAddress = 0;
   if (!_queries[1].name) {
      if (!_queries[0].name) return;
      uint8_t* scratch = static_cast<uint8_t*>(allocateBytes(nameCapacity));
      if (!scratch) { _fail(MDNSOutOfMemory); return; }
      MDNSError_t result = findAddress(packet, header, _queries[0].name, scratch, nameCapacity, hostAddress);
      free(scratch);
      if (result != MDNSSuccess) _fail(result);
      else if (hostAddress) _finishName(data + hostAddress);
      return;
   }
   size_t rightCapacity = txtCapacity + 1 > nameCapacity ? txtCapacity + 1 : nameCapacity;
   Assembly* allocated = static_cast<Assembly*>(
      allocateBytes(sizeof(Assembly) + candidateCapacity * sizeof(Candidate) +
                    nameCapacity + rightCapacity, true, 320));
   if (!allocated) { _fail(MDNSOutOfMemory); return; }
   Assembly& work = *allocated;
   work.candidates = reinterpret_cast<Candidate*>(allocated + 1);
   work.candidateCapacity = candidateCapacity;
   work.left = reinterpret_cast<uint8_t*>(work.candidates + candidateCapacity);
   work.right = work.left + nameCapacity;
   work.nameCapacity = nameCapacity;
   size_t count = 0;
   uint32_t hostGeneration = _queries[0].generation;
   uint32_t serviceGeneration = _queries[1].generation;
   MDNSError_t failure = findAddress(packet, header, _queries[0].name, work.left,
                                     work.nameCapacity, hostAddress);
   if (failure == MDNSSuccess)
      failure = assembleServices(packet, header, _queries[1].name, work, count);

   if (failure != MDNSSuccess) {
      free(allocated); _fail(failure); return;
   }
   if (hostAddress && _queries[0].name && _queries[0].generation == hostGeneration)
      _finishName(data + hostAddress);
   for (size_t c = 0; c < count; ++c) {
      if (!_queries[1].name || _queries[1].generation != serviceGeneration) break;
      const Candidate& candidate = work.candidates[c];
      if (!candidate.srv || !candidate.address) continue;
      decode(packet, candidate.instance, candidate.instanceEnd, work.left, work.nameCapacity);
      size_t instanceLength = work.left[0];
      char* instance = reinterpret_cast<char*>(work.left);
      char* type = reinterpret_cast<char*>(work.left + instanceLength + 1);
      memmove(instance, work.left + 1, instanceLength); instance[instanceLength] = 0;
      strcpy(type, _queries[1].display);
      uint16_t port = uint16_t(uint16_t(data[candidate.srv + 4]) << 8) | data[candidate.srv + 5];
      if (!port) continue;
      const uint8_t* txt = NULL;
      if (candidate.txt) {
         memcpy(work.right, data + candidate.txt, candidate.txtLength);
         work.right[candidate.txtLength] = 0; txt = work.right;
      }
      MDNSServiceProtocol_t proto = _queries[1].proto;
      MDNSServiceFoundBinaryCallback binary = _binaryCallback;
      MDNSServiceFoundCallback legacy = _serviceFoundCallback;
      if (binary) binary(type, proto, instance, IPAddress(data + candidate.address), port,
                         txt, candidate.txtLength);
      else if (legacy) legacy(type, proto, instance, IPAddress(data + candidate.address),
                              port, reinterpret_cast<const char*>(txt));
   }
   free(allocated);
}

void MDNS::run()
{
   if (_running) { _fail(MDNSAlreadyProcessingQuery); return; }
   _error = MDNSSuccess; _running = true;
   if (_available) _receive(); else _fail(MDNSSocketError);
   for (uint8_t i = 0; i < 2; ++i) {
      Query& q = _queries[i];
      if (!q.name) continue;
      uint32_t now = uint32_t(millis());
      if (q.duration && uint32_t(now - q.started) >= q.duration) {
         _fail(MDNSTimedOut);
         if (!i) _finishName(NULL); else _timeoutService();
         continue;
      }
      uint32_t interval = i ? 10000 : 1000;
      if (_available && uint32_t(now - q.sent) >= interval &&
          uint32_t(now - q.attempted) >= kRetry) _sendQuery(i);
   }
   uint32_t now = uint32_t(millis());
   if (_available && uint32_t(now - _lastAnnounceMillis) >= kAnnounce &&
       uint32_t(now - _lastAnnounceAttempt) >= kRetry) {
      _lastAnnounceAttempt = now;
      bool success = true;
      for (int i = 0; i < NumMDNSServiceRecords; ++i)
         if (_serviceRecords[i] && !_sendRecord(i, kTTL)) { success = false; break; }
      if (success) _lastAnnounceMillis = uint32_t(millis());
   }
   _running = false;
}
