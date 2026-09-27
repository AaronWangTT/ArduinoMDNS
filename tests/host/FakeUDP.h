#ifndef MDNS_TEST_FAKE_UDP_H
#define MDNS_TEST_FAKE_UDP_H

#include "Udp.h"
#include <algorithm>
#include <deque>
#include <vector>

struct FakeDatagram {
   std::vector<uint8_t> bytes;
   IPAddress peer;
   uint16_t port;
   explicit FakeDatagram(const std::vector<uint8_t>& data,
                         IPAddress address = IPAddress(192, 168, 1, 2),
                         uint16_t peerPort = 5353)
      : bytes(data), peer(address), port(peerPort) {}
};

class FakeUDP : public UDP {
public:
   std::deque<FakeDatagram> incoming;
   std::vector<std::vector<uint8_t> > sent;
   std::vector<uint8_t> pending;
   bool failBeginPacket = false;
   bool failEndPacket = false;
   bool failBeginMulticast = false;
   bool failRead = false;
   bool flushDiscards = true;
   int shortRead = -1;
   int shortWriteCall = -1;
   int parseError = 0;
   size_t writeCalls = 0;
   size_t beginCalls = 0;
   size_t endCalls = 0;
   size_t stopCalls = 0;
   size_t multicastCalls = 0;

   void enqueue(const std::vector<uint8_t>& bytes)
   {
      incoming.push_back(FakeDatagram(bytes));
   }
   uint8_t begin(uint16_t) override { return 1; }
   uint8_t beginMulticast(IPAddress, uint16_t) override
   {
      ++multicastCalls;
      return failBeginMulticast ? 0 : 1;
   }
   void stop() override
   {
      ++stopCalls;
      pending.clear();
      if (active_ && !incoming.empty()) incoming.pop_front();
      active_ = false;
      offset_ = 0;
   }
   int beginPacket(IPAddress, uint16_t) override
   {
      ++beginCalls;
      pending.clear();
      return failBeginPacket ? 0 : 1;
   }
   int beginPacket(const char*, uint16_t port) override
   {
      return beginPacket(IPAddress(), port);
   }
   int endPacket() override
   {
      ++endCalls;
      if (failEndPacket) return 0;
      sent.push_back(pending);
      pending.clear();
      return 1;
   }
   size_t write(uint8_t value) override { return write(&value, 1); }
   size_t write(const uint8_t* bytes, size_t length) override
   {
      const size_t call = writeCalls++;
      size_t count = length;
      if (shortWriteCall >= 0 && call == static_cast<size_t>(shortWriteCall))
         count = length ? length - 1 : 0;
      if (count) pending.insert(pending.end(), bytes, bytes + count);
      return count;
   }
   int parsePacket() override
   {
      if (parseError) return parseError;
      if (active_ && !incoming.empty()) incoming.pop_front();
      offset_ = 0;
      active_ = !incoming.empty();
      return active_ ? static_cast<int>(incoming.front().bytes.size()) : 0;
   }
   int available() override
   {
      return active_ ? static_cast<int>(incoming.front().bytes.size() - offset_) : 0;
   }
   int read() override
   {
      uint8_t value;
      return read(&value, 1) == 1 ? value : -1;
   }
   int read(unsigned char* bytes, size_t length) override
   {
      if (failRead) return -1;
      if (!active_) return -1;
      size_t count = std::min(length, static_cast<size_t>(available()));
      if (shortRead >= 0) count = std::min(count, static_cast<size_t>(shortRead));
      if (count) memcpy(bytes, incoming.front().bytes.data() + offset_, count);
      offset_ += count;
      return static_cast<int>(count);
   }
   int peek() override
   {
      return available() ? incoming.front().bytes[offset_] : -1;
   }
   void flush() override
   {
      if (active_ && flushDiscards) offset_ = incoming.front().bytes.size();
   }
   IPAddress remoteIP() override
   {
      return active_ ? incoming.front().peer : IPAddress();
   }
   uint16_t remotePort() override
   {
      return active_ ? incoming.front().port : 0;
   }
private:
   size_t offset_ = 0;
   bool active_ = false;
};

#endif
