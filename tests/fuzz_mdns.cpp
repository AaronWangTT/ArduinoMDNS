#include "host/FakeUDP.h"
#include <MDNS.h>
#include <stddef.h>
#include <stdint.h>

uint32_t mdnsTestMillis = 3000;
static MDNS* current;
static unsigned callbacks;
static void found(const char*, MDNSServiceProtocol_t, const char*, IPAddress,
                  unsigned short, const uint8_t*, size_t)
{
   if (++callbacks == 1) {
      current->stopDiscoveringService();
      current->startDiscoveringService("_http", MDNSServiceTCP, 32);
      current->run();
   }
}
static void resolved(const char*, IPAddress)
{
   current->cancelResolveName();
   current->resolveName("next", 32);
}
static void u16(std::vector<uint8_t>& out, uint16_t value)
{
   out.push_back(uint8_t(value >> 8)); out.push_back(uint8_t(value));
}
static void name(std::vector<uint8_t>& out, const char* text)
{
   while (*text) {
      const char* end = strchr(text, '.');
      size_t size = end ? size_t(end - text) : strlen(text);
      out.push_back(uint8_t(size)); out.insert(out.end(), text, text + size);
      text += size; if (*text) ++text;
   }
   out.push_back(0);
}
static void rr(std::vector<uint8_t>& out, const char* owner, uint16_t type, uint16_t length)
{
   name(out, owner); u16(out, type); u16(out, 1); u16(out, 0); u16(out, 120); u16(out, length);
}
static std::vector<uint8_t> structured(const uint8_t* data, size_t size)
{
   std::vector<uint8_t> out(12, 0); out[2] = 0x84; out[7] = 4;
   rr(out, "_http._tcp.local", 12, 23); name(out, "Fuzz._http._tcp.local");
   rr(out, "Fuzz._http._tcp.local", 33, 20);
   u16(out, 0); u16(out, 0); u16(out, 80); name(out, "device.local");
   rr(out, "device.local", 1, 4);
   out.push_back(10); out.push_back(0); out.push_back(0); out.push_back(1);
   size_t count = std::min(size, size_t(MDNS_MAX_TXT_SIZE - 1));
   bool valid = !size || (data[0] & 1);
   rr(out, "Fuzz._http._tcp.local", 16, uint16_t(count + (valid ? 1 : 0)));
   if (valid) out.push_back(uint8_t(count));
   out.insert(out.end(), data, data + count);
   return out;
}
static void faults(FakeUDP& udp, unsigned kind, uint8_t amount)
{
   udp.failBeginPacket = kind == 5 || kind == 9;
   udp.failEndPacket = kind == 7 || kind == 14;
   udp.failBeginMulticast = kind >= 8;
   udp.failRead = kind == 2 || kind == 13;
   udp.parseError = kind == 1 || kind == 11 ? -1 : 0;
   udp.shortRead = kind == 3 ? 0 :
      (kind == 4 || kind == 12 || kind == 15 ? int(amount % 20) : -1);
   udp.shortWriteCall = kind == 6 || kind == 10 ? int(udp.writeCalls) : -1;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   if (size > MDNS_MAX_PACKET_SIZE + 1) return 0;
   FakeUDP udp;
   MDNS mdns(udp); current = &mdns; callbacks = 0;
   mdnsTestMillis = 0xfffffff0u;
   mdns.begin(IPAddress(10,0,0,1), "device");
   mdns.setNameResolvedCallback(resolved);
   mdns.setServiceFoundBinaryCallback(found);
   mdns.resolveName("device", 0);
   mdns.startDiscoveringService("_http", MDNSServiceTCP, 0);
   mdns.addServiceRecord("Fuzz._http", 80, MDNSServiceTCP);
   udp.enqueue(std::vector<uint8_t>(data, data + size));
   mdns.run();
   // Exercise lifecycle and binary TXT even when arbitrary input cannot pass
   // the complete DNS envelope gate; retain a raw-packet pass above.
   udp.enqueue(structured(data, size));
   mdns.run();
   mdnsTestMillis += 64;
   mdns.run();
   // Bound stateful operation sequences independently of packet length. Each
   // high nibble selects an I/O failure, including failed stop/rejoin recovery.
   size_t steps = std::min(size, size_t(16));
   for (size_t i = 0; i < steps; ++i) {
      uint8_t control = data[i], amount = data[(i + 1) % size];
      faults(udp, control >> 4, amount);
      switch (control & 7) {
         case 0:
            udp.enqueue(std::vector<uint8_t>(data, data + size));
            mdns.run();
            break;
         case 1:
            udp.enqueue(structured(data, size));
            mdns.run();
            break;
         case 2:
            mdns.cancelResolveName();
            mdns.resolveName(amount & 1 ? "device" : "next", amount);
            break;
         case 3:
            mdns.stopDiscoveringService();
            mdns.startDiscoveringService("_http", MDNSServiceTCP, amount);
            break;
         case 4:
            mdns.removeAllServiceRecords();
            mdns.addServiceRecord("Fuzz._http", uint16_t(amount + 1), MDNSServiceTCP);
            break;
         case 5:
            mdnsTestMillis += uint32_t(amount) << 24;
            mdns.run();
            break;
         case 6:
            mdns.begin(IPAddress(10,0,0,1), amount & 1 ? "device" : "next");
            break;
         case 7:
            mdns.setServiceFoundBinaryCallback(amount & 1 ? found : NULL);
            mdns.setName(amount & 2 ? "device" : "next");
            mdns.run();
            break;
      }
   }
   // Explicitly exercise recovery after a failed rejoin marked the socket down.
   faults(udp, 0, 0);
   mdns.begin(IPAddress(10,0,0,1), "device");
   mdns.resolveName("device", 32);
   udp.enqueue(structured(data, size));
   mdns.run();
   current = NULL;
   return 0;
}
