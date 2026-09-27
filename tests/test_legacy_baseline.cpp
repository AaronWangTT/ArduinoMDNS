#include "host/FakeUDP.h"
#include <MDNS.h>
#include <assert.h>
#include <stdio.h>

uint32_t mdnsTestMillis = 3000;
static void resolved(const char*, IPAddress) {}

int main()
{
   FakeUDP udp;
   MDNS mdns(udp);
   mdns.setNameResolvedCallback(resolved);
   assert(mdns.resolveName("device", 1000) == 1);
   assert(udp.sent.size() == 1);
   const std::vector<uint8_t>& query = udp.sent[0];
   const uint8_t expectedPrefix[] = {
      0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
      6, 'd', 'e', 'v', 'i', 'c', 'e', 5, 'l', 'o', 'c', 'a', 'l', 0,
      0, 1, 0, 1
   };
   assert(query.size() == sizeof(expectedPrefix) + 8);
   assert(memcmp(query.data(), expectedPrefix, sizeof(expectedPrefix)) == 0);
   mdns.cancelResolveName();
   assert(!mdns.isResolvingName());
   puts("legacy baseline: A question prefix captured; confirmed eight unintended trailing bytes");
}
