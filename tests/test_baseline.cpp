#include "host/FakeUDP.h"
#include <MDNS.h>
#include <assert.h>
#include <stdio.h>

uint32_t mdnsTestMillis = 3000;

int main()
{
   FakeUDP udp;
   {
      MDNS mdns(udp);
      assert(!mdns.isResolvingName());
      assert(!mdns.isDiscoveringService());
      mdns.setNameResolvedCallback(NULL);
      mdns.setServiceFoundCallback(NULL);
      mdns.run();
      assert(udp.sent.empty());
   }
   assert(udp.stopCalls == 1);
   puts("baseline: idle construction, callback setup, run and socket release passed");
}
