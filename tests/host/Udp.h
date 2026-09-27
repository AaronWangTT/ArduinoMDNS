#ifndef MDNS_TEST_UDP_H
#define MDNS_TEST_UDP_H

#include <stddef.h>
#include <stdint.h>
#include "IPAddress.h"

class UDP {
public:
   virtual ~UDP() {}
   virtual uint8_t begin(uint16_t) = 0;
   virtual uint8_t beginMulticast(IPAddress, uint16_t) = 0;
   virtual void stop() = 0;
   virtual int beginPacket(IPAddress, uint16_t) = 0;
   virtual int beginPacket(const char*, uint16_t) = 0;
   virtual int endPacket() = 0;
   virtual size_t write(uint8_t) = 0;
   virtual size_t write(const uint8_t*, size_t) = 0;
   virtual int parsePacket() = 0;
   virtual int available() = 0;
   virtual int read() = 0;
   virtual int read(unsigned char*, size_t) = 0;
   virtual int read(char* buffer, size_t length)
   {
      return read(reinterpret_cast<unsigned char*>(buffer), length);
   }
   virtual int peek() = 0;
   virtual void flush() = 0;
   virtual IPAddress remoteIP() = 0;
   virtual uint16_t remotePort() = 0;
};

#endif
