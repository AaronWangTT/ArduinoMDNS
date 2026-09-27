#ifndef MDNS_TEST_IP_ADDRESS_H
#define MDNS_TEST_IP_ADDRESS_H

#include <stdint.h>
#include <string.h>

class IPAddress {
public:
   IPAddress() { memset(bytes_, 0, sizeof(bytes_)); }
   IPAddress(uint32_t address) { memcpy(bytes_, &address, sizeof(bytes_)); }
   IPAddress(const uint8_t* address) { memcpy(bytes_, address, sizeof(bytes_)); }
   IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
   {
      bytes_[0] = a; bytes_[1] = b; bytes_[2] = c; bytes_[3] = d;
   }
   uint8_t operator[](int index) const { return bytes_[index]; }
   uint8_t& operator[](int index) { return bytes_[index]; }
   operator uint32_t() const
   {
      uint32_t value;
      memcpy(&value, bytes_, sizeof(value));
      return value;
   }
   bool operator==(const IPAddress& other) const
   {
      return memcmp(bytes_, other.bytes_, sizeof(bytes_)) == 0;
   }
   bool operator!=(const IPAddress& other) const { return !(*this == other); }
private:
   uint8_t bytes_[4];
};

static const IPAddress INADDR_NONE(255, 255, 255, 255);

#endif
