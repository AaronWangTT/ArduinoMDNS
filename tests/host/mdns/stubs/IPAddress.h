#ifndef IPAddress_h
#define IPAddress_h

#include <stdint.h>
#include <string.h>

class IPAddress {
public:
    IPAddress() {
        memset(bytes_, 0, sizeof(bytes_));
    }

    IPAddress(uint32_t address) {
        memcpy(bytes_, &address, sizeof(bytes_));
    }

    IPAddress(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth) {
        bytes_[0] = first;
        bytes_[1] = second;
        bytes_[2] = third;
        bytes_[3] = fourth;
    }

    IPAddress(const uint8_t *address) {
        memcpy(bytes_, address, sizeof(bytes_));
    }

    operator uint32_t() const {
        uint32_t address;
        memcpy(&address, bytes_, sizeof(address));
        return address;
    }

    uint8_t operator[](int index) const {
        return bytes_[index];
    }

private:
    uint8_t bytes_[4];
};

#endif
