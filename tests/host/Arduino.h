#ifndef MDNS_TEST_ARDUINO_H
#define MDNS_TEST_ARDUINO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t byte;
extern uint32_t mdnsTestMillis;

inline unsigned long millis() { return mdnsTestMillis; }
inline void delay(unsigned long duration) { mdnsTestMillis += duration; }

#endif
