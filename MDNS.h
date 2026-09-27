//  Copyright (C) 2010 Georg Kaindl
//  http://gkaindl.com
//
//  This file is part of Arduino EthernetBonjour.
//
//  EthernetBonjour is free software: you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version.
//
//  EthernetBonjour is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with EthernetBonjour. If not, see
//  <http://www.gnu.org/licenses/>.
//

#if !defined(__MDNS_H__)
#define __MDNS_H__ 1

extern "C" {
   #include <inttypes.h>
}

#include <Arduino.h>
#include <IPAddress.h>
#include <Udp.h>

typedef uint8_t byte;

typedef enum _MDNSState_t {
   MDNSStateIdle,
   MDNSStateQuerySent
} MDNSState_t;

typedef enum _MDNSError_t {
   MDNSTryLater = 3,
   MDNSNothingToDo = 2,
   MDNSSuccess  = 1,
   MDNSInvalidArgument = -1,
   MDNSOutOfMemory = -2,
   MDNSSocketError = -3,
   MDNSAlreadyProcessingQuery = -4,
   MDNSNotFound = -5,
   MDNSServerError = -6,
   MDNSTimedOut = -7,
   MDNSMalformedPacket = -8,
   MDNSResourceLimit = -9,
   MDNSConflictingRecords = -10,
   MDNSUnrepresentableName = -11
} MDNSError_t;

typedef struct _MDNSDataInternal_t {
   uint32_t xid;
   uint32_t lastQueryFirstXid;
} MDNSDataInternal_t;

typedef enum _MDNSServiceProtocol_t {
   MDNSServiceTCP,
   MDNSServiceUDP
} MDNSServiceProtocol_t;

typedef MDNSServiceProtocol_t MDNSServiceProtocol;

typedef struct _MDNSServiceRecord_t {
   uint16_t                port;
   MDNSServiceProtocol_t   proto;
   uint8_t*                name;
   uint8_t*                servName;
   uint8_t*                textContent;
   size_t                  textLength;
} MDNSServiceRecord_t;

typedef void (*MDNSNameFoundCallback)(const char*, IPAddress);
typedef void (*MDNSServiceFoundCallback)(const char*, MDNSServiceProtocol_t, const char*,
                                         IPAddress, unsigned short, const char*);
typedef void (*MDNSServiceFoundBinaryCallback)(const char*, MDNSServiceProtocol_t,
                                               const char*, IPAddress, unsigned short,
                                               const uint8_t*, size_t);

#ifndef MDNS_MAX_PACKET_SIZE
#if defined(ARDUINO_ARCH_AVR) || defined(__AVR__)
#define MDNS_MAX_PACKET_SIZE 512
#else
#define MDNS_MAX_PACKET_SIZE 1472
#endif
#endif
#ifndef MDNS_MAX_TXT_SIZE
#define MDNS_MAX_TXT_SIZE 128
#endif
#if MDNS_MAX_PACKET_SIZE < 12 || MDNS_MAX_PACKET_SIZE > 32767
#error MDNS_MAX_PACKET_SIZE must fit a positive 16-bit UDP read length
#endif
#if MDNS_MAX_TXT_SIZE < 1 || MDNS_MAX_TXT_SIZE > MDNS_MAX_PACKET_SIZE
#error MDNS_MAX_TXT_SIZE must be positive and no larger than MDNS_MAX_PACKET_SIZE
#endif

#define  NumMDNSServiceRecords   (8)

//class MDNS
class MDNS
{
private:
   struct Query {
      uint8_t* name;
      char* display;
      uint32_t started, duration, attempted, sent, generation;
      MDNSServiceProtocol_t proto;
   };
   UDP* _udp;
   IPAddress _ipAddress;
   uint8_t* _name;
   MDNSServiceRecord_t* _serviceRecords[NumMDNSServiceRecords];
   Query _queries[2];
   uint32_t _lastAnnounceMillis, _lastAnnounceAttempt;
   bool _available, _running;
   MDNSError_t _error;
   MDNSNameFoundCallback _nameFoundCallback;
   MDNSServiceFoundCallback _serviceFoundCallback;
   MDNSServiceFoundBinaryCallback _binaryCallback;

   void _resetError();
   void _fail(MDNSError_t error);
   bool _recover();
   bool _send(const uint8_t* data, size_t length);
   bool _sendQuery(uint8_t idx);
   bool _sendRecord(int idx, uint32_t ttl, uint16_t xid = 0);
   void _receive();
   void _process(const uint8_t* data, size_t length);
   void _respond(const uint8_t* data, size_t length, size_t nameCapacity);
   int _initQuery(uint8_t idx, const char* name, MDNSServiceProtocol_t proto,
                  unsigned long timeout);
   void _cancelQuery(uint8_t idx);
   void _finishName(const uint8_t* address);
   void _timeoutService();
   void _removeServiceRecord(int idx, bool goodbye);
   MDNS(const MDNS&);
   MDNS& operator=(const MDNS&);
public:
   MDNS(UDP& udp);
   ~MDNS();
   
   int begin(const IPAddress& ip);
   int begin(const IPAddress& ip, const char* name);
   void run();
   
   int setName(const char* name);
   
   int addServiceRecord(const char* name, uint16_t port, MDNSServiceProtocol_t proto);
   int addServiceRecord(const char* name, uint16_t port, MDNSServiceProtocol_t proto,
                        const char* textContent);
   int addServiceRecord(const char* name, uint16_t port, MDNSServiceProtocol_t proto,
                        const uint8_t* txtData, size_t txtLength);
   
   void removeServiceRecord(uint16_t port, MDNSServiceProtocol_t proto);
   void removeServiceRecord(const char* name, uint16_t port, MDNSServiceProtocol_t proto);
      
   void removeAllServiceRecords();
   
   void setNameResolvedCallback(MDNSNameFoundCallback newCallback);
   int resolveName(const char* name, unsigned long timeout);
   void cancelResolveName();
   int isResolvingName();
   
   void setServiceFoundCallback(MDNSServiceFoundCallback newCallback);
   void setServiceFoundBinaryCallback(MDNSServiceFoundBinaryCallback newCallback);
   int startDiscoveringService(const char* serviceName, MDNSServiceProtocol_t proto,
                               unsigned long timeout);
   void stopDiscoveringService();
   int isDiscoveringService();
   MDNSError_t lastError() const { return _error; }
};

#endif // __MDNS_H__
