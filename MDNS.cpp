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

#define  HAS_SERVICE_REGISTRATION      1  // disabling saves about 1.25 kilobytes
#define  HAS_NAME_BROWSING             1  // disable together with above, additionally saves about 4.3 kilobytes

#include <string.h>
#include <stdlib.h>
#include <Arduino.h>

extern "C" {
   #include <utility/EthernetUtil.h>
}

#include "MDNS.h"

#define  MDNS_DEFAULT_NAME       "arduino"
#define  MDNS_TLD                ".local"
#define  DNS_SD_SERVICE          "_services._dns-sd._udp.local"
#define  MDNS_SERVER_PORT        (5353)
#define  MDNS_NQUERY_RESEND_TIME (1000)   // 1 second, name query resend timeout
#define  MDNS_SQUERY_RESEND_TIME (10000)  // 10 seconds, service query resend timeout
#define  MDNS_RESPONSE_TTL       (120)    // two minutes (in seconds)

#define  MDNS_MAX_SERVICES_PER_PACKET  (6)

//#define  _BROKEN_MALLOC_   1
#undef _USE_MALLOC_

static uint8_t mdnsMulticastIPAddr[] = { 224, 0, 0, 251 };
//static uint8_t mdnsHWAddr[] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb };

typedef enum _MDNSPacketType_t {
   MDNSPacketTypeMyIPAnswer,
   MDNSPacketTypeNoIPv6AddrAvailable,
   MDNSPacketTypeServiceRecord,
   MDNSPacketTypeServiceRecordRelease,
   MDNSPacketTypeNameQuery,
   MDNSPacketTypeServiceQuery,
} MDNSPacketType_t;

typedef struct _DNSHeader_t {
   uint16_t    xid;
   uint8_t     recursionDesired:1;
   uint8_t     truncated:1;
   uint8_t     authoritiveAnswer:1;
   uint8_t     opCode:4;
   uint8_t     queryResponse:1;
   uint8_t     responseCode:4;
   uint8_t     checkingDisabled:1;
   uint8_t     authenticatedData:1;
   uint8_t     zReserved:1;
   uint8_t     recursionAvailable:1;
   uint16_t    queryCount;
   uint16_t    answerCount;
   uint16_t    authorityCount;
   uint16_t    additionalCount;
} __attribute__((__packed__)) DNSHeader_t;

typedef enum _DNSOpCode_t {
   DNSOpQuery     = 0,
   DNSOpIQuery    = 1,
   DNSOpStatus    = 2,
   DNSOpNotify    = 4,
   DNSOpUpdate    = 5
} DNSOpCode_t;

static bool packetHasBytes(int offset, size_t count, uint16_t packetLength)
{
   return offset >= 0 &&
      static_cast<size_t>(offset) <= packetLength &&
      count <= packetLength - static_cast<size_t>(offset);
}

static bool validDNSName(const char* name, size_t suffixLength)
{
   if (NULL == name || '\0' == name[0])
      return false;

   size_t nameLength = strlen(name);
   if (nameLength + suffixLength > 253)
      return false;

   size_t labelLength = 0;
   for (size_t i=0; i<nameLength; i++) {
      if ('.' == name[i]) {
         if (0 == labelLength)
            return false;
         labelLength = 0;
      } else if (++labelLength > 63) {
         return false;
      }
   }
   return labelLength > 0;
}

// for some reason, I get data corruption issues with normal malloc() on arduino 0017
void* my_malloc(unsigned s)
{
#if defined(_BROKEN_MALLOC_)
   char* b = (char*)malloc(s+2);
   if (b)
      b++;
   
   return (void*)b;
#else
   return malloc(s);
#endif
}

void my_free(void* ptr)
{
#if defined(_BROKEN_MALLOC_)
   char* b = (char*)ptr;
   if (b)
      b--;
   
   free(b);
#else
   free(ptr);
#endif
}

static bool validEncodedDNSName(
   const uint8_t* packet, uint16_t packetLength,
   uint16_t offset, uint16_t encodedEnd)
{
   if (offset >= encodedEnd || encodedEnd > packetLength)
      return false;

   uint16_t cursor = offset;
   uint16_t boundary = encodedEnd;
   bool followingPointer = false;
   while (packetHasBytes(cursor, 1, boundary)) {
      uint8_t labelLength = packet[cursor];
      if (0 == labelLength)
         return followingPointer || cursor + 1 == encodedEnd;

      if ((labelLength & 0xc0) == 0xc0) {
         if (!packetHasBytes(cursor, 2, boundary) ||
             (!followingPointer && cursor + 2 != encodedEnd))
            return false;
         uint16_t target =
            (static_cast<uint16_t>(labelLength & 0x3f) << 8) |
            packet[cursor + 1];
         if (target >= cursor || !packetHasBytes(target, 1, packetLength))
            return false;
         cursor = target;
         boundary = packetLength;
         followingPointer = true;
         continue;
      }

      if (labelLength > 63 ||
          !packetHasBytes(cursor + 1, labelLength, boundary))
         return false;
      cursor += labelLength + 1;
   }
   return false;
}

static bool readServiceInstance(
   const uint8_t* packet, uint16_t packetLength, uint16_t offset, uint16_t recordEnd,
   uint8_t** instance, uint16_t* nameOffset)
{
   if (!validEncodedDNSName(packet, packetLength, offset, recordEnd))
      return false;

   uint16_t sourceOffset = offset;
   uint8_t labelLength = packet[offset];
   if ((labelLength & 0xc0) == 0xc0) {
      sourceOffset =
         (static_cast<uint16_t>(labelLength & 0x3f) << 8) |
         packet[offset + 1];
      labelLength = packet[sourceOffset];
   }

   if (0 == labelLength || labelLength > 63 ||
       !packetHasBytes(sourceOffset + 1, labelLength, packetLength))
      return false;

   uint8_t* value = (uint8_t*)my_malloc(labelLength + 1);
   if (NULL == value)
      return false;
   memcpy(value, packet + sourceOffset + 1, labelLength);
   value[labelLength] = '\0';
   *instance = value;
   *nameOffset = sourceOffset;
   return true;
}

static bool validTXTRecord(
   const uint8_t* packet, uint16_t offset, uint16_t dataLength)
{
   uint16_t cursor = offset;
   uint16_t end = offset + dataLength;
   while (cursor < end) {
      uint8_t stringLength = packet[cursor++];
      if (stringLength > end - cursor)
         return false;
      cursor += stringLength;
   }
   return true;
}

void MDNS::_initialize()
{
   memset(&this->_mdnsData, 0, sizeof(MDNSDataInternal_t));
   memset(&this->_serviceRecords, 0, sizeof(this->_serviceRecords));
   this->_state = MDNSStateIdle;
//   this->_sock = -1;
   
   this->_name = NULL;
   this->_resolveNames[0] = NULL;
   this->_resolveNames[1] = NULL;
   this->_nameFoundCallback = NULL;
   this->_serviceFoundCallback = NULL;
   this->_writeFailed = false;
   
   this->_lastAnnounceMillis = 0;
}

MDNS::~MDNS()
{
	this->end();
}

void MDNS::end()
{
   this->removeAllServiceRecords();
   this->cancelResolveName();
   this->stopDiscoveringService();
   my_free(this->_name);
   this->_name = NULL;
   this->_udp->stop();
   this->_state = MDNSStateIdle;
   this->_lastAnnounceMillis = 0;
}

int MDNS::announce()
{
   if (NULL == this->_name)
      return 0;

   int success = MDNSSuccess == this->_sendMDNSMessage(
      0, 0, MDNSPacketTypeMyIPAnswer, 0);
   for (int index = 0; index < NumMDNSServiceRecords; ++index) {
      if (NULL != this->_serviceRecords[index])
         success &= MDNSSuccess == this->_sendMDNSMessage(
            0, 0, MDNSPacketTypeServiceRecord, index);
   }
   if (success)
      this->_lastAnnounceMillis = millis();
   return success;
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::begin(const IPAddress& ip, const char* name)
{
   this->end();

   if (this->_waitForNetworkHardware) {
      // Give the EthernetShield (WIZnet) time to accept an immediate announcement.
      while (millis() < 3000) delay(100);
   }

	_ipAddress = ip;

	int statusCode = 0;
	statusCode = this->setName(name);
	if (statusCode)
	statusCode = this->_udp->beginMulticast(mdnsMulticastIPAddr, MDNS_SERVER_PORT);

	return statusCode;
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::begin(const IPAddress& ip)
{
   return this->begin(ip, MDNS_DEFAULT_NAME);
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::_initQuery(uint8_t idx, const char* name, unsigned long timeout)
{
   int statusCode = 0;
   
   if (NULL == this->_resolveNames[idx] && NULL != ((0==idx) ? (void*)this->_nameFoundCallback :
                                                               (void*)this->_serviceFoundCallback)) {
      this->_resolveNames[idx] = (uint8_t*)name;
      
      if (timeout)
         this->_resolveTimeouts[idx] = millis() + timeout;
      else
         this->_resolveTimeouts[idx] = 0;
      
      statusCode = (MDNSSuccess == this->_sendMDNSMessage(0,
                                             0,
                                             (idx == 0) ? MDNSPacketTypeNameQuery :
                                                          MDNSPacketTypeServiceQuery,
                                             0));
      if (!statusCode)
         this->_cancelQuery(idx);
   } else
      my_free((void*)name);
   
   return statusCode;
}

void MDNS::_cancelQuery(uint8_t idx)
{
   if (NULL != this->_resolveNames[idx]) {
      my_free(this->_resolveNames[idx]);
      this->_resolveNames[idx] = NULL;
   }
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::resolveName(const char* name, unsigned long timeout)
{   
   this->cancelResolveName();

   if (!validDNSName(name, strlen(MDNS_TLD)))
      return 0;
   
   char* n = (char*)my_malloc(strlen(name) + 7);
   if (NULL == n)
      return 0;
   
   strcpy(n, name);
   strcat(n, MDNS_TLD);
         
   return this->_initQuery(0, n, timeout);
}

void MDNS::setNameResolvedCallback(MDNSNameFoundCallback newCallback)
{
   this->_nameFoundCallback = newCallback;
}

void MDNS::cancelResolveName()
{
   this->_cancelQuery(0);
}

int MDNS::isResolvingName()
{
   return (NULL != this->_resolveNames[0]);
}

void MDNS::setServiceFoundCallback(MDNSServiceFoundCallback newCallback)
{
   this->_serviceFoundCallback = newCallback;
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::startDiscoveringService(const char* serviceName,
                                                  MDNSServiceProtocol_t proto,
                                                  unsigned long timeout)
{   
   this->stopDiscoveringService();

   const uint8_t* srv_type = this->_postfixForProtocol(proto);
   if (NULL == srv_type ||
       !validDNSName(serviceName, strlen((const char*)srv_type)))
      return 0;
   
   char* n = (char*)my_malloc(strlen(serviceName) + 13);
   if (NULL == n)
      return 0;
   
   strcpy(n, serviceName);   
         
   strcat(n, (const char*)srv_type);
   
   this->_resolveServiceProto = proto;
   
   return this->_initQuery(1, n, timeout);
}

void MDNS::stopDiscoveringService()
{
   this->_cancelQuery(1);
}

int MDNS::isDiscoveringService()
{
   return (NULL != this->_resolveNames[1]);
}

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSError_t MDNS::_sendMDNSMessage(uint32_t /*peerAddress*/, uint32_t xid, int type,
                                                   int serviceRecord)
{
   MDNSError_t statusCode = MDNSSuccess;
   this->_writeFailed = false;
   uint16_t ptr = 0;
#if defined(_USE_MALLOC_)
   DNSHeader_t* dnsHeader = NULL;
#else
   DNSHeader_t dnsHeaderBuf;
   DNSHeader_t* dnsHeader = &dnsHeaderBuf;
#endif
   uint8_t* buf;
   


#if defined(_USE_MALLOC_)
   dnsHeader = (DNSHeader_t*)my_malloc(sizeof(DNSHeader_t));
   if (NULL == dnsHeader) {
      statusCode = MDNSOutOfMemory;
      goto errorReturn;
   }
#endif
      
   memset(dnsHeader, 0, sizeof(DNSHeader_t));
   
   dnsHeader->xid = ethutil_htons(xid);
   dnsHeader->opCode = DNSOpQuery;
   
   switch (type) {
      case MDNSPacketTypeServiceRecordRelease:
      case MDNSPacketTypeMyIPAnswer:
         dnsHeader->answerCount = ethutil_htons(1);
         dnsHeader->queryResponse = 1;
         dnsHeader->authoritiveAnswer = 1;
         break;
      case MDNSPacketTypeServiceRecord:
         dnsHeader->answerCount = ethutil_htons(4);
         dnsHeader->additionalCount = ethutil_htons(1);
         dnsHeader->queryResponse = 1;
         dnsHeader->authoritiveAnswer = 1;
         break;
      case MDNSPacketTypeNameQuery:
      case MDNSPacketTypeServiceQuery:
         dnsHeader->queryCount = ethutil_htons(1);
         break;
      case MDNSPacketTypeNoIPv6AddrAvailable:
         dnsHeader->queryCount = ethutil_htons(1);
         dnsHeader->additionalCount = ethutil_htons(1);
         dnsHeader->responseCode = 0;
         dnsHeader->authoritiveAnswer = 1;
         dnsHeader->queryResponse = 1;
         break;
   }




   if (!this->_udp->beginPacket(mdnsMulticastIPAddr,MDNS_SERVER_PORT)) {
      statusCode = MDNSSocketError;
      goto errorReturn;
   }
   this->_writeBytes((uint8_t*)dnsHeader,sizeof(DNSHeader_t));

   ptr += sizeof(DNSHeader_t);
   buf = (uint8_t*)dnsHeader;
   
   // construct the answer section
   switch (type) {
      case MDNSPacketTypeMyIPAnswer: {
         this->_writeMyIPAnswerRecord(&ptr, buf, sizeof(DNSHeader_t));
         break;
      }

#if defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION
      
      case MDNSPacketTypeServiceRecord: {

         // SRV location record
         this->_writeServiceRecordName(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 0);
         
         buf[0] = 0x00;
         buf[1] = 0x21;    // SRV record
         buf[2] = 0x80;    // cache flush
         buf[3] = 0x01;    // class IN
         
         // ttl
         *((uint32_t*)&buf[4]) = ethutil_htonl(MDNS_RESPONSE_TTL);
         
         // data length
         *((uint16_t*)&buf[8]) = ethutil_htons(8 + strlen((char*)this->_name));

         this->_writeBytes((uint8_t*)buf,10);
         ptr += 10;
         // priority and weight
         buf[0] = buf[1] = buf[2] = buf[3] = 0;
         
         // port
         *((uint16_t*)&buf[4]) = ethutil_htons(this->_serviceRecords[serviceRecord]->port);
         
         this->_writeBytes((uint8_t*)buf,6);
         ptr += 6;
         // target
         this->_writeDNSName(this->_name, &ptr, buf, sizeof(DNSHeader_t), 1);
         
         // TXT record
         this->_writeServiceRecordName(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 0);
         
         buf[0] = 0x00;
         buf[1] = 0x10;    // TXT record
         buf[2] = 0x80;    // cache flush
         buf[3] = 0x01;    // class IN
         
         // ttl
         *((uint32_t*)&buf[4]) = ethutil_htonl(MDNS_RESPONSE_TTL);

         this->_writeBytes((uint8_t*)buf,8);
         ptr += 8;
         
         // data length, character-string length, and text
         size_t slen = NULL == this->_serviceRecords[serviceRecord]->textContent
            ? 0
            : strlen((char*)this->_serviceRecords[serviceRecord]->textContent);
         if (slen > 255) {
            statusCode = MDNSInvalidArgument;
            goto errorReturn;
         }
         *((uint16_t*)buf) = ethutil_htons(slen + 1);
         buf[2] = static_cast<uint8_t>(slen);
         this->_writeBytes((uint8_t*)buf,3);
         ptr += 3;
         if (slen > 0) {
            this->_writeBytes(
               (uint8_t*)this->_serviceRecords[serviceRecord]->textContent, slen);
            ptr += slen;
         }
         
         // PTR record (for the DNS-SD service in general)
         this->_writeDNSName((const uint8_t*)DNS_SD_SERVICE, &ptr, buf,
                                          sizeof(DNSHeader_t), 1);
         
         buf[0] = 0x00;
         buf[1] = 0x0c;    // PTR record
         buf[2] = 0x00;    // no cache flush
         buf[3] = 0x01;    // class IN
         
         // ttl
         *((uint32_t*)&buf[4]) = ethutil_htonl(MDNS_RESPONSE_TTL);
         
         // data length.
         uint16_t dlen = strlen((char*)this->_serviceRecords[serviceRecord]->servName) + 2;
         *((uint16_t*)&buf[8]) = ethutil_htons(dlen);

         this->_writeBytes((uint8_t*)buf, 10);
         ptr += 10;
         
         this->_writeServiceRecordName(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 1);
         
         // PTR record (our service)
         this->_writeServiceRecordPTR(serviceRecord, &ptr, buf, sizeof(DNSHeader_t),
                                      MDNS_RESPONSE_TTL);
         
         // finally, our IP address as additional record
         this->_writeMyIPAnswerRecord(&ptr, buf, sizeof(DNSHeader_t));

         break;
      }
      
      case MDNSPacketTypeServiceRecordRelease: {
         // just send our service PTR with a TTL of zero
         this->_writeServiceRecordPTR(serviceRecord, &ptr, buf, sizeof(DNSHeader_t), 0);
         break;
      }
      
#endif // defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION

#if defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING
    
      case MDNSPacketTypeNameQuery:
      case MDNSPacketTypeServiceQuery: 
      {
         // construct a query for the currently set _resolveNames[0]
         this->_writeDNSName(
               (type == MDNSPacketTypeServiceQuery) ? this->_resolveNames[1] :
                                                      this->_resolveNames[0],
               &ptr, buf, sizeof(DNSHeader_t), 1);

         buf[0] = buf[2] = 0x0;
         buf[1] = (type == MDNSPacketTypeServiceQuery) ? 0x0c : 0x01; 
         buf[3] = 0x1;

         this->_writeBytes((uint8_t*)buf, 4);
         ptr += 4;
         
         this->_resolveLastSendMillis[(type == MDNSPacketTypeServiceQuery) ? 1 : 0] = millis();
         
         break;
      }
      
#endif // defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING
      
      case MDNSPacketTypeNoIPv6AddrAvailable: {
         // Return NOERROR without an AAAA record and include the available IPv4 address.
         this->_writeDNSName(this->_name, &ptr, buf, sizeof(DNSHeader_t), 1);
         
         buf[0] = buf[2] = 0x0;
         buf[1] = 0x1c; // AAAA record
         buf[3] = 0x01;

         this->_writeBytes((uint8_t*)buf, 4);
         ptr += 4;
         
         // send our IPv4 address record as additional record, in case the peer wants it.
         this->_writeMyIPAnswerRecord(&ptr, buf, sizeof(DNSHeader_t));
         
         break;
      }
   }


   if (this->_writeFailed)
      statusCode = MDNSSocketError;
   else if (!this->_udp->endPacket())
      statusCode = MDNSSocketError;

errorReturn:

#if defined(_USE_MALLOC_)
   if (NULL != dnsHeader)
      my_free(dnsHeader);
#endif
   
   return statusCode;
}

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSError_t MDNS::_processMDNSQuery()
{
   MDNSError_t statusCode = MDNSSuccess;
#if defined(_USE_MALLOC_)
   DNSHeader_t* dnsHeader = NULL;
#else
   DNSHeader_t dnsHeaderBuf;
   DNSHeader_t* dnsHeader = &dnsHeaderBuf;
#endif
   unsigned int i, j;
   uint8_t* buf;
   uint32_t xid = 0;
   uint16_t udp_len, qCnt, aCnt, aaCnt, addCnt;
   uint8_t recordsAskedFor[NumMDNSServiceRecords+2];
   uint8_t recordsFound[2];
   uint8_t wantsIPv6Addr = 0;
   uint8_t * udpBuffer = NULL;
   uint8_t* ptrNames[MDNS_MAX_SERVICES_PER_PACKET] = {};
   uint8_t* servTxt[MDNS_MAX_SERVICES_PER_PACKET] = {};
   uintptr_t ptr;

   memset(recordsAskedFor, 0, sizeof(uint8_t)*(NumMDNSServiceRecords+2));
   memset(recordsFound, 0, sizeof(uint8_t)*2);


   udp_len = this->_udp->parsePacket();
   if (0 == udp_len) {
      statusCode = MDNSTryLater;
      goto errorReturn;
   }
   if (udp_len < sizeof(DNSHeader_t) || this->_name == NULL) {
      this->_udp->flush();
      statusCode = MDNSInvalidArgument;
      goto errorReturn;
   }

   udpBuffer = (uint8_t*) my_malloc(udp_len);  //allocate memory to hold _remaining UDP packet
   if (NULL == udpBuffer) {
      this->_udp->flush();
      statusCode = MDNSOutOfMemory;
      goto errorReturn;
   }
   if (this->_udp->read(udpBuffer, udp_len) != udp_len) {
      statusCode = MDNSInvalidArgument;
      goto errorReturn;
   }
   ptr = (uintptr_t)udpBuffer;

#if defined(_USE_MALLOC_)
   dnsHeader = (DNSHeader_t*)my_malloc(sizeof(DNSHeader_t));
   if (NULL == dnsHeader) {
      statusCode = MDNSOutOfMemory;
      goto errorReturn;
   }
#endif

   buf = (uint8_t*)dnsHeader;
   memcpy((uint8_t*)buf, (uint16_t*)ptr ,sizeof(DNSHeader_t));
   
   xid = ethutil_ntohs(dnsHeader->xid);
   qCnt = ethutil_ntohs(dnsHeader->queryCount);
   aCnt = ethutil_ntohs(dnsHeader->answerCount);
   aaCnt = ethutil_ntohs(dnsHeader->authorityCount);
   addCnt = ethutil_ntohs(dnsHeader->additionalCount);

   if (0 == dnsHeader->queryResponse &&
       DNSOpQuery == dnsHeader->opCode &&
       MDNS_SERVER_PORT == this->_udp->remotePort())
	  {
      // process an MDNS query
      int offset = sizeof(DNSHeader_t);
      uint8_t* buf = (uint8_t*)dnsHeader;
      int rLen = 0, tLen = 0;
      uint16_t servNamePos[NumMDNSServiceRecords+2] = {};

      // read over the query section 
      for (i=0; i<qCnt; i++) {         
         // construct service name data structures for comparison
         const uint8_t* servNames[NumMDNSServiceRecords+2];
         int servLens[NumMDNSServiceRecords+2];
         uint8_t servMatches[NumMDNSServiceRecords+2];
         
         // first entry is our own MDNS name, the rest are our services
         servNames[0] = (const uint8_t*)this->_name;
         servLens[0] = strlen((char*)this->_name);
         servMatches[0] = 1;
         
         // second entry is our own the general DNS-SD service
         servNames[1] = (const uint8_t*)DNS_SD_SERVICE;
         servLens[1] = strlen((char*)DNS_SD_SERVICE);
         servMatches[1] = 1;
                  
         for (j=2; j<NumMDNSServiceRecords+2; j++)
            if (NULL != this->_serviceRecords[j-2] && NULL != this->_serviceRecords[j-2]->servName) {
               servNames[j] = this->_serviceRecords[j-2]->servName;
               servLens[j] = strlen((char*)servNames[j]);
               servMatches[j] = 1;
            } else {
               servNames[j] = NULL;
               servLens[j] = 0;
               servMatches[j] = 0;
            }
   
         tLen = 0;
         do {


            if (offset >= udp_len) {
               statusCode = MDNSInvalidArgument;
               goto errorReturn;
            }
        	memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,1);
            offset += 1;

            rLen = buf[0];
            tLen += 1;
            
            if ((rLen & 0xc0) == 0xc0) {// handle DNS name compression, kinda, sorta


               if (offset >= udp_len) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }

            	memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,1);
            	offset += 1;
               uint16_t compressedOffset =
                  (static_cast<uint16_t>(rLen & 0x3f) << 8) | buf[0];
               if (compressedOffset >= static_cast<uint16_t>(offset - 2)) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }
               
               for (j=0; j<NumMDNSServiceRecords+2; j++) {
                  if (0 == servNamePos[j] ||
                      servNamePos[j] != compressedOffset) {
                     servMatches[j] = 0;
                  } else {
                     servLens[j] = 0;
                  }
               }
               
               tLen += 1;
            } else if (rLen > 0) {
               if (rLen > 63 || offset + rLen > udp_len) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }
               int tr = rLen, ir;
               
               while (tr > 0) {
                  ir = (tr > (int)sizeof(DNSHeader_t)) ? sizeof(DNSHeader_t) : tr;

                  memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,ir);
                  offset += ir;
                  tr -= ir;
                  
                  for (j=0; j<NumMDNSServiceRecords+2; j++) {
                     if (!recordsAskedFor[j] && servMatches[j])
                        servMatches[j] &= this->_matchStringPart(&servNames[j], &servLens[j], buf,
                                                                 ir);
                  }
               }
               
               tLen += rLen;
            }
         } while (rLen > 0 && rLen <= 128);

         // if this matched a name of ours (and there are no characters left), then
         // check whether this is an A record query (for our own name) or a PTR record query
         // (for one of our services).
         // if so, we'll note to send a record

         if (offset + 4 > udp_len) {
            statusCode = MDNSInvalidArgument;
            goto errorReturn;
         }
         memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,4);
         offset += 4;
         
         for (j=0; j<NumMDNSServiceRecords+2; j++) {
            if (!recordsAskedFor[j] && servNames[j] && servMatches[j] && 0 == servLens[j]) {
               if (0 == servNamePos[j])
                  servNamePos[j] = offset - 4 - tLen;
               
               if (buf[0] == 0 && buf[3] == 0x01 &&
                  (buf[2] == 0x00 || buf[2] == 0x80)) {
                  
                    if ((0 == j && (0x01 == buf[1] || 0xff == buf[1])) ||
                       (0 < j && (0x0c == buf[1] || 0x10 == buf[1] ||
                               0x21 == buf[1] || 0xff == buf[1])))
                     recordsAskedFor[j] = 1;
                  else if (0 == j && 0x1c == buf[1])
                     wantsIPv6Addr = 1;
               }
            }
         }
      }
   } 
   
#if (defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION) || (defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING)

   else if (1 == dnsHeader->queryResponse &&
              DNSOpQuery == dnsHeader->opCode &&
              MDNS_SERVER_PORT == this->_udp->remotePort() &&
              (NULL != this->_resolveNames[0] || NULL != this->_resolveNames[1]))
	     {
         int offset = sizeof(DNSHeader_t);
         uint8_t* buf = (uint8_t*)dnsHeader;
         int rLen = 0, tLen = 0;
         
         uint16_t ptrOffsets[MDNS_MAX_SERVICES_PER_PACKET];
         uint16_t ptrPorts[MDNS_MAX_SERVICES_PER_PACKET];
         uint16_t ptrTargetOffsets[MDNS_MAX_SERVICES_PER_PACKET];
         uint16_t servIPOffsets[MDNS_MAX_SERVICES_PER_PACKET];
         uint8_t servIPs[MDNS_MAX_SERVICES_PER_PACKET][4];
         memset(ptrOffsets, 0, sizeof(ptrOffsets));
         memset(ptrPorts, 0, sizeof(ptrPorts));
         memset(ptrTargetOffsets, 0, sizeof(ptrTargetOffsets));
         memset(servIPOffsets, 0, sizeof(servIPOffsets));
         memset(servIPs, 0, sizeof(servIPs));
         
         const uint8_t* ptrNamesCmp[MDNS_MAX_SERVICES_PER_PACKET];
         int ptrLensCmp[MDNS_MAX_SERVICES_PER_PACKET];
         uint8_t ptrNamesMatches[MDNS_MAX_SERVICES_PER_PACKET];
         
         uint8_t checkAARecords = 0;
         memset(ptrNames, 0, sizeof(uint8_t*)*MDNS_MAX_SERVICES_PER_PACKET);
         
         const uint8_t* servNames[2];
         uint16_t servNamePos[2];
         int servLens[2];
         uint8_t servMatches[2];
         uint16_t firstNamePtrOffset = 0;
         uint8_t partMatched[2];
         uint8_t lastWasCompressed[2];
         uint8_t servWasCompressed[2];
         
         servNamePos[0] = servNamePos[1] = 0;
                  
         for (i=0; i<(unsigned int)(qCnt+aCnt+aaCnt+addCnt); i++) {

            for (j=0; j<2; j++) {
               if (NULL != this->_resolveNames[j]) {
                  servNames[j] = this->_resolveNames[j];
                  servLens[j] = strlen((const char*)this->_resolveNames[j]);
                  servMatches[j] = 1;
               } else {
                  servNames[j] = NULL;
                  servLens[j] = servMatches[j] = 0;
               }
            }
            
            for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
               if (NULL != ptrNames[j]) {
                  ptrNamesCmp[j] = ptrNames[j];
                  ptrLensCmp[j] = strlen((const char*)ptrNames[j]);
                  ptrNamesMatches[j] = 1;
               }
            }
            
            partMatched[0] = partMatched[1] = 0;
            lastWasCompressed[0] = lastWasCompressed[1] = 0;
            servWasCompressed[0] = servWasCompressed[1] = 0;
            firstNamePtrOffset = 0;
            tLen = 0;
                        
            do {
               if (!packetHasBytes(offset, 1, udp_len)) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }
            	memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,1);
               offset += 1;
               rLen = buf[0];
               tLen += 1;
            
               if ((rLen & 0xc0) == 0xc0) { // handle DNS name compression, kinda, sorta...
                  if (!packetHasBytes(offset, 1, udp_len)) {
                     statusCode = MDNSInvalidArgument;
                     goto errorReturn;
                  }
            	   memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,1);
                  offset += 1;
                  uint16_t compressedOffset =
                     (static_cast<uint16_t>(rLen & 0x3f) << 8) | buf[0];
                  if (compressedOffset >= static_cast<uint16_t>(offset - 2) ||
                      !packetHasBytes(compressedOffset, 1, udp_len)) {
                     statusCode = MDNSInvalidArgument;
                     goto errorReturn;
                  }

                  for (j=0; j<2; j++) {
                     if (servNamePos[j] && servNamePos[j] != compressedOffset)
                        servMatches[j] = 0;
                     else
                        servWasCompressed[j] = 1;
                     
                     lastWasCompressed[j] = 1;
                  }
               
                  tLen += 1;
                  
                  if (0 == firstNamePtrOffset)
                     firstNamePtrOffset = compressedOffset;
               } else if (rLen > 0) {
                  if (rLen > 63 || !packetHasBytes(offset, rLen, udp_len)) {
                     statusCode = MDNSInvalidArgument;
                     goto errorReturn;
                  }
                  if (i < qCnt)
                     offset += rLen;
                  else {
                     int tr = rLen, ir;
                     
                     if (0 == firstNamePtrOffset)
                        firstNamePtrOffset = offset-1; // -1, since we already read length (1 byte)
               
                     while (tr > 0) {
                        ir = (tr > (int)sizeof(DNSHeader_t)) ? sizeof(DNSHeader_t) : tr;
                        memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,ir);
                        offset += ir;
                        tr -= ir;
                  
                        for (j=0; j<2; j++) {
                           if (!recordsFound[j] && servMatches[j] && servNames[j])
                              servMatches[j] &= this->_matchStringPart(&servNames[j], &servLens[j],
                                                                       buf, ir);
                           if (!partMatched[j])
                              partMatched[j] = servMatches[j];
        
                           lastWasCompressed[j] = 0;
                        }               
                        
                        for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                           if (NULL != ptrNames[j] && ptrNamesMatches[j]) {
                              // only compare the part we have. this is incorrect, but good enough,
                              // since actual mDNS implementations won't go here anyways, as they
                              // should use name compression. This is just so that multiple Arduinos
                              // running this mDNSResponder code should be able to find each other's
                              // services.
                              if (ptrLensCmp[j] >= ir) 
                                 ptrNamesMatches[j] &= this->_matchStringPart(&ptrNamesCmp[j],
                                                            &ptrLensCmp[j], buf, ir);
                           }
                        }
                     }                     
                     
                     tLen += rLen;
                  }
               }
            } while (rLen > 0 && rLen <= 128);
                        
            // if this matched a name of ours (and there are no characters left), then
            // check whether this is an A record query (for our own name) or a PTR record query
            // (for one of our services).
            // if so, we'll note to send a record
            if (i < qCnt) {
               if (!packetHasBytes(offset, 4, udp_len)) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }
               offset += 4;
            }
            else if (i >= qCnt) {               
               if (i >= qCnt + aCnt && !checkAARecords)
                  break;
               
               uint8_t packetHandled = 0;

               if (!packetHasBytes(offset, 4, udp_len)) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }
               memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,4);
               offset += 4;
               uint8_t recordType = buf[1];
               uint8_t recordClassHigh = buf[2];
               uint8_t recordClassLow = buf[3];
               uint16_t recordNameOffset = offset - 4 - tLen;

               if (!packetHasBytes(offset, 6, udp_len)) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }
               memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,6);
               offset += 6;
               uint16_t dataLen = ethutil_ntohs(*(uint16_t*)&buf[4]);
               if (!packetHasBytes(offset, dataLen, udp_len)) {
                  statusCode = MDNSInvalidArgument;
                  goto errorReturn;
               }

               if (i < qCnt+aCnt) {
                  for (j=0; j<2; j++) {
                     if (0 == servNamePos[j])
                        servNamePos[j] = recordNameOffset;
                                      
                     if (servNames[j] &&
                         ((servMatches[j] && 0 == servLens[j]) ||
                         (partMatched[j] && lastWasCompressed[j]) ||
                         (servWasCompressed[j] && servMatches[j]))) { // somewhat handle compression by guessing
                                             
                        if (recordType == ((0 == j) ? 0x01 : 0x0c) &&
                           (recordClassHigh == 0x00 || recordClassHigh == 0x80) &&
                           recordClassLow == 0x01) {
                           recordsFound[j] = 1;
                        
                           // this is an A or PTR type response. Parse it as such.
                        
                           if (0 == j && 4 == dataLen) {
                              // ok, this is the IP address. report it via callback.

                        	   memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,4);
                              
                              this->_finishedResolvingName((char*)this->_resolveNames[0],
                                                           (const byte*)buf);
                           } else if (1 == j && dataLen >= 2) {
                              uint8_t k;
                              for (k=0; k<MDNS_MAX_SERVICES_PER_PACKET; k++)
                                 if (NULL == ptrNames[k])
                                    break;
                           
                              if (k < MDNS_MAX_SERVICES_PER_PACKET) {
                                 if (readServiceInstance(
                                        udpBuffer, udp_len, offset, offset + dataLen,
                                        &ptrNames[k], &ptrOffsets[k])) {
                                    checkAARecords = 1;
                                 } else {
                                    statusCode = MDNSInvalidArgument;
                                    goto errorReturn;
                                 }
                              }
                           }
                           offset += dataLen;
                           packetHandled = 1;
                        }
                     }
                  }
               } else if (i >= (unsigned int)(qCnt+aCnt+aaCnt)) {
                  //  check whether we find a service description
                  if (recordType == 0x21) {
                     for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                        if (ptrNames[j] &&
                              ((firstNamePtrOffset && firstNamePtrOffset == ptrOffsets[j]) ||
                              (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {
                           // we have found the matching SRV location packet to a previous SRV domain

                           if (dataLen < 8) {
                              statusCode = MDNSInvalidArgument;
                              goto errorReturn;
                           }

                           memcpy((uint8_t*)buf, (uint16_t*)(ptr+offset) ,8);
                           ptrPorts[j] = ethutil_ntohs(*(uint16_t*)&buf[4]);

                           if (!validEncodedDNSName(
                                  udpBuffer, udp_len, offset + 6, offset + dataLen)) {
                              statusCode = MDNSInvalidArgument;
                              goto errorReturn;
                           }
                           if ((buf[6] & 0xc0) == 0xc0) {
                              ptrTargetOffsets[j] =
                                 (static_cast<uint16_t>(buf[6] & 0x3f) << 8) |
                                 buf[7];
                           } else {
                              ptrTargetOffsets[j] = offset+6;
                           }
                           offset += dataLen;
                           packetHandled = 1;
                           
                           break;
                        }
                     }
                 } else if (recordType == 0x10) { // txt record
                     for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                        if (ptrNames[j] &&
                              ((firstNamePtrOffset && firstNamePtrOffset == ptrOffsets[j]) ||
                              (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {

                           if (!validTXTRecord(udpBuffer, offset, dataLen)) {
                              statusCode = MDNSInvalidArgument;
                              goto errorReturn;
                           }
                           // if there's a content to this txt record, save it for delivery
                           if (dataLen > 1 && NULL == servTxt[j]) {
                              servTxt[j] = (uint8_t*)my_malloc(dataLen+1);
                              if (NULL != servTxt[j]) {

                            	  memcpy((uint8_t*)servTxt[j], (uint16_t*)(ptr+offset) ,dataLen);
                              
                                 // zero-terminate
                                 servTxt[j][dataLen] = '\0';
                              }
                           }
                           offset += dataLen;
                           packetHandled = 1;
                        
                           break;
                        }
                     }
                  } else if (recordType == 0x01) { // A record (IPv4 address)
                     if (4 != dataLen) {
                        statusCode = MDNSInvalidArgument;
                        goto errorReturn;
                     }
                     for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                        if (0 == servIPOffsets[j]) {
                           servIPOffsets[j] =
                              firstNamePtrOffset ? firstNamePtrOffset : UINT16_MAX;

                           memcpy((uint8_t*)servIPs[j], (uint16_t*)(ptr+offset) ,4);
                  offset += dataLen;
                           packetHandled = 1;
                           
                           break;
                        }
                     }
                  }
               }
               
               // eat the answer
               if (!packetHandled) {
                  offset += dataLen;
               }
            }
         }
         
         // deliver the services discovered in this packet
         if (NULL != this->_resolveNames[1]) {
            char typeName[64];
            size_t typeLength = 0;
            while (this->_resolveNames[1][typeLength] &&
                   this->_resolveNames[1][typeLength] != '.')
               typeLength++;
            if (0 == typeLength || typeLength >= sizeof(typeName)) {
               statusCode = MDNSInvalidArgument;
               goto errorReturn;
            }
            memcpy(typeName, this->_resolveNames[1], typeLength);
            typeName[typeLength] = '\0';
            MDNSServiceFoundCallback callback = this->_serviceFoundCallback;
            MDNSServiceProtocol_t protocol = this->_resolveServiceProto;
            
            for (i=0; i<MDNS_MAX_SERVICES_PER_PACKET; i++)
               if (ptrNames[i]) {
                  const uint8_t* ipAddr = NULL;
                  const uint8_t* fallbackIpAddr = NULL;

                  for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                     if (servIPOffsets[j] == ptrTargetOffsets[i] ||
                         servIPOffsets[j] == UINT16_MAX) {
                        // the || part is such a hack, but it will work as long as there's only
                        // one A record per mDNS packet. fucking DNS name compression.                     
                        ipAddr = servIPs[j];
                        
                        break;
                     } else if (NULL == fallbackIpAddr && 0 != servIPOffsets[j])
                        fallbackIpAddr = servIPs[j];
                  }
               
                  // if we can't find a matching IP, we try to use the first one we found.
                  if (NULL == ipAddr) ipAddr = fallbackIpAddr;
               
                  if (ipAddr && ptrPorts[i] != 0 && callback) {
                     callback(typeName,
                              protocol,
                              (const char*)ptrNames[i],
                              IPAddress((const byte*)ipAddr),
                              (unsigned short)ptrPorts[i],
                              (const char*)servTxt[i]);
                  }
               }
         }
   
   }

#endif // (defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION) || (defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING)

errorReturn:

   for (i=0; i<MDNS_MAX_SERVICES_PER_PACKET; i++) {
      if (NULL != ptrNames[i])
         my_free(ptrNames[i]);
      if (NULL != servTxt[i])
         my_free(servTxt[i]);
   }
   my_free(udpBuffer);

#if defined(_USE_MALLOC_) 
   if (NULL != dnsHeader)
      my_free(dnsHeader);
#endif
   
   // now, handle the requests
   for (j=0; statusCode == MDNSSuccess && j<NumMDNSServiceRecords+2; j++) {
      if (recordsAskedFor[j]) {
         if (0 == j)
            (void)this->_sendMDNSMessage(this->_udp->remoteIP(), xid, (int)MDNSPacketTypeMyIPAnswer, 0);
         else if (1 == j) {
            uint8_t k = 2;
            for (k=0; k<NumMDNSServiceRecords; k++)
               recordsAskedFor[k+2] = 1;
         } else if (NULL != this->_serviceRecords[j-2])
            (void)this->_sendMDNSMessage(this->_udp->remoteIP(), xid, (int)MDNSPacketTypeServiceRecord, j-2);
      }
   }
   
   // if we were asked for our IPv6 address, say that we don't have any
   if (statusCode == MDNSSuccess && wantsIPv6Addr)
      (void)this->_sendMDNSMessage(this->_udp->remoteIP(), xid, (int)MDNSPacketTypeNoIPv6AddrAvailable, 0);
   
   return statusCode;
}

void MDNS::run()
{
   uint8_t i;
   unsigned long now = millis();
   
   // first, look for mDNS queries to handle
   (void)_processMDNSQuery();
   
   // are we querying a name or service? if so, should we resend the packet or time out?
   for (i=0; i<2; i++) {
      if (NULL != this->_resolveNames[i]) {
         // Hint: _resolveLastSendMillis is updated in _sendMDNSMessage
         if (now - this->_resolveLastSendMillis[i] > ((i == 0) ? (uint32_t)MDNS_NQUERY_RESEND_TIME :
                                                                 (uint32_t)MDNS_SQUERY_RESEND_TIME))
            (void)this->_sendMDNSMessage(0,
                                         0,
                                         (0 == i) ? MDNSPacketTypeNameQuery :
                                                    MDNSPacketTypeServiceQuery,
                                         0);
      
         if (this->_resolveTimeouts[i] > 0 && now > this->_resolveTimeouts[i]) {
            if (i == 0)
               this->_finishedResolvingName((char*)this->_resolveNames[0], NULL);
            else if (i == 1) {
               uint8_t* expiredName = this->_resolveNames[1];
               this->_resolveNames[1] = NULL;
               MDNSServiceFoundCallback callback = this->_serviceFoundCallback;
               MDNSServiceProtocol_t protocol = this->_resolveServiceProto;
               char typeName[64];
               size_t typeLength = 0;
               while (expiredName[typeLength] && expiredName[typeLength] != '.')
                  typeLength++;
               memcpy(typeName, expiredName, typeLength);
               typeName[typeLength] = '\0';
               my_free(expiredName);

               if (callback)
                  callback(typeName, protocol, NULL, IPAddress(), 0, NULL);
            }
         }
      }
   }
   
   // now, should we re-announce our services again?
   unsigned long announceTimeOut = (((uint32_t)MDNS_RESPONSE_TTL/2)+((uint32_t)MDNS_RESPONSE_TTL/4));
   if ((now - this->_lastAnnounceMillis) > 1000*announceTimeOut) {
      bool success = true;
      for (i=0; i<NumMDNSServiceRecords; i++) {
         if (NULL != this->_serviceRecords[i])
            success &= MDNSSuccess ==
               this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecord, i);
      }

      if (success)
         this->_lastAnnounceMillis = now;
   }
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::setName(const char* name)
{
   if (!validDNSName(name, strlen(MDNS_TLD)))
      return 0;

   uint8_t* replacement = (uint8_t*)my_malloc(strlen(name) + 7);
   if (NULL == replacement)
      return 0;
   
   strcpy((char*)replacement, name);
   strcpy((char*)replacement+strlen(name), MDNS_TLD);

   if (this->_name != NULL)
      my_free(this->_name);
   this->_name = replacement;
   
   return 1;
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::addServiceRecord(const char* name, uint16_t port,
                                           MDNSServiceProtocol_t proto)
{
#if defined(__MK20DX128__) || defined(__MK20DX256__)
	 return this->addServiceRecord(name, port, proto, NULL); //works for Teensy 3 (32-bit Arm Cortex)
#else
   return this->addServiceRecord(name, port, proto, ""); //works for Teensy 2 (8-bit Atmel)
#endif
}

// return values:
// 1 on success
// 0 otherwise
int MDNS::addServiceRecord(const char* name, uint16_t port,
                                           MDNSServiceProtocol_t proto, const char* textContent)
{
   int i, status = 0;
   MDNSServiceRecord_t* record = NULL;
   const char* separator = NULL;
   const uint8_t* srv_type = this->_postfixForProtocol(proto);
      
   if (NULL != name)
      separator = strrchr(name, '.');

   if (NULL != srv_type &&
       NULL != separator && separator != name && '\0' != separator[1] &&
       validDNSName(name, strlen((const char*)srv_type)) &&
       (NULL == textContent || strlen(textContent) <= 255) &&
       0 != port && (MDNSServiceTCP == proto || MDNSServiceUDP == proto)) {
      for (i=0; i < NumMDNSServiceRecords; i++) {
         if (NULL == this->_serviceRecords[i]) {
            record = (MDNSServiceRecord_t*)my_malloc(sizeof(MDNSServiceRecord_t));
            if (NULL != record) {
               record->name = record->textContent = record->servName = NULL;
               
               record->name = (uint8_t*)my_malloc(strlen((char*)name) + 1);
               if (NULL == record->name)
                  goto errorReturn;
               
               if (NULL != textContent) {
                  record->textContent = (uint8_t*)my_malloc(strlen((char*)textContent) + 1);
                  if (NULL == record->textContent)
                     goto errorReturn;
                  
                  strcpy((char*)record->textContent, textContent);
               }
               
               record->port = port;
               record->proto = proto;
               strcpy((char*)record->name, name);
               
               uint8_t* s = this->_findFirstDotFromRight(record->name);
               record->servName = (uint8_t*)my_malloc(strlen((char*)s) + 12);
               if (NULL == record->servName)
                  goto errorReturn;
               if (record->servName) {
                  strcpy((char*)record->servName, (const char*)s);

                  strcat((char*)record->servName, (const char*)srv_type);
               }

               this->_serviceRecords[i] = record;
                              
               status = (MDNSSuccess ==
                           this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecord, i));
               if (!status) {
                  this->_serviceRecords[i] = NULL;
                  goto errorReturn;
               }
               
               break;
            }
         }
      }
   }
   
   return status;

errorReturn:
   if (NULL != record) {
      if (NULL != record->name)
         my_free(record->name);
      if (NULL != record->servName)
         my_free(record->servName);
      if (NULL != record->textContent)
         my_free(record->textContent);
      
      my_free(record);
   }
   
   return 0;
}

void MDNS::_removeServiceRecord(int idx)
{
   if (NULL != this->_serviceRecords[idx]) {
      (void)this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecordRelease, idx);
      
      if (NULL != this->_serviceRecords[idx]->textContent)
         my_free(this->_serviceRecords[idx]->textContent);
      
      if (NULL != this->_serviceRecords[idx]->servName)
         my_free(this->_serviceRecords[idx]->servName);
      
      my_free(this->_serviceRecords[idx]->name);
      my_free(this->_serviceRecords[idx]);
      
      this->_serviceRecords[idx] = NULL;
   }
}

void MDNS::removeServiceRecord(uint16_t port, MDNSServiceProtocol_t proto)
{
   this->removeServiceRecord(NULL, port, proto);
}

void MDNS::removeServiceRecord(const char* name, uint16_t port,
                                               MDNSServiceProtocol_t proto)
{
   int i;
   for (i=0; i<NumMDNSServiceRecords; i++)
      if (NULL != this->_serviceRecords[i] &&
          port == this->_serviceRecords[i]->port &&
          proto == this->_serviceRecords[i]->proto &&
          (NULL == name || 0 == strcmp((char*)this->_serviceRecords[i]->name, name))) {
             this->_removeServiceRecord(i);
             break;
          }
}

void MDNS::removeAllServiceRecords()
{
   int i;
   for (i=0; i<NumMDNSServiceRecords; i++)
      this->_removeServiceRecord(i);
}

bool MDNS::_writeBytes(const uint8_t* buffer, size_t size)
{
   if (this->_writeFailed)
      return false;

   if (this->_udp->write(buffer, size) != size) {
      this->_writeFailed = true;
      return false;
   }
   return true;
}

void MDNS::_writeDNSName(const uint8_t* name, uint16_t* pPtr,
                                         uint8_t* buf, int bufSize, int zeroTerminate)
{
   uint16_t ptr = *pPtr;
   uint8_t* p1 = (uint8_t*)name, *p2, *p3;
   int i, c, len;
   
   while(*p1) {
      c = 1;
      p2 = p1;
      while (0 != *p2 && '.' != *p2) { p2++; c++; };

      p3 = buf;
      i = c;
      len = bufSize-1;
      *p3++ = (uint8_t)--i;
      while (i-- > 0) {
         *p3++ = *p1++;

         if (--len <= 0) {
            this->_writeBytes((uint8_t*)buf, bufSize);
            ptr += bufSize;
            len = bufSize;
            p3 = buf;
         }
      }

      while ('.' == *p1)
         ++p1;

      if (len != bufSize) {
         this->_writeBytes((uint8_t*)buf, bufSize-len);
         ptr += bufSize-len;
      }
   }
   
   if (zeroTerminate) {
      buf[0] = 0;
      this->_writeBytes((uint8_t*)buf, 1);
      ptr += 1;
   }
      
   *pPtr = ptr;
}

void MDNS::_writeMyIPAnswerRecord(uint16_t* pPtr, uint8_t* buf, int bufSize)
{
   uint16_t ptr = *pPtr;
   
   this->_writeDNSName(this->_name, &ptr, buf, bufSize, 1);

   buf[0] = 0x00;
   buf[1] = 0x01;
   buf[2] = 0x80; // cache flush: true
   buf[3] = 0x01;
   this->_writeBytes((uint8_t*)buf, 4);
   ptr += 4;

   *((uint32_t*)buf) = ethutil_htonl(MDNS_RESPONSE_TTL);
   *((uint16_t*)&buf[4]) = ethutil_htons(4);      // data length

   uint8_t myIp[4];
   myIp[0] = _ipAddress [0];
   myIp[1] = _ipAddress [1];
   myIp[2] = _ipAddress [2];
   myIp[3] = _ipAddress [3];

   memcpy(&buf[6], &myIp, 4);              // our IP address

   this->_writeBytes((uint8_t*)buf, 10);
   ptr += 10;
   
   *pPtr = ptr;
}

void MDNS::_writeServiceRecordName(int recordIndex, uint16_t* pPtr, uint8_t* buf,
                                                   int bufSize, int tld)
{
   uint16_t ptr = *pPtr;
      
   uint8_t* name = tld ? this->_serviceRecords[recordIndex]->servName :
                         this->_serviceRecords[recordIndex]->name;
   
   this->_writeDNSName(name, &ptr, buf, bufSize, tld);
   
   if (0 == tld) {
      const uint8_t* srv_type =
         this->_postfixForProtocol(this->_serviceRecords[recordIndex]->proto);
   
      if (NULL != srv_type) {
         srv_type++; // eat the dot at the beginning
         this->_writeDNSName(srv_type, &ptr, buf, bufSize, 1);
      }
   }
   
   *pPtr = ptr;
}

void MDNS::_writeServiceRecordPTR(int recordIndex, uint16_t* pPtr, uint8_t* buf,
                                                  int bufSize, uint32_t ttl)
{
   uint16_t ptr = *pPtr;

   this->_writeServiceRecordName(recordIndex, &ptr, buf, bufSize, 1);
   
   buf[0] = 0x00;
   buf[1] = 0x0c;    // PTR record
   buf[2] = 0x00;    // no cache flush
   buf[3] = 0x01;    // class IN
   
   // ttl
   *((uint32_t*)&buf[4]) = ethutil_htonl(ttl);
   
   // data length (+13 = "._tcp.local" or "._udp.local" + 1  byte zero termination)
   *((uint16_t*)&buf[8]) =
         ethutil_htons(strlen((char*)this->_serviceRecords[recordIndex]->name) + 13);

   this->_writeBytes((uint8_t*)buf, 10);
   ptr += 10;
   
   this->_writeServiceRecordName(recordIndex, &ptr, buf, bufSize, 0);
   
   *pPtr = ptr;
}

uint8_t* MDNS::_findFirstDotFromRight(const uint8_t* str)
{
   const uint8_t* p = str + strlen((char*)str);
   while (p > str && '.' != *p--);
   return (uint8_t*)&p[2];
}

// case-insensitive memcmp
static int cimemcmp(const void *s1, const void *s2, size_t n)
{
   #define TO_LOWER(c) (c >= 'A' && c <= 'Z' ? c + ('a'-'A') : c)
   for (size_t i = 0; i < n; i ++) {
      uint8_t c1 = *((uint8_t*)s1+i), c2 = *((uint8_t*)s2+i);
      int dc = TO_LOWER(c1) - TO_LOWER(c2);
      if (dc) return dc;
   }
   return 0;
   #undef TO_LOWER
}

int MDNS::_matchStringPart(const uint8_t** pCmpStr, int* pCmpLen, const uint8_t* buf,
                                           int dataLen)
{
   if (*pCmpLen < dataLen)
      return 0;
   int matches = 1;

   if (*pCmpLen >= dataLen)
      matches &= (0 == cimemcmp(*pCmpStr, buf, dataLen));
   else
      matches = 0;

   *pCmpStr += dataLen;
   *pCmpLen -= dataLen;
   if ('.' == **pCmpStr)
      (*pCmpStr)++, (*pCmpLen)--;

   return matches;
}

const uint8_t* MDNS::_postfixForProtocol(MDNSServiceProtocol_t proto)
{
   const uint8_t* srv_type = NULL;
   switch(proto) {
      case MDNSServiceTCP:
         srv_type = (uint8_t*)"._tcp" MDNS_TLD;
         break;
      case MDNSServiceUDP:
         srv_type = (uint8_t*)"._udp" MDNS_TLD;
         break;
   }
   
   return srv_type;
}

void MDNS::_finishedResolvingName(char* name, const byte ipAddr[4])
{
   uint8_t* completedName = this->_resolveNames[0];
   this->_resolveNames[0] = NULL;
   MDNSNameFoundCallback callback = this->_nameFoundCallback;

   if (NULL != callback) {
      if (NULL != name) {
         uint8_t* n = this->_findFirstDotFromRight((const uint8_t*)name);
         *(n-1) = '\0';
      }
         
      callback(
         (const char*)name, 
         (NULL != ipAddr) ? IPAddress(ipAddr) : IPAddress()
      );
   }

   my_free(completedName);
}
