#ifndef __MDNS_TRANSPORT_H__
#define __MDNS_TRANSPORT_H__ 1

#include <Arduino.h>
#include <IPAddress.h>

class MDNSTransport
{
public:
   template <typename Transport>
   explicit MDNSTransport(Transport& transport)
      : _context(&transport),
        _beginMulticast(&invokeBeginMulticast<Transport>),
        _stop(&invokeStop<Transport>),
        _beginPacket(&invokeBeginPacket<Transport>),
        _write(&invokeWrite<Transport>),
        _endPacket(&invokeEndPacket<Transport>),
        _parsePacket(&invokeParsePacket<Transport>),
        _read(&invokeRead<Transport>),
        _flush(&invokeFlush<Transport>),
        _remoteIP(&invokeRemoteIP<Transport>),
        _remotePort(&invokeRemotePort<Transport>)
   {
   }

   uint8_t beginMulticast(IPAddress address, uint16_t port)
   {
      return _beginMulticast(_context, address, port);
   }

   void stop()
   {
      _stop(_context);
   }

   int beginPacket(IPAddress address, uint16_t port)
   {
      return _beginPacket(_context, address, port);
   }

   size_t write(const uint8_t* buffer, size_t size)
   {
      return _write(_context, buffer, size);
   }

   int endPacket()
   {
      return _endPacket(_context);
   }

   int parsePacket()
   {
      return _parsePacket(_context);
   }

   int read(uint8_t* buffer, size_t size)
   {
      return _read(_context, buffer, size);
   }

   void flush()
   {
      _flush(_context);
   }

   IPAddress remoteIP()
   {
      return _remoteIP(_context);
   }

   uint16_t remotePort()
   {
      return _remotePort(_context);
   }

private:
   typedef uint8_t (*BeginMulticastFunction)(void*, IPAddress, uint16_t);
   typedef void (*StopFunction)(void*);
   typedef int (*BeginPacketFunction)(void*, IPAddress, uint16_t);
   typedef size_t (*WriteFunction)(void*, const uint8_t*, size_t);
   typedef int (*EndPacketFunction)(void*);
   typedef int (*ParsePacketFunction)(void*);
   typedef int (*ReadFunction)(void*, uint8_t*, size_t);
   typedef void (*FlushFunction)(void*);
   typedef IPAddress (*RemoteIPFunction)(void*);
   typedef uint16_t (*RemotePortFunction)(void*);

   template <typename Transport>
   static uint8_t invokeBeginMulticast(void* context, IPAddress address, uint16_t port)
   {
      return static_cast<Transport*>(context)->beginMulticast(address, port);
   }

   template <typename Transport>
   static void invokeStop(void* context)
   {
      static_cast<Transport*>(context)->stop();
   }

   template <typename Transport>
   static int invokeBeginPacket(void* context, IPAddress address, uint16_t port)
   {
      return static_cast<Transport*>(context)->beginPacket(address, port);
   }

   template <typename Transport>
   static size_t invokeWrite(void* context, const uint8_t* buffer, size_t size)
   {
      return static_cast<Transport*>(context)->write(buffer, size);
   }

   template <typename Transport>
   static int invokeEndPacket(void* context)
   {
      return static_cast<Transport*>(context)->endPacket();
   }

   template <typename Transport>
   static int invokeParsePacket(void* context)
   {
      return static_cast<Transport*>(context)->parsePacket();
   }

   template <typename Transport>
   static int invokeRead(void* context, uint8_t* buffer, size_t size)
   {
      return static_cast<Transport*>(context)->read(buffer, size);
   }

   template <typename Transport>
   static void invokeFlush(void* context)
   {
      static_cast<Transport*>(context)->flush();
   }

   template <typename Transport>
   static IPAddress invokeRemoteIP(void* context)
   {
      return static_cast<Transport*>(context)->remoteIP();
   }

   template <typename Transport>
   static uint16_t invokeRemotePort(void* context)
   {
      return static_cast<Transport*>(context)->remotePort();
   }

   void* _context;
   BeginMulticastFunction _beginMulticast;
   StopFunction _stop;
   BeginPacketFunction _beginPacket;
   WriteFunction _write;
   EndPacketFunction _endPacket;
   ParsePacketFunction _parsePacket;
   ReadFunction _read;
   FlushFunction _flush;
   RemoteIPFunction _remoteIP;
   RemotePortFunction _remotePort;
};

#endif // __MDNS_TRANSPORT_H__