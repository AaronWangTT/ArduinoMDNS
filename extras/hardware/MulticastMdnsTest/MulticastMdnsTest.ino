#include <ArduinoMDNS.h>
#include <AZ3166MulticastUdp.h>
#include <AZ3166WiFi.h>

AZ3166MulticastUDP udp;
MDNS mdns(udp, false);
bool ready = false;
bool rejoined = false;
IPAddress deviceIP;
unsigned long lastHeartbeat = 0;
unsigned long readyAt = 0;

bool startDiscovery()
{
  deviceIP = WiFi.localIP();
  udp.setLocalIPv4Address(deviceIP);
  return mdns.begin(deviceIP, "az3166-mdns-test") &&
      mdns.addServiceRecord(
          "az3166-mdns-test._http", 8080, MDNSServiceTCP,
          "\x19" "path=/hardware-validation");
}

void setup()
{
  Serial.begin(115200);
  delay(1000);
  Serial.println("HW_MDNS:BOOT");

  if (WiFi.begin() != WL_CONNECTED) {
    Serial.println("HW_MDNS:WIFI_FAILED");
    return;
  }

  Serial.print("HW_MDNS:IP=");
  Serial.println(WiFi.localIP());

  if (!startDiscovery()) {
    Serial.println("HW_MDNS:START_FAILED");
    return;
  }

  Serial.println("HW_MDNS:READY");
  ready = true;
  readyAt = millis();
}

void loop()
{
  if (!ready) {
    delay(1000);
    return;
  }

  if (!rejoined && millis() - readyAt >= 10000) {
    Serial.println("HW_MDNS:REJOIN_BEGIN");
    mdns.end();
    WiFi.disconnect();
    delay(1000);
    if (WiFi.begin() != WL_CONNECTED || !startDiscovery()) {
      Serial.println("HW_MDNS:REJOIN_FAILED");
      ready = false;
      return;
    }
    rejoined = true;
    Serial.print("HW_MDNS:REJOIN_READY IP=");
    Serial.println(deviceIP);
  }

  mdns.run();
  if (udp.failed()) {
    Serial.println("HW_MDNS:TRANSPORT_FAILED");
    mdns.end();
    ready = false;
    return;
  }

  if (millis() - lastHeartbeat >= 2000) {
    lastHeartbeat = millis();
    Serial.print(rejoined ? "HW_MDNS:REJOIN_READY IP=" : "HW_MDNS:READY IP=");
    Serial.println(deviceIP);
  }
  delay(20);
}
