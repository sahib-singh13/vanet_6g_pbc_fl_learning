#ifndef VEHICLE_APP_H
#define VEHICLE_APP_H

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <string>
#include <unordered_set>
#include <vector>

namespace ns3 {

class VehicleApp : public Application
{
public:
  VehicleApp();
  ~VehicleApp() override;

  static TypeId GetTypeId();

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void SendRegisterRequest();
  void HandleRsuRead(Ptr<Socket> socket);
  void HandleV2vRead(Ptr<Socket> socket);
  void SendV2iPing();
  void SendV2vMessage();
  void Rebroadcast(Ptr<Packet> packet);
  void MarkInfected();

  Ptr<Socket> m_rsuSocket;
  Ptr<Socket> m_v2vSocket;

  Ipv4Address m_rsuAddress{"10.1.0.1"};
  uint16_t m_rsuPort{9100};
  uint16_t m_v2vPort{9200};
  Ipv4Address m_relayAddress{"10.2.0.1"};
  uint16_t m_relayPort{9200};

  Time m_messageInterval{Seconds(1.0)};
  Time m_v2iInterval{Seconds(1.0)};
  Time m_registrationInterval{Seconds(2.0)};
  bool m_verifySignatures{true};
  bool m_broadcastRegister{true};
  bool m_useBsRelay{false};

  uint32_t m_vehicleId{0};
  uint32_t m_nextMessageId{0};
  uint32_t m_nextV2iId{0};
  bool m_hasCredentials{false};
  bool m_infected{false};

  std::string m_publicKeyPem;
  std::string m_privateKeyPem;
  std::vector<uint8_t> m_cert;
  std::string m_taPublicKeyPem;

  std::unordered_set<uint64_t> m_seenMessages;
};

} // namespace ns3

#endif // VEHICLE_APP_H
