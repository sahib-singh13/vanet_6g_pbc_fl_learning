#ifndef RSU_APP_H
#define RSU_APP_H

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace ns3 {

class RsuApp : public Application
{
public:
  RsuApp();
  ~RsuApp() override;

  static TypeId GetTypeId();

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleVehicleRead(Ptr<Socket> socket);
  void HandleBsRead(Ptr<Socket> socket);
  void SendRegisterToBs(uint32_t nodeId);

  Ptr<Socket> m_vehicleSocket;
  Ptr<Socket> m_bsSocket;

  uint16_t m_vehiclePort{9100};
  Ipv4Address m_bsAddress{"10.2.0.1"};
  uint16_t m_bsPort{9002};

  uint32_t m_rsuId{0};

  std::unordered_map<uint32_t, Address> m_vehicleAddress;

  std::string m_privateKeyPem;
  std::string m_publicKeyPem;
  std::vector<uint8_t> m_cert;
};

} // namespace ns3

#endif // RSU_APP_H
