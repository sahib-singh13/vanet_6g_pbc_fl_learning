#ifndef BS_RELAY_APP_H
#define BS_RELAY_APP_H

#include "ns3/application.h"
#include "ns3/ipv4-address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"

#include <vector>

namespace ns3 {

class BsRelayApp : public Application
{
public:
  BsRelayApp();
  ~BsRelayApp() override;

  static TypeId GetTypeId();

  void SetUeAddresses(const std::vector<Ipv4Address>& addresses);

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleRead(Ptr<Socket> socket);

  Ptr<Socket> m_socket;
  uint16_t m_port{9200};
  std::vector<Ipv4Address> m_ueAddresses;
};

} // namespace ns3

#endif // BS_RELAY_APP_H
