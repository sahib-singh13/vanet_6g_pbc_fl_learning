#ifndef BS_APP_H
#define BS_APP_H

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/type-id.h"
#include "ns3/ipv4-address.h"

#include "ecc-crypto.h"

#include <map>
#include <unordered_map>
#include <vector>

namespace ns3 {

class BsApp : public Application
{
public:
  BsApp();
  ~BsApp() override;

  static TypeId GetTypeId();

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleAccept(Ptr<Socket> socket, const Address& from);
  void HandleRead(Ptr<Socket> socket);

  void RequestKeyFromKgc(uint32_t nodeId);
  void HandleKgcResponse(Ptr<Socket> socket);

  void RequestCertFromTa(uint32_t nodeId, const std::string& publicPem);
  void HandleTaResponse(Ptr<Socket> socket);

  void ReplyToRsu(uint32_t nodeId);

  Ptr<Socket> m_listenSocket;
  uint16_t m_listenPort{9002};

  Ipv4Address m_taAddress{"10.1.1.1"};
  uint16_t m_taPort{9000};

  Ipv4Address m_kgcAddress{"10.1.1.2"};
  uint16_t m_kgcPort{9001};

  std::unordered_map<uint32_t, EccCrypto::KeyPair> m_keyCache;
  std::unordered_map<uint32_t, std::vector<uint8_t>> m_certCache;
  std::unordered_map<uint32_t, Ptr<Socket>> m_pendingRsu;
  std::map<Ptr<Socket>, uint32_t> m_pendingKgc;
  std::map<Ptr<Socket>, uint32_t> m_pendingTa;
};

} // namespace ns3

#endif // BS_APP_H
