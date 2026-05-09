#ifndef KGC_APP_H
#define KGC_APP_H

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/type-id.h"

#ifdef VANET_SECURITY_USE_PBC
#include "pbc-crypto.h"
#endif

#include "ecc-crypto.h"

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace ns3 {

class KgcApp : public Application
{
public:
  KgcApp();
  ~KgcApp() override;

  static TypeId GetTypeId();
  std::vector<uint8_t> GetPpubBytes() const;

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleAccept(Ptr<Socket> socket, const Address& from);
  void HandleRead(Ptr<Socket> socket);

  Ptr<Socket> m_listenSocket;
  uint16_t m_port{9001};
  bool m_enablePbc{false};
  std::string m_pairingParams;
  std::vector<uint8_t> m_pbcP;
  std::vector<uint8_t> m_pbcPpub;
  std::vector<uint8_t> m_pbcTpub;
#ifdef VANET_SECURITY_USE_PBC
  PbcCrypto m_pbc;
#endif
  std::unordered_map<uint32_t, EccCrypto::KeyPair> m_keyCache;
  std::map<Ptr<Socket>, std::vector<uint8_t>> m_rxBuffers;
  uint64_t m_freshnessDeltaUs{2000000};
};

} // namespace ns3

#endif // KGC_APP_H
