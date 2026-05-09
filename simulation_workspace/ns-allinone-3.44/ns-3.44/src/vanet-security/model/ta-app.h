#ifndef TA_APP_H
#define TA_APP_H

#include "ns3/application.h"
#include "ns3/address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/type-id.h"

#ifdef VANET_SECURITY_USE_PBC
#include "pbc-crypto.h"
#endif

#include <string>
#include <map>
#include <unordered_map>
#include <vector>

namespace ns3 {

class TaApp : public Application
{
public:
  TaApp();
  ~TaApp() override;

  static TypeId GetTypeId();

  void SetPrivateKeyPem(const std::string& pem);
  void SetPublicKeyPem(const std::string& pem);
  const std::string& GetPublicKeyPem() const;

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleAccept(Ptr<Socket> socket, const Address& from);
  void HandleRead(Ptr<Socket> socket);
  void EnsureKeyPair();

  struct PseudoRecord
  {
    std::vector<uint8_t> pid1;
    std::vector<uint8_t> pid2;
    uint64_t tiUs{0};
  };

  Ptr<Socket> m_listenSocket;
  uint16_t m_port{9000};
  std::string m_privateKeyPem;
  std::string m_publicKeyPem;
  bool m_enablePbc{false};
  std::string m_pairingParams;
  std::vector<uint8_t> m_pbcP;
  std::vector<uint8_t> m_pbcPpub;
  std::vector<uint8_t> m_pbcTpub;
  std::unordered_map<uint32_t, PseudoRecord> m_pseudoDb;
  std::map<Ptr<Socket>, std::vector<uint8_t>> m_rxBuffers;
#ifdef VANET_SECURITY_USE_PBC
  PbcCrypto m_pbc;
#endif
};

} // namespace ns3

#endif // TA_APP_H
