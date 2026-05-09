#ifndef TA_APP_H
#define TA_APP_H

#include "ns3/application.h"
#include "ns3/address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/type-id.h"

#include <string>

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

  Ptr<Socket> m_listenSocket;
  uint16_t m_port{9000};
  std::string m_privateKeyPem;
  std::string m_publicKeyPem;
};

} // namespace ns3

#endif // TA_APP_H
