#ifndef KGC_APP_H
#define KGC_APP_H

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/type-id.h"

namespace ns3 {

class KgcApp : public Application
{
public:
  KgcApp();
  ~KgcApp() override;

  static TypeId GetTypeId();

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleAccept(Ptr<Socket> socket, const Address& from);
  void HandleRead(Ptr<Socket> socket);

  Ptr<Socket> m_listenSocket;
  uint16_t m_port{9001};
};

} // namespace ns3

#endif // KGC_APP_H
