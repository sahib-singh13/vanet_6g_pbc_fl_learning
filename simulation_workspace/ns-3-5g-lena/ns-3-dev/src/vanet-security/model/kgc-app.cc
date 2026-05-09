#include "kgc-app.h"

#include "ecc-crypto.h"
#include "vanet-message.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("KgcApp");

KgcApp::KgcApp() = default;
KgcApp::~KgcApp() = default;

TypeId
KgcApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::KgcApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<KgcApp>()
                          .AddAttribute("Port",
                                        "TCP port for KGC requests.",
                                        UintegerValue(9001),
                                        MakeUintegerAccessor(&KgcApp::m_port),
                                        MakeUintegerChecker<uint16_t>());
  return tid;
}

void
KgcApp::StartApplication()
{
  if (!m_listenSocket)
  {
    m_listenSocket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
    if (m_listenSocket->Bind(local) != 0)
    {
      NS_LOG_ERROR("KGC bind failed");
      return;
    }
    m_listenSocket->Listen();
    m_listenSocket->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&KgcApp::HandleAccept, this));
  }
}

void
KgcApp::StopApplication()
{
  if (m_listenSocket)
  {
    m_listenSocket->Close();
    m_listenSocket = nullptr;
  }
}

void
KgcApp::HandleAccept(Ptr<Socket> socket, const Address& from)
{
  NS_LOG_INFO("KGC accepted connection");
  socket->SetRecvCallback(MakeCallback(&KgcApp::HandleRead, this));
}

void
KgcApp::HandleRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);

    if (header.GetType() != VanetMessageType::KEY_REQ)
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> payload(packet->GetSize());
    packet->CopyData(payload.data(), payload.size());

    size_t offset = 0;
    uint32_t nodeId = 0;
    if (!ReadUint32(payload, offset, nodeId))
    {
      NS_LOG_WARN("KGC failed to parse KEY_REQ");
      packet = socket->RecvFrom(from);
      continue;
    }

    auto keys = EccCrypto::GenerateKeyPair();
    std::vector<uint8_t> pubBytes(keys.publicPem.begin(), keys.publicPem.end());
    std::vector<uint8_t> privBytes(keys.privatePem.begin(), keys.privatePem.end());

    std::vector<uint8_t> respPayload;
    WriteUint16(respPayload, static_cast<uint16_t>(pubBytes.size()));
    WriteBytes(respPayload, pubBytes);
    WriteUint16(respPayload, static_cast<uint16_t>(privBytes.size()));
    WriteBytes(respPayload, privBytes);

    VanetMessageHeader resp;
    resp.SetType(VanetMessageType::KEY_RESP);
    resp.SetSenderId(0);
    resp.SetTargetId(nodeId);
    resp.SetMessageId(0);
    resp.SetTimestampUs(0);
    resp.SetPayloadSize(respPayload.size());

    Ptr<Packet> respPacket = Create<Packet>(respPayload.data(), respPayload.size());
    respPacket->AddHeader(resp);
    socket->Send(respPacket);

    packet = socket->RecvFrom(from);
  }
}

} // namespace ns3
