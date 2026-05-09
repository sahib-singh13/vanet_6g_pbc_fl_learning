#include "ta-app.h"

#include "ecc-crypto.h"
#include "vanet-message.h"

#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/inet-socket-address.h"
#include "ns3/socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("TaApp");

TaApp::TaApp() = default;
TaApp::~TaApp() = default;

TypeId
TaApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::TaApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<TaApp>()
                          .AddAttribute("Port",
                                        "TCP port for TA requests.",
                                        UintegerValue(9000),
                                        MakeUintegerAccessor(&TaApp::m_port),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PrivateKeyPem",
                                        "TA private key PEM.",
                                        StringValue(""),
                                        MakeStringAccessor(&TaApp::m_privateKeyPem),
                                        MakeStringChecker())
                          .AddAttribute("PublicKeyPem",
                                        "TA public key PEM.",
                                        StringValue(""),
                                        MakeStringAccessor(&TaApp::m_publicKeyPem),
                                        MakeStringChecker());
  return tid;
}

void
TaApp::SetPrivateKeyPem(const std::string& pem)
{
  m_privateKeyPem = pem;
}

void
TaApp::SetPublicKeyPem(const std::string& pem)
{
  m_publicKeyPem = pem;
}

const std::string&
TaApp::GetPublicKeyPem() const
{
  return m_publicKeyPem;
}

void
TaApp::StartApplication()
{
  EnsureKeyPair();

  if (!m_listenSocket)
  {
    m_listenSocket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
    if (m_listenSocket->Bind(local) != 0)
    {
      NS_LOG_ERROR("TA bind failed");
      return;
    }
    m_listenSocket->Listen();
    m_listenSocket->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&TaApp::HandleAccept, this));
  }
}

void
TaApp::StopApplication()
{
  if (m_listenSocket)
  {
    m_listenSocket->Close();
    m_listenSocket = nullptr;
  }
}

void
TaApp::EnsureKeyPair()
{
  if (!m_privateKeyPem.empty() && !m_publicKeyPem.empty())
  {
    return;
  }
  auto keys = EccCrypto::GenerateKeyPair();
  m_privateKeyPem = keys.privatePem;
  m_publicKeyPem = keys.publicPem;
}

void
TaApp::HandleAccept(Ptr<Socket> socket, const Address& from)
{
  NS_LOG_INFO("TA accepted connection");
  socket->SetRecvCallback(MakeCallback(&TaApp::HandleRead, this));
}

void
TaApp::HandleRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);

    if (header.GetType() != VanetMessageType::CERT_REQ)
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> payload(packet->GetSize());
    packet->CopyData(payload.data(), payload.size());

    size_t offset = 0;
    uint32_t nodeId = 0;
    uint16_t pubLen = 0;
    if (!ReadUint32(payload, offset, nodeId) || !ReadUint16(payload, offset, pubLen))
    {
      NS_LOG_WARN("TA failed to parse CERT_REQ");
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> pubBytes;
    if (!ReadBytes(payload, offset, pubLen, pubBytes))
    {
      NS_LOG_WARN("TA failed to read pubkey bytes");
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> toSign;
    WriteUint32(toSign, nodeId);
    WriteBytes(toSign, pubBytes);
    std::vector<uint8_t> cert = EccCrypto::Sign(m_privateKeyPem, toSign.data(), toSign.size());

    std::vector<uint8_t> respPayload;
    WriteUint16(respPayload, static_cast<uint16_t>(cert.size()));
    WriteBytes(respPayload, cert);

    VanetMessageHeader resp;
    resp.SetType(VanetMessageType::CERT_RESP);
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
