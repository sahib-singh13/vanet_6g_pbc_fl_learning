#include "bs-app.h"

#include "vanet-message.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/tcp-socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("BsApp");

BsApp::BsApp() = default;
BsApp::~BsApp() = default;

TypeId
BsApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::BsApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<BsApp>()
                          .AddAttribute("ListenPort",
                                        "TCP port for RSU connections.",
                                        UintegerValue(9002),
                                        MakeUintegerAccessor(&BsApp::m_listenPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("TaAddress",
                                        "TA IPv4 address.",
                                        Ipv4AddressValue("10.1.1.1"),
                                        MakeIpv4AddressAccessor(&BsApp::m_taAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("TaPort",
                                        "TA port.",
                                        UintegerValue(9000),
                                        MakeUintegerAccessor(&BsApp::m_taPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("KgcAddress",
                                        "KGC IPv4 address.",
                                        Ipv4AddressValue("10.1.1.2"),
                                        MakeIpv4AddressAccessor(&BsApp::m_kgcAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("KgcPort",
                                        "KGC port.",
                                        UintegerValue(9001),
                                        MakeUintegerAccessor(&BsApp::m_kgcPort),
                                        MakeUintegerChecker<uint16_t>());
  return tid;
}

void
BsApp::StartApplication()
{
  if (!m_listenSocket)
  {
    m_listenSocket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_listenPort);
    if (m_listenSocket->Bind(local) != 0)
    {
      NS_LOG_ERROR("BS bind failed");
      return;
    }
    m_listenSocket->Listen();
    m_listenSocket->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&BsApp::HandleAccept, this));
  }
}

void
BsApp::StopApplication()
{
  if (m_listenSocket)
  {
    m_listenSocket->Close();
    m_listenSocket = nullptr;
  }
  m_pendingRsu.clear();
}

void
BsApp::HandleAccept(Ptr<Socket> socket, const Address& from)
{
  NS_LOG_INFO("BS accepted connection");
  socket->SetRecvCallback(MakeCallback(&BsApp::HandleRead, this));
}

void
BsApp::HandleRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);

    if (header.GetType() != VanetMessageType::REGISTER_REQ)
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    uint32_t nodeId = header.GetSenderId();

    auto keyIt = m_keyCache.find(nodeId);
    auto certIt = m_certCache.find(nodeId);
    if (keyIt != m_keyCache.end() && certIt != m_certCache.end())
    {
      ReplyToRsu(nodeId);
      packet = socket->RecvFrom(from);
      continue;
    }

    m_pendingRsu[nodeId] = socket;
    RequestKeyFromKgc(nodeId);

    packet = socket->RecvFrom(from);
  }
}

void
BsApp::RequestKeyFromKgc(uint32_t nodeId)
{
  Ptr<Socket> socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  socket->Connect(InetSocketAddress(m_kgcAddress, m_kgcPort));
  m_pendingKgc[socket] = nodeId;
  socket->SetRecvCallback(MakeCallback(&BsApp::HandleKgcResponse, this));

  std::vector<uint8_t> payload;
  WriteUint32(payload, nodeId);

  VanetMessageHeader header;
  header.SetType(VanetMessageType::KEY_REQ);
  header.SetSenderId(0);
  header.SetTargetId(nodeId);
  header.SetMessageId(0);
  header.SetTimestampUs(0);
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);
  socket->Send(packet);
}

void
BsApp::HandleKgcResponse(Ptr<Socket> socket)
{
  auto it = m_pendingKgc.find(socket);
  if (it == m_pendingKgc.end())
  {
    return;
  }
  uint32_t nodeId = it->second;

  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);
    if (header.GetType() != VanetMessageType::KEY_RESP)
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> payload(packet->GetSize());
    packet->CopyData(payload.data(), payload.size());
    size_t offset = 0;
    uint16_t pubLen = 0;
    uint16_t privLen = 0;
    std::vector<uint8_t> pubBytes;
    std::vector<uint8_t> privBytes;

    if (!ReadUint16(payload, offset, pubLen) ||
        !ReadBytes(payload, offset, pubLen, pubBytes) ||
        !ReadUint16(payload, offset, privLen) ||
        !ReadBytes(payload, offset, privLen, privBytes))
    {
      NS_LOG_WARN("BS failed to parse KEY_RESP");
      packet = socket->RecvFrom(from);
      continue;
    }

    EccCrypto::KeyPair keys;
    keys.publicPem.assign(pubBytes.begin(), pubBytes.end());
    keys.privatePem.assign(privBytes.begin(), privBytes.end());
    m_keyCache[nodeId] = keys;

    RequestCertFromTa(nodeId, keys.publicPem);

    packet = socket->RecvFrom(from);
  }

  socket->Close();
  m_pendingKgc.erase(it);
}

void
BsApp::RequestCertFromTa(uint32_t nodeId, const std::string& publicPem)
{
  Ptr<Socket> socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  socket->Connect(InetSocketAddress(m_taAddress, m_taPort));
  m_pendingTa[socket] = nodeId;
  socket->SetRecvCallback(MakeCallback(&BsApp::HandleTaResponse, this));

  std::vector<uint8_t> payload;
  WriteUint32(payload, nodeId);
  std::vector<uint8_t> pubBytes(publicPem.begin(), publicPem.end());
  WriteUint16(payload, static_cast<uint16_t>(pubBytes.size()));
  WriteBytes(payload, pubBytes);

  VanetMessageHeader header;
  header.SetType(VanetMessageType::CERT_REQ);
  header.SetSenderId(0);
  header.SetTargetId(nodeId);
  header.SetMessageId(0);
  header.SetTimestampUs(0);
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);
  socket->Send(packet);
}

void
BsApp::HandleTaResponse(Ptr<Socket> socket)
{
  auto it = m_pendingTa.find(socket);
  if (it == m_pendingTa.end())
  {
    return;
  }
  uint32_t nodeId = it->second;

  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);
    if (header.GetType() != VanetMessageType::CERT_RESP)
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> payload(packet->GetSize());
    packet->CopyData(payload.data(), payload.size());
    size_t offset = 0;
    uint16_t certLen = 0;
    std::vector<uint8_t> certBytes;
    if (!ReadUint16(payload, offset, certLen) || !ReadBytes(payload, offset, certLen, certBytes))
    {
      NS_LOG_WARN("BS failed to parse CERT_RESP");
      packet = socket->RecvFrom(from);
      continue;
    }

    m_certCache[nodeId] = certBytes;
    ReplyToRsu(nodeId);

    packet = socket->RecvFrom(from);
  }
  socket->Close();
  m_pendingTa.erase(it);
}

void
BsApp::ReplyToRsu(uint32_t nodeId)
{
  auto pendingIt = m_pendingRsu.find(nodeId);
  if (pendingIt == m_pendingRsu.end())
  {
    return;
  }

  auto keyIt = m_keyCache.find(nodeId);
  auto certIt = m_certCache.find(nodeId);
  if (keyIt == m_keyCache.end() || certIt == m_certCache.end())
  {
    return;
  }

  const auto& keys = keyIt->second;
  std::vector<uint8_t> pubBytes(keys.publicPem.begin(), keys.publicPem.end());
  std::vector<uint8_t> privBytes(keys.privatePem.begin(), keys.privatePem.end());
  const auto& certBytes = certIt->second;

  std::vector<uint8_t> payload;
  WriteUint16(payload, static_cast<uint16_t>(pubBytes.size()));
  WriteBytes(payload, pubBytes);
  WriteUint16(payload, static_cast<uint16_t>(privBytes.size()));
  WriteBytes(payload, privBytes);
  WriteUint16(payload, static_cast<uint16_t>(certBytes.size()));
  WriteBytes(payload, certBytes);

  VanetMessageHeader resp;
  resp.SetType(VanetMessageType::REGISTER_RESP);
  resp.SetSenderId(0);
  resp.SetTargetId(nodeId);
  resp.SetMessageId(0);
  resp.SetTimestampUs(0);
  resp.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(resp);

  pendingIt->second->Send(packet);
  m_pendingRsu.erase(pendingIt);
}

} // namespace ns3
