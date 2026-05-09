#include "bs-app.h"

#include "vanet-message.h"
#include "vanet-power-model.h"
#include "vanet-stats.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
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
  m_kgcSentAt.clear();
  m_taSentAt.clear();
  m_pid1Cache.clear();
  m_pid2Cache.clear();
  m_tiCache.clear();
  m_siCache.clear();
  m_rxBuffers.clear();
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
  auto& rxBuffer = m_rxBuffers[socket];
  while (packet && packet->GetSize() > 0)
  {
    std::vector<uint8_t> chunk(packet->GetSize());
    packet->CopyData(chunk.data(), chunk.size());
    rxBuffer.insert(rxBuffer.end(), chunk.begin(), chunk.end());

    VanetMessageHeader header;
    std::vector<uint8_t> payload;
    while (TryExtractMessage(rxBuffer, header, payload))
    {
      if (header.GetType() != VanetMessageType::REGISTER_REQ)
      {
        continue;
      }

      uint32_t nodeId = header.GetSenderId();
      NS_LOG_INFO("BS got REGISTER_REQ for node " << nodeId);

      if (!payload.empty())
      {
        size_t offset = 0;
        uint32_t idPayload = 0;
        uint16_t pid1Len = 0;
        std::vector<uint8_t> pid1Bytes;
        if (ReadUint32(payload, offset, idPayload) &&
            ReadUint16(payload, offset, pid1Len) &&
            ReadBytes(payload, offset, pid1Len, pid1Bytes))
        {
          if (idPayload != nodeId)
          {
            NS_LOG_WARN("BS payload ID mismatch for node " << nodeId << " got " << idPayload);
          }
          if (pid1Len > 0)
          {
            m_pid1Cache[nodeId] = pid1Bytes;
          }
          else
          {
            m_pid1Cache.erase(nodeId);
          }
        }
      }

      auto keyIt = m_keyCache.find(nodeId);
      auto certIt = m_certCache.find(nodeId);
      if (keyIt != m_keyCache.end() && certIt != m_certCache.end())
      {
        ReplyToRsu(nodeId);
        continue;
      }

      m_pendingRsu[nodeId] = socket;
      RequestKeyFromKgc(nodeId);
    }

    packet = socket->RecvFrom(from);
  }
}

void
BsApp::RequestKeyFromKgc(uint32_t nodeId)
{
  NS_LOG_INFO("BS RequestKeyFromKgc for node " << nodeId);
  m_kgcSentAt[nodeId] = Simulator::Now();
  Ptr<Socket> socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  int conn = socket->Connect(InetSocketAddress(m_kgcAddress, m_kgcPort));
  if (conn != 0)
  {
    NS_LOG_WARN("BS failed to connect to KGC " << m_kgcAddress);
  }
  else
  {
    NS_LOG_INFO("BS connecting to KGC " << m_kgcAddress << " for node " << nodeId);
  }
  m_pendingKgc[socket] = nodeId;
  socket->SetRecvCallback(MakeCallback(&BsApp::HandleKgcResponse, this));

  std::vector<uint8_t> payload;
  WriteUint32(payload, nodeId);
  auto pid1It = m_pid1Cache.find(nodeId);
  auto pid2It = m_pid2Cache.find(nodeId);
  auto tiIt = m_tiCache.find(nodeId);
  if (pid1It != m_pid1Cache.end() && pid2It != m_pid2Cache.end() && tiIt != m_tiCache.end())
  {
    const auto& pid1Bytes = pid1It->second;
    const auto& pid2Bytes = pid2It->second;
    WriteUint16(payload, static_cast<uint16_t>(pid1Bytes.size()));
    WriteBytes(payload, pid1Bytes);
    WriteUint16(payload, static_cast<uint16_t>(pid2Bytes.size()));
    WriteBytes(payload, pid2Bytes);
    WriteUint64(payload, tiIt->second);
  }

  VanetMessageHeader header;
  header.SetType(VanetMessageType::KEY_REQ);
  header.SetSenderId(0);
  header.SetTargetId(nodeId);
  header.SetMessageId(0);
  header.SetTimestampUs(0);
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);
  const uint64_t bytes = packet->GetSize();
  socket->Send(packet);
  VanetPowerModel::RecordCommunication("key_req", "bs", "kgc", bytes);
  NS_LOG_INFO("BS sent KEY_REQ for node " << nodeId);
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
  auto& rxBuffer = m_rxBuffers[socket];
  bool processed = false;
  while (packet && packet->GetSize() > 0)
  {
    std::vector<uint8_t> chunk(packet->GetSize());
    packet->CopyData(chunk.data(), chunk.size());
    rxBuffer.insert(rxBuffer.end(), chunk.begin(), chunk.end());

    VanetMessageHeader header;
    std::vector<uint8_t> payload;
    while (TryExtractMessage(rxBuffer, header, payload))
    {
      if (header.GetType() != VanetMessageType::KEY_RESP)
      {
        continue;
      }
      processed = true;

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
        continue;
      }

      EccCrypto::KeyPair keys;
      keys.publicPem.assign(pubBytes.begin(), pubBytes.end());
      keys.privatePem.assign(privBytes.begin(), privBytes.end());
      m_keyCache[nodeId] = keys;

      uint16_t siLen = 0;
      std::vector<uint8_t> siBytes;
      if (offset < payload.size())
      {
        if (ReadUint16(payload, offset, siLen) &&
            ReadBytes(payload, offset, siLen, siBytes) &&
            siLen > 0)
        {
          m_siCache[nodeId] = siBytes;
        }
      }

      auto sentIt = m_kgcSentAt.find(nodeId);
      if (sentIt != m_kgcSentAt.end())
      {
        double rtt = Simulator::Now().GetSeconds() - sentIt->second.GetSeconds();
        VanetStats::RecordKgcRtt(rtt);
        m_kgcSentAt.erase(sentIt);
      }

      const bool needPbc = m_pid1Cache.find(nodeId) != m_pid1Cache.end();
      const bool haveCert = m_certCache.find(nodeId) != m_certCache.end();
      const bool havePid2 = m_pid2Cache.find(nodeId) != m_pid2Cache.end();
      const bool haveTi = m_tiCache.find(nodeId) != m_tiCache.end();
      const bool haveSi = m_siCache.find(nodeId) != m_siCache.end();

      if (!haveCert)
      {
        std::vector<uint8_t> pid1Bytes;
        auto pidIt = m_pid1Cache.find(nodeId);
        if (pidIt != m_pid1Cache.end())
        {
          pid1Bytes = pidIt->second;
        }
        RequestCertFromTa(nodeId, keys.publicPem, pid1Bytes);
      }
      else
      {
        if (!needPbc || (havePid2 && haveTi && haveSi))
        {
          ReplyToRsu(nodeId);
        }
      }
    }

    packet = socket->RecvFrom(from);
  }

  if (processed && rxBuffer.empty())
  {
    socket->Close();
    m_pendingKgc.erase(it);
    m_rxBuffers.erase(socket);
  }
}

void
BsApp::RequestCertFromTa(uint32_t nodeId,
                         const std::string& publicPem,
                         const std::vector<uint8_t>& pid1Bytes)
{
  NS_LOG_INFO("BS RequestCertFromTa for node " << nodeId);
  m_taSentAt[nodeId] = Simulator::Now();
  Ptr<Socket> socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  int conn = socket->Connect(InetSocketAddress(m_taAddress, m_taPort));
  if (conn != 0)
  {
    NS_LOG_WARN("BS failed to connect to TA " << m_taAddress);
  }
  else
  {
    NS_LOG_INFO("BS connecting to TA " << m_taAddress << " for node " << nodeId);
  }
  m_pendingTa[socket] = nodeId;
  socket->SetRecvCallback(MakeCallback(&BsApp::HandleTaResponse, this));

  std::vector<uint8_t> payload;
  WriteUint32(payload, nodeId);
  std::vector<uint8_t> pubBytes(publicPem.begin(), publicPem.end());
  WriteUint16(payload, static_cast<uint16_t>(pubBytes.size()));
  WriteBytes(payload, pubBytes);
  WriteUint16(payload, static_cast<uint16_t>(pid1Bytes.size()));
  WriteBytes(payload, pid1Bytes);

  VanetMessageHeader header;
  header.SetType(VanetMessageType::CERT_REQ);
  header.SetSenderId(0);
  header.SetTargetId(nodeId);
  header.SetMessageId(0);
  header.SetTimestampUs(0);
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);
  const uint64_t bytes = packet->GetSize();
  socket->Send(packet);
  VanetPowerModel::RecordCommunication("cert_req", "bs", "ta", bytes);
  NS_LOG_INFO("BS sent CERT_REQ for node " << nodeId);
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
  auto& rxBuffer = m_rxBuffers[socket];
  bool processed = false;
  while (packet && packet->GetSize() > 0)
  {
    std::vector<uint8_t> chunk(packet->GetSize());
    packet->CopyData(chunk.data(), chunk.size());
    rxBuffer.insert(rxBuffer.end(), chunk.begin(), chunk.end());

    VanetMessageHeader header;
    std::vector<uint8_t> payload;
    while (TryExtractMessage(rxBuffer, header, payload))
    {
      if (header.GetType() != VanetMessageType::CERT_RESP)
      {
        continue;
      }
      processed = true;

      size_t offset = 0;
      uint16_t certLen = 0;
      std::vector<uint8_t> certBytes;
      if (!ReadUint16(payload, offset, certLen) || !ReadBytes(payload, offset, certLen, certBytes))
      {
        NS_LOG_WARN("BS failed to parse CERT_RESP");
        continue;
      }

      m_certCache[nodeId] = certBytes;

      uint16_t pid2Len = 0;
      std::vector<uint8_t> pid2Bytes;
      uint64_t tiUs = 0;
      if (offset < payload.size())
      {
        if (ReadUint16(payload, offset, pid2Len) &&
            ReadBytes(payload, offset, pid2Len, pid2Bytes) &&
            pid2Len > 0)
        {
          m_pid2Cache[nodeId] = pid2Bytes;
        }
        if (ReadUint64(payload, offset, tiUs))
        {
          m_tiCache[nodeId] = tiUs;
        }
      }
      auto sentIt = m_taSentAt.find(nodeId);
      if (sentIt != m_taSentAt.end())
      {
        double rtt = Simulator::Now().GetSeconds() - sentIt->second.GetSeconds();
        VanetStats::RecordTaRtt(rtt);
        m_taSentAt.erase(sentIt);
      }

      const bool needPbc = m_pid1Cache.find(nodeId) != m_pid1Cache.end();
      const bool havePid2 = m_pid2Cache.find(nodeId) != m_pid2Cache.end();
      const bool haveTi = m_tiCache.find(nodeId) != m_tiCache.end();
      const bool haveSi = m_siCache.find(nodeId) != m_siCache.end();

      if (needPbc && havePid2 && haveTi && !haveSi)
      {
        RequestKeyFromKgc(nodeId);
      }

      if (!needPbc || haveSi)
      {
        ReplyToRsu(nodeId);
      }
    }

    packet = socket->RecvFrom(from);
  }
  if (processed && rxBuffer.empty())
  {
    socket->Close();
    m_pendingTa.erase(it);
    m_rxBuffers.erase(socket);
  }
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

  const bool needPbc = m_pid1Cache.find(nodeId) != m_pid1Cache.end();
  if (needPbc)
  {
    if (m_pid2Cache.find(nodeId) == m_pid2Cache.end() ||
        m_tiCache.find(nodeId) == m_tiCache.end() ||
        m_siCache.find(nodeId) == m_siCache.end())
    {
      return;
    }
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
  auto pid2It = m_pid2Cache.find(nodeId);
  if (pid2It != m_pid2Cache.end())
  {
    WriteUint16(payload, static_cast<uint16_t>(pid2It->second.size()));
    WriteBytes(payload, pid2It->second);
  }
  else
  {
    WriteUint16(payload, 0);
  }
  auto tiIt = m_tiCache.find(nodeId);
  WriteUint64(payload, tiIt != m_tiCache.end() ? tiIt->second : 0);
  auto siIt = m_siCache.find(nodeId);
  if (siIt != m_siCache.end())
  {
    WriteUint16(payload, static_cast<uint16_t>(siIt->second.size()));
    WriteBytes(payload, siIt->second);
  }
  else
  {
    WriteUint16(payload, 0);
  }

  VanetMessageHeader resp;
  resp.SetType(VanetMessageType::REGISTER_RESP);
  resp.SetSenderId(0);
  resp.SetTargetId(nodeId);
  resp.SetMessageId(0);
  resp.SetTimestampUs(0);
  resp.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(resp);

  const uint64_t bytes = packet->GetSize();
  pendingIt->second->Send(packet);
  VanetPowerModel::RecordCommunication("register_resp", "bs", "rsu", bytes);
  NS_LOG_INFO("BS sent REGISTER_RESP for node " << nodeId);
  m_pendingRsu.erase(pendingIt);
}

} // namespace ns3
