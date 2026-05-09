#include "kgc-app.h"

#include "ecc-crypto.h"
#include "vanet-message.h"
#include "vanet-power-model.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/boolean.h"
#include "ns3/simulator.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("KgcApp");

KgcApp::KgcApp() = default;
KgcApp::~KgcApp() = default;

std::vector<uint8_t>
KgcApp::GetPpubBytes() const
{
  return m_pbcPpub;
}

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
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("EnablePbc",
                                        "Enable PBC setup for KGC.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&KgcApp::m_enablePbc),
                                        MakeBooleanChecker())
                          .AddAttribute("FreshnessDeltaUs",
                                        "Freshness window (microseconds).",
                                        UintegerValue(2000000),
                                        MakeUintegerAccessor(&KgcApp::m_freshnessDeltaUs),
                                        MakeUintegerChecker<uint64_t>())
                          .AddAttribute("PairingParams",
                                        "PBC pairing parameters (Type A).",
                                        StringValue(""),
                                        MakeStringAccessor(&KgcApp::m_pairingParams),
                                        MakeStringChecker());
  return tid;
}

void
KgcApp::StartApplication()
{
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pairingParams.empty())
    {
      NS_FATAL_ERROR("KGC EnablePbc is true but PairingParams is empty. Provide Type A params.");
    }
    if (!m_pbc.Init(m_pairingParams))
    {
      NS_FATAL_ERROR("KGC PBC Init failed.");
    }
    if (!m_pbc.SetupKgc())
    {
      NS_FATAL_ERROR("KGC PBC SetupKgc failed.");
    }
    m_pbcP = m_pbc.GetGeneratorBytes();
    m_pbcPpub = m_pbc.GetPpubBytes();
    m_pbcTpub = m_pbc.GetTpubBytes();
    NS_LOG_INFO("KGC PBC setup complete. P=" << m_pbcP.size()
                                             << " bytes, Ppub=" << m_pbcPpub.size()
                                             << " bytes");
#else
    NS_FATAL_ERROR("KGC EnablePbc requires VANET_SECURITY_ENABLE_PBC=ON at build time.");
#endif
  }

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
  m_rxBuffers.clear();
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
      if (header.GetType() != VanetMessageType::KEY_REQ)
      {
        continue;
      }

      NS_LOG_INFO("KGC received KEY_REQ");

      size_t offset = 0;
      uint32_t nodeId = 0;
      if (!ReadUint32(payload, offset, nodeId))
      {
        NS_LOG_WARN("KGC failed to parse KEY_REQ");
        continue;
      }

      std::vector<uint8_t> pid1Bytes;
      std::vector<uint8_t> pid2Bytes;
      uint64_t tiUs = 0;
      uint16_t pid1Len = 0;
      uint16_t pid2Len = 0;
      if (offset < payload.size())
      {
        if (ReadUint16(payload, offset, pid1Len) &&
            ReadBytes(payload, offset, pid1Len, pid1Bytes) &&
            ReadUint16(payload, offset, pid2Len) &&
            ReadBytes(payload, offset, pid2Len, pid2Bytes) &&
            ReadUint64(payload, offset, tiUs))
        {
          // Parsed optional PID info.
        }
        else
        {
          pid1Bytes.clear();
          pid2Bytes.clear();
        }
      }

      auto keyIt = m_keyCache.find(nodeId);
      EccCrypto::KeyPair keys;
      if (keyIt != m_keyCache.end())
      {
        keys = keyIt->second;
      }
      else
      {
        {
          VanetPowerModel::ScopedTimer timer("ecc_keygen", "kgc");
          keys = EccCrypto::GenerateKeyPair();
        }
        m_keyCache[nodeId] = keys;
      }
      std::vector<uint8_t> pubBytes(keys.publicPem.begin(), keys.publicPem.end());
      std::vector<uint8_t> privBytes(keys.privatePem.begin(), keys.privatePem.end());

      std::vector<uint8_t> siBytes;
      if (!pid1Bytes.empty() && !pid2Bytes.empty())
      {
        uint64_t trUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
        if (trUs >= tiUs && (trUs - tiUs) <= m_freshnessDeltaUs)
        {
#ifdef VANET_SECURITY_USE_PBC
          if (!m_pbc.ComputePartialKey(pid1Bytes, pid2Bytes, tiUs, siBytes))
          {
            NS_LOG_WARN("KGC failed to compute partial key for node " << nodeId);
            siBytes.clear();
          }
#else
          NS_LOG_WARN("KGC PBC disabled at build time; partial key not computed.");
#endif
        }
        else
        {
          NS_LOG_WARN("KGC freshness check failed for node " << nodeId);
        }
      }

      std::vector<uint8_t> respPayload;
      WriteUint16(respPayload, static_cast<uint16_t>(pubBytes.size()));
      WriteBytes(respPayload, pubBytes);
      WriteUint16(respPayload, static_cast<uint16_t>(privBytes.size()));
      WriteBytes(respPayload, privBytes);
      WriteUint16(respPayload, static_cast<uint16_t>(siBytes.size()));
      WriteBytes(respPayload, siBytes);

      VanetMessageHeader resp;
      resp.SetType(VanetMessageType::KEY_RESP);
      resp.SetSenderId(0);
      resp.SetTargetId(nodeId);
      resp.SetMessageId(0);
      resp.SetTimestampUs(0);
      resp.SetPayloadSize(respPayload.size());

      Ptr<Packet> respPacket = Create<Packet>(respPayload.data(), respPayload.size());
      respPacket->AddHeader(resp);
      const uint64_t bytes = respPacket->GetSize();
      socket->Send(respPacket);
      VanetPowerModel::RecordCommunication("key_resp", "kgc", "bs", bytes);
      NS_LOG_INFO("KGC sent KEY_RESP for node " << nodeId);
    }

    packet = socket->RecvFrom(from);
  }
}

} // namespace ns3
