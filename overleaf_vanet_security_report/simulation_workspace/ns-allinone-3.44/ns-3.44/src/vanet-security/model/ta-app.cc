#include "ta-app.h"

#include "ecc-crypto.h"
#include "vanet-message.h"

#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/inet-socket-address.h"
#include "ns3/socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/simulator.h"

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
                                        MakeStringChecker())
                          .AddAttribute("EnablePbc",
                                        "Enable PBC setup for TA.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&TaApp::m_enablePbc),
                                        MakeBooleanChecker())
                          .AddAttribute("PairingParams",
                                        "PBC pairing parameters (Type A).",
                                        StringValue(""),
                                        MakeStringAccessor(&TaApp::m_pairingParams),
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
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pairingParams.empty())
    {
      NS_FATAL_ERROR("TA EnablePbc is true but PairingParams is empty. Provide Type A params.");
    }
    if (!m_pbc.Init(m_pairingParams))
    {
      NS_FATAL_ERROR("TA PBC Init failed.");
    }
    if (!m_pbc.SetupTa())
    {
      NS_FATAL_ERROR("TA PBC SetupTa failed.");
    }
    m_pbcP = m_pbc.GetGeneratorBytes();
    m_pbcPpub = m_pbc.GetPpubBytes();
    m_pbcTpub = m_pbc.GetTpubBytes();
    NS_LOG_INFO("TA PBC setup complete. P=" << m_pbcP.size()
                                            << " bytes, Tpub=" << m_pbcTpub.size()
                                            << " bytes");
#else
    NS_FATAL_ERROR("TA EnablePbc requires VANET_SECURITY_ENABLE_PBC=ON at build time.");
#endif
  }

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
  m_rxBuffers.clear();
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
      if (header.GetType() != VanetMessageType::CERT_REQ)
      {
        continue;
      }

      NS_LOG_INFO("TA received CERT_REQ");

      size_t offset = 0;
      uint32_t nodeId = 0;
      uint16_t pubLen = 0;
      if (!ReadUint32(payload, offset, nodeId) || !ReadUint16(payload, offset, pubLen))
      {
        NS_LOG_WARN("TA failed to parse CERT_REQ");
        continue;
      }

      std::vector<uint8_t> pubBytes;
      if (!ReadBytes(payload, offset, pubLen, pubBytes))
      {
        NS_LOG_WARN("TA failed to read pubkey bytes");
        continue;
      }

      uint16_t pid1Len = 0;
      std::vector<uint8_t> pid1Bytes;
      if (offset < payload.size())
      {
        if (!ReadUint16(payload, offset, pid1Len) ||
            !ReadBytes(payload, offset, pid1Len, pid1Bytes))
        {
          NS_LOG_WARN("TA failed to read PID1 bytes");
          pid1Len = 0;
          pid1Bytes.clear();
        }
      }

      std::vector<uint8_t> toSign;
      WriteUint32(toSign, nodeId);
      WriteBytes(toSign, pubBytes);
      std::vector<uint8_t> cert = EccCrypto::Sign(m_privateKeyPem, toSign.data(), toSign.size());

      std::vector<uint8_t> pid2Bytes;
      uint64_t tiUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
      if (m_enablePbc && !pid1Bytes.empty())
      {
#ifdef VANET_SECURITY_USE_PBC
        if (!m_pbc.ComputePid2(nodeId, pid1Bytes, pid2Bytes))
        {
          NS_LOG_WARN("TA failed to compute PID2 for node " << nodeId);
          pid2Bytes.clear();
        }
        else
        {
          m_pseudoDb[nodeId] = {pid1Bytes, pid2Bytes, tiUs};
        }
#else
        NS_LOG_WARN("TA PBC disabled at build time; PID2 not computed.");
#endif
      }

      std::vector<uint8_t> respPayload;
      WriteUint16(respPayload, static_cast<uint16_t>(cert.size()));
      WriteBytes(respPayload, cert);
      WriteUint16(respPayload, static_cast<uint16_t>(pid2Bytes.size()));
      WriteBytes(respPayload, pid2Bytes);
      WriteUint64(respPayload, tiUs);

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
      NS_LOG_INFO("TA sent CERT_RESP for node " << nodeId);
    }

    packet = socket->RecvFrom(from);
  }
}

} // namespace ns3
