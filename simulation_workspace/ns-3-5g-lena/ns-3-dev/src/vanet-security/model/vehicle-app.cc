#include "vehicle-app.h"

#include "ecc-crypto.h"
#include "vanet-message.h"
#include "vanet-stats.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/mobility-model.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/boolean.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/udp-socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("VehicleApp");

VehicleApp::VehicleApp() = default;
VehicleApp::~VehicleApp() = default;

TypeId
VehicleApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::VehicleApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<VehicleApp>()
                          .AddAttribute("RsuAddress",
                                        "RSU address for registration.",
                                        Ipv4AddressValue("10.1.0.1"),
                                        MakeIpv4AddressAccessor(&VehicleApp::m_rsuAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("RsuPort",
                                        "RSU port for registration.",
                                        UintegerValue(9100),
                                        MakeUintegerAccessor(&VehicleApp::m_rsuPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("V2vPort",
                                        "V2V broadcast port.",
                                        UintegerValue(9200),
                                        MakeUintegerAccessor(&VehicleApp::m_v2vPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("RelayAddress",
                                        "BS relay address for V2V over cellular.",
                                        Ipv4AddressValue("10.2.0.1"),
                                        MakeIpv4AddressAccessor(&VehicleApp::m_relayAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("RelayPort",
                                        "BS relay UDP port for V2V over cellular.",
                                        UintegerValue(9200),
                                        MakeUintegerAccessor(&VehicleApp::m_relayPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("MessageInterval",
                                        "Interval between source broadcasts.",
                                        TimeValue(Seconds(1.0)),
                                        MakeTimeAccessor(&VehicleApp::m_messageInterval),
                                        MakeTimeChecker())
                          .AddAttribute("V2iInterval",
                                        "Interval between V2I ping messages.",
                                        TimeValue(Seconds(1.0)),
                                        MakeTimeAccessor(&VehicleApp::m_v2iInterval),
                                        MakeTimeChecker())
                          .AddAttribute("RegistrationInterval",
                                        "Retry interval for RSU registration.",
                                        TimeValue(Seconds(2.0)),
                                        MakeTimeAccessor(&VehicleApp::m_registrationInterval),
                                        MakeTimeChecker())
                          .AddAttribute("VerifySignatures",
                                        "Enable ECDSA verification.",
                                        BooleanValue(true),
                                        MakeBooleanAccessor(&VehicleApp::m_verifySignatures),
                                        MakeBooleanChecker())
                          .AddAttribute("BroadcastRegister",
                                        "Send registration requests using broadcast.",
                                        BooleanValue(true),
                                        MakeBooleanAccessor(&VehicleApp::m_broadcastRegister),
                                        MakeBooleanChecker())
                          .AddAttribute("UseBsRelay",
                                        "Send V2V packets via BS relay instead of broadcast.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&VehicleApp::m_useBsRelay),
                                        MakeBooleanChecker())
                          .AddAttribute("TaPublicKeyPem",
                                        "TA public key PEM for cert verification.",
                                        StringValue(""),
                                        MakeStringAccessor(&VehicleApp::m_taPublicKeyPem),
                                        MakeStringChecker());
  return tid;
}

void
VehicleApp::StartApplication()
{
  m_vehicleId = GetNode()->GetId();

  if (!m_rsuSocket)
  {
    m_rsuSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_rsuSocket->Bind();
    m_rsuSocket->SetRecvCallback(MakeCallback(&VehicleApp::HandleRsuRead, this));
  }

  if (!m_v2vSocket)
  {
    m_v2vSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_v2vPort);
    m_v2vSocket->Bind(local);
    m_v2vSocket->SetAllowBroadcast(true);
    m_v2vSocket->SetRecvCallback(MakeCallback(&VehicleApp::HandleV2vRead, this));
  }

  Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
  Time delay = MilliSeconds(jitter->GetValue(0.0, 500.0));
  Simulator::Schedule(delay, &VehicleApp::SendRegisterRequest, this);
}

void
VehicleApp::StopApplication()
{
  if (m_rsuSocket)
  {
    m_rsuSocket->Close();
    m_rsuSocket = nullptr;
  }
  if (m_v2vSocket)
  {
    m_v2vSocket->Close();
    m_v2vSocket = nullptr;
  }
}

void
VehicleApp::SendRegisterRequest()
{
  if (!m_rsuSocket || m_hasCredentials)
  {
    return;
  }

  VanetMessageHeader header;
  header.SetType(VanetMessageType::REGISTER_REQ);
  header.SetSenderId(m_vehicleId);
  header.SetTargetId(m_vehicleId);
  header.SetMessageId(0);
  header.SetTimestampUs(0);
  header.SetPayloadSize(0);

  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(header);
  Ipv4Address dest = m_broadcastRegister ? Ipv4Address("255.255.255.255") : m_rsuAddress;
  m_rsuSocket->SetAllowBroadcast(true);
  m_rsuSocket->SendTo(packet, 0, InetSocketAddress(dest, m_rsuPort));

  Simulator::Schedule(m_registrationInterval, &VehicleApp::SendRegisterRequest, this);
}

void
VehicleApp::SendV2iPing()
{
  if (!m_hasCredentials || !m_rsuSocket)
  {
    return;
  }

  uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
  VanetMessageHeader header;
  header.SetType(VanetMessageType::V2I_PING);
  header.SetSenderId(m_vehicleId);
  header.SetTargetId(0);
  header.SetMessageId(m_nextV2iId++);
  header.SetTimestampUs(nowUs);
  header.SetPayloadSize(0);

  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(header);
  m_rsuSocket->SendTo(packet, 0, InetSocketAddress(m_rsuAddress, m_rsuPort));

  if (m_v2iInterval.GetSeconds() > 0.0)
  {
    Simulator::Schedule(m_v2iInterval, &VehicleApp::SendV2iPing, this);
  }
}

void
VehicleApp::HandleRsuRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);

    if (header.GetType() == VanetMessageType::REGISTER_RESP)
    {
      std::vector<uint8_t> payload(packet->GetSize());
      packet->CopyData(payload.data(), payload.size());
      size_t offset = 0;
      uint16_t pubLen = 0;
      uint16_t privLen = 0;
      uint16_t certLen = 0;
      std::vector<uint8_t> pubBytes;
      std::vector<uint8_t> privBytes;
      std::vector<uint8_t> certBytes;

      if (!ReadUint16(payload, offset, pubLen) || !ReadBytes(payload, offset, pubLen, pubBytes) ||
          !ReadUint16(payload, offset, privLen) || !ReadBytes(payload, offset, privLen, privBytes) ||
          !ReadUint16(payload, offset, certLen) || !ReadBytes(payload, offset, certLen, certBytes))
      {
        NS_LOG_WARN("Vehicle failed to parse REGISTER_RESP");
        packet = socket->RecvFrom(from);
        continue;
      }

      m_publicKeyPem.assign(pubBytes.begin(), pubBytes.end());
      m_privateKeyPem.assign(privBytes.begin(), privBytes.end());
      m_cert = certBytes;
      m_hasCredentials = true;

      if (m_vehicleId == 0 && !m_infected)
      {
        Ptr<MobilityModel> mobility = GetNode()->GetObject<MobilityModel>();
        if (mobility && !VanetStats::HasSource())
        {
          VanetStats::SetSourcePosition(mobility->GetPosition());
        }
        MarkInfected();
        Simulator::Schedule(Seconds(0.1), &VehicleApp::SendV2vMessage, this);
      }

      Simulator::Schedule(Seconds(0.2), &VehicleApp::SendV2iPing, this);
    }
    else if (header.GetType() == VanetMessageType::V2I_PONG)
    {
      uint64_t sendUs = header.GetTimestampUs();
      double downlink = Simulator::Now().GetSeconds() - (static_cast<double>(sendUs) / 1e6);
      VanetStats::RecordV2iDownlinkDelay(downlink);

      std::vector<uint8_t> payload(packet->GetSize());
      packet->CopyData(payload.data(), payload.size());
      size_t offset = 0;
      uint64_t origUs = 0;
      if (ReadUint64(payload, offset, origUs))
      {
        double rtt = Simulator::Now().GetSeconds() - (static_cast<double>(origUs) / 1e6);
        VanetStats::RecordV2iRtt(rtt);
      }
    }

    packet = socket->RecvFrom(from);
  }
}

void
VehicleApp::HandleV2vRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    Ptr<Packet> forwardPacket = packet->Copy();

    VanetAuthHeader auth;
    packet->RemoveHeader(auth);

    std::vector<uint8_t> signedData(packet->GetSize());
    packet->CopyData(signedData.data(), signedData.size());

    VanetMessageHeader header;
    packet->RemoveHeader(header);

    if (header.GetSenderId() == m_vehicleId)
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    uint64_t msgKey = (static_cast<uint64_t>(header.GetSenderId()) << 32) | header.GetMessageId();
    if (m_seenMessages.find(msgKey) != m_seenMessages.end())
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    if (m_verifySignatures)
    {
      if (m_taPublicKeyPem.empty())
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }
      std::vector<uint8_t> certData;
      WriteUint32(certData, header.GetSenderId());
      WriteBytes(certData, auth.GetPublicKey());
      if (!EccCrypto::Verify(m_taPublicKeyPem, certData.data(), certData.size(), auth.GetCertificate()))
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }

      std::string pubPem(auth.GetPublicKey().begin(), auth.GetPublicKey().end());
      if (!EccCrypto::Verify(pubPem, signedData.data(), signedData.size(), auth.GetSignature()))
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }
    }

    double v2vDelay = Simulator::Now().GetSeconds() - (static_cast<double>(header.GetTimestampUs()) / 1e6);
    VanetStats::RecordV2vDelay(v2vDelay);

    m_seenMessages.insert(msgKey);
    if (!m_infected)
    {
      MarkInfected();
    }

    Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
    Time delay = MilliSeconds(jitter->GetValue(10.0, 50.0));
    Simulator::Schedule(delay, &VehicleApp::Rebroadcast, this, forwardPacket);

    packet = socket->RecvFrom(from);
  }
}

void
VehicleApp::SendV2vMessage()
{
  if (!m_hasCredentials || !m_v2vSocket)
  {
    return;
  }

  std::vector<uint8_t> payload;
  WriteUint32(payload, m_nextMessageId);

  VanetMessageHeader header;
  header.SetType(VanetMessageType::V2V_DATA);
  header.SetSenderId(m_vehicleId);
  header.SetTargetId(0);
  header.SetMessageId(m_nextMessageId++);
  header.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);

  std::vector<uint8_t> signData(packet->GetSize());
  packet->CopyData(signData.data(), signData.size());

  std::vector<uint8_t> signature = EccCrypto::Sign(m_privateKeyPem, signData.data(), signData.size());
  VanetAuthHeader auth;
  std::vector<uint8_t> pubBytes(m_publicKeyPem.begin(), m_publicKeyPem.end());
  auth.SetPublicKey(pubBytes);
  auth.SetCertificate(m_cert);
  auth.SetSignature(signature);
  packet->AddHeader(auth);

  InetSocketAddress dest =
      m_useBsRelay ? InetSocketAddress(m_relayAddress, m_relayPort)
                   : InetSocketAddress(Ipv4Address("255.255.255.255"), m_v2vPort);
  m_v2vSocket->SendTo(packet, 0, dest);

  Simulator::Schedule(m_messageInterval, &VehicleApp::SendV2vMessage, this);
}

void
VehicleApp::Rebroadcast(Ptr<Packet> packet)
{
  if (!m_v2vSocket)
  {
    return;
  }
  InetSocketAddress dest =
      m_useBsRelay ? InetSocketAddress(m_relayAddress, m_relayPort)
                   : InetSocketAddress(Ipv4Address("255.255.255.255"), m_v2vPort);
  m_v2vSocket->SendTo(packet, 0, dest);
}

void
VehicleApp::MarkInfected()
{
  m_infected = true;
  Ptr<MobilityModel> mobility = GetNode()->GetObject<MobilityModel>();
  Vector pos(0.0, 0.0, 0.0);
  if (mobility)
  {
    pos = mobility->GetPosition();
  }
  VanetStats::MarkInfected(m_vehicleId, pos);
}

} // namespace ns3
