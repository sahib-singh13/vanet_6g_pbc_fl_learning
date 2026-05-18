#include "vehicle-app.h"

#include "ecc-crypto.h"
#include "vanet-message.h"
#include "vanet-power-model.h"
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

namespace {

constexpr uint64_t kSeenRetentionUs = 120000000;
constexpr size_t kMaxSeenMessages = 200000;

} // namespace

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
                          .AddAttribute("EnablePbc",
                                        "Enable PBC pseudonym generation.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&VehicleApp::m_enablePbc),
                                        MakeBooleanChecker())
                          .AddAttribute("PairingParams",
                                        "PBC pairing parameters (Type A).",
                                        StringValue(""),
                                        MakeStringAccessor(&VehicleApp::m_pairingParams),
                                        MakeStringChecker())
                          .AddAttribute("StateInfo",
                                        "Shared state information theta for PBC V2V signatures.",
                                        StringValue("traffic-alert"),
                                        MakeStringAccessor(&VehicleApp::m_stateInfo),
                                        MakeStringChecker())
                          .AddAttribute("PidValidityUs",
                                        "Validity window for the active PID in microseconds.",
                                        UintegerValue(30000000),
                                        MakeUintegerAccessor(&VehicleApp::m_pidValidityUs),
                                        MakeUintegerChecker<uint64_t>())
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

  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pairingParams.empty())
    {
      NS_FATAL_ERROR("Vehicle EnablePbc is true but PairingParams is empty.");
    }
    if (!m_pbc.Init(m_pairingParams))
    {
      NS_FATAL_ERROR("Vehicle PBC Init failed.");
    }
#else
    NS_FATAL_ERROR("Vehicle EnablePbc requires VANET_SECURITY_ENABLE_PBC=ON at build time.");
#endif
  }

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
  std::vector<uint8_t> payload;
  WriteUint32(payload, m_vehicleId);
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pid1.empty())
    {
      if (!m_pbc.GeneratePid1(m_pid1, m_pbcDi))
      {
        NS_LOG_WARN("Vehicle " << m_vehicleId << " failed to generate PID1");
      }
    }
#endif
    WriteUint16(payload, static_cast<uint16_t>(m_pid1.size()));
    WriteBytes(payload, m_pid1);
  }
  else
  {
    WriteUint16(payload, 0);
  }

  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet =
      payload.empty() ? Create<Packet>() : Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);
  m_lastRegisterSentUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
  Ipv4Address dest = m_broadcastRegister ? Ipv4Address("255.255.255.255") : m_rsuAddress;
  m_rsuSocket->SetAllowBroadcast(true);
  const uint64_t bytes = packet->GetSize();
  m_rsuSocket->SendTo(packet, 0, InetSocketAddress(dest, m_rsuPort));
  VanetPowerModel::RecordCommunication("register_req", "vehicle", "rsu", bytes);
  NS_LOG_INFO("Vehicle " << m_vehicleId << " sent REGISTER_REQ to " << dest);

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
  const uint64_t bytes = packet->GetSize();
  m_rsuSocket->SendTo(packet, 0, InetSocketAddress(m_rsuAddress, m_rsuPort));
  VanetPowerModel::RecordCommunication("v2i_ping", "vehicle", "rsu", bytes);

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
    if (!TryRemoveVanetMessageHeader(packet, header) ||
        header.GetPayloadSize() != packet->GetSize())
    {
      packet = socket->RecvFrom(from);
      continue;
    }

    if (header.GetType() == VanetMessageType::REGISTER_RESP)
    {
      NS_LOG_INFO("Vehicle " << m_vehicleId << " received REGISTER_RESP");
      if (m_lastRegisterSentUs > 0)
      {
        double delay = Simulator::Now().GetSeconds() -
                       (static_cast<double>(m_lastRegisterSentUs) / 1e6);
        VanetStats::RecordRegistrationDelay(delay);
        m_lastRegisterSentUs = 0;
      }
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

      uint16_t pid2Len = 0;
      std::vector<uint8_t> pid2Bytes;
      uint64_t tiUs = 0;
      uint16_t siLen = 0;
      std::vector<uint8_t> siBytes;
      if (offset < payload.size())
      {
        if (ReadUint16(payload, offset, pid2Len) &&
            ReadBytes(payload, offset, pid2Len, pid2Bytes) &&
            ReadUint64(payload, offset, tiUs) &&
            ReadUint16(payload, offset, siLen) &&
            ReadBytes(payload, offset, siLen, siBytes))
        {
          if (pid2Len > 0)
          {
            m_pid2 = pid2Bytes;
            m_pidTiUs = tiUs;
            NS_LOG_INFO("Vehicle " << m_vehicleId << " stored PID2 (" << m_pid2.size()
                                   << " bytes) Ti=" << m_pidTiUs);
          }
          if (siLen > 0)
          {
            m_partialKey = siBytes;
            NS_LOG_INFO("Vehicle " << m_vehicleId << " stored partial key (" << m_partialKey.size()
                                   << " bytes)");
#ifdef VANET_SECURITY_USE_PBC
            if (m_enablePbc)
            {
              if (!m_pbc.GenerateVerificationKey(m_secretXi, m_publicQi))
              {
                NS_LOG_WARN("Vehicle " << m_vehicleId
                                       << " failed to generate verification key Qi");
                m_secretXi.clear();
                m_publicQi.clear();
              }
              else
              {
                NS_LOG_INFO("Vehicle " << m_vehicleId << " generated Qi (" << m_publicQi.size()
                                       << " bytes)");
              }
            }
#endif
          }
        }
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
      NS_LOG_INFO("Vehicle " << m_vehicleId << " received V2I_PONG");
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
    else
    {
      NS_LOG_INFO("Vehicle " << m_vehicleId << " received unexpected type "
                             << static_cast<uint32_t>(header.GetType()));
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
    StripPacketTags(forwardPacket);

    if (m_enablePbc && m_useBsRelay)
    {
      Ptr<Packet> inspect = packet->Copy();
      VanetPbcAuthHeader auth;
      if (!TryRemoveVanetPbcAuthHeader(inspect, auth))
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }

      VanetMessageHeader header;
      if (!TryRemoveVanetMessageHeader(inspect, header) ||
          header.GetType() != VanetMessageType::V2V_PBC_DATA ||
          header.GetPayloadSize() != inspect->GetSize())
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }

      bool trustedRelay = false;
      if (InetSocketAddress::IsMatchingType(from))
      {
        trustedRelay = (InetSocketAddress::ConvertFrom(from).GetIpv4() == m_relayAddress);
      }
      if (!trustedRelay)
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }

      if (header.GetSenderId() == m_vehicleId)
      {
        packet = socket->RecvFrom(from);
        continue;
      }

      uint64_t msgKey = MakeVanetMessageKey(header.GetSenderId(), header.GetMessageId());
      const uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
      if (!MarkMessageSeen(msgKey, nowUs))
      {
        packet = socket->RecvFrom(from);
        continue;
      }

      double v2vDelay =
          Simulator::Now().GetSeconds() - (static_cast<double>(header.GetTimestampUs()) / 1e6);
      VanetStats::RecordV2vDelay(v2vDelay);

      if (!m_infected)
      {
        MarkInfected();
      }

      Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
      Time delay = MilliSeconds(jitter->GetValue(10.0, 50.0));
      Simulator::Schedule(delay, &VehicleApp::Rebroadcast, this, forwardPacket);
    }
    else
    {
      Ptr<Packet> inspect = packet->Copy();
      VanetAuthHeader auth;
      if (!TryRemoveVanetAuthHeader(inspect, auth))
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }

      std::vector<uint8_t> signedData;
      CopyPacketBytes(inspect, signedData);

      VanetMessageHeader header;
      if (!TryRemoveVanetMessageHeader(inspect, header) ||
          header.GetType() != VanetMessageType::V2V_DATA ||
          header.GetPayloadSize() != inspect->GetSize())
      {
        VanetStats::RecordVerificationFailure();
        packet = socket->RecvFrom(from);
        continue;
      }

      if (header.GetSenderId() == m_vehicleId)
      {
        packet = socket->RecvFrom(from);
        continue;
      }

      uint64_t msgKey = MakeVanetMessageKey(header.GetSenderId(), header.GetMessageId());
      const uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
      if (!MarkMessageSeen(msgKey, nowUs))
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
        bool certOk = false;
        {
          VanetPowerModel::ScopedTimer timer("ecc_verify", "vehicle");
          certOk = EccCrypto::Verify(
              m_taPublicKeyPem, certData.data(), certData.size(), auth.GetCertificate());
        }
        if (!certOk)
        {
          VanetStats::RecordVerificationFailure();
          packet = socket->RecvFrom(from);
          continue;
        }

        std::string pubPem(auth.GetPublicKey().begin(), auth.GetPublicKey().end());
        bool sigOk = false;
        {
          VanetPowerModel::ScopedTimer timer("ecc_verify", "vehicle");
          sigOk = EccCrypto::Verify(pubPem, signedData.data(), signedData.size(), auth.GetSignature());
        }
        if (!sigOk)
        {
          VanetStats::RecordVerificationFailure();
          packet = socket->RecvFrom(from);
          continue;
        }
      }

      double v2vDelay =
          Simulator::Now().GetSeconds() - (static_cast<double>(header.GetTimestampUs()) / 1e6);
      VanetStats::RecordV2vDelay(v2vDelay);

      if (!m_infected)
      {
        MarkInfected();
      }

      Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
      Time delay = MilliSeconds(jitter->GetValue(10.0, 50.0));
      Simulator::Schedule(delay, &VehicleApp::Rebroadcast, this, forwardPacket);
    }

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
  header.SetType((m_enablePbc && m_useBsRelay) ? VanetMessageType::V2V_PBC_DATA
                                               : VanetMessageType::V2V_DATA);
  header.SetSenderId(m_vehicleId);
  header.SetTargetId(0);
  header.SetMessageId(m_nextMessageId++);
  header.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);

  if (m_enablePbc && m_useBsRelay)
  {
#ifdef VANET_SECURITY_USE_PBC
    const uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
    if (m_pid1.empty() || m_pid2.empty() || m_partialKey.empty() || m_secretXi.empty() ||
        m_publicQi.empty())
    {
      NS_LOG_WARN("Vehicle " << m_vehicleId << " missing active PBC signing material");
      Simulator::Schedule(m_messageInterval, &VehicleApp::SendV2vMessage, this);
      return;
    }
    if (nowUs < m_pidTiUs || (nowUs - m_pidTiUs) > m_pidValidityUs)
    {
      NS_LOG_WARN("Vehicle " << m_vehicleId << " active PID expired; skipping PBC V2V send");
      Simulator::Schedule(m_messageInterval, &VehicleApp::SendV2vMessage, this);
      return;
    }

    std::vector<uint8_t> pidBytes;
    std::vector<uint8_t> thetaBytes(m_stateInfo.begin(), m_stateInfo.end());
    std::vector<uint8_t> wiBytes;
    std::vector<uint8_t> psiBytes;
    if (!m_pbc.EncodePid(m_pid1, m_pid2, m_pidTiUs, pidBytes) ||
        !m_pbc.SignMessage(m_partialKey,
                           m_secretXi,
                           pidBytes,
                           thetaBytes,
                           payload,
                           wiBytes,
                           psiBytes))
    {
      NS_LOG_WARN("Vehicle " << m_vehicleId << " failed to produce PBC signature");
      Simulator::Schedule(m_messageInterval, &VehicleApp::SendV2vMessage, this);
      return;
    }

    VanetPbcAuthHeader auth;
    auth.SetState(thetaBytes);
    auth.SetPid1(m_pid1);
    auth.SetPid2(m_pid2);
    auth.SetTimestampUs(m_pidTiUs);
    auth.SetQi(m_publicQi);
    auth.SetWi(wiBytes);
    auth.SetPsi(psiBytes);
    packet->AddHeader(auth);
#else
    Simulator::Schedule(m_messageInterval, &VehicleApp::SendV2vMessage, this);
    return;
#endif
  }
  else
  {
    std::vector<uint8_t> signData(packet->GetSize());
    packet->CopyData(signData.data(), signData.size());

    std::vector<uint8_t> signature;
    {
      VanetPowerModel::ScopedTimer timer("ecc_sign", "vehicle");
      signature = EccCrypto::Sign(m_privateKeyPem, signData.data(), signData.size());
    }
    VanetAuthHeader auth;
    std::vector<uint8_t> pubBytes(m_publicKeyPem.begin(), m_publicKeyPem.end());
    auth.SetPublicKey(pubBytes);
    auth.SetCertificate(m_cert);
    auth.SetSignature(signature);
    packet->AddHeader(auth);
  }

  InetSocketAddress dest =
      m_useBsRelay ? InetSocketAddress(m_relayAddress, m_relayPort)
                   : InetSocketAddress(Ipv4Address("255.255.255.255"), m_v2vPort);
  const uint64_t bytes = packet->GetSize();
  m_v2vSocket->SendTo(packet, 0, dest);
  VanetPowerModel::RecordCommunication(m_useBsRelay ? "v2v_relay_upload" : "v2v_broadcast",
                                       "vehicle",
                                       m_useBsRelay ? "bs_relay" : "vehicle",
                                       bytes);

  Simulator::Schedule(m_messageInterval, &VehicleApp::SendV2vMessage, this);
}

void
VehicleApp::Rebroadcast(Ptr<Packet> packet)
{
  if (!m_v2vSocket)
  {
    return;
  }
  Ptr<Packet> clean = packet->Copy();
  StripPacketTags(clean);
  InetSocketAddress dest =
      m_useBsRelay ? InetSocketAddress(m_relayAddress, m_relayPort)
                   : InetSocketAddress(Ipv4Address("255.255.255.255"), m_v2vPort);
  const uint64_t bytes = clean->GetSize();
  m_v2vSocket->SendTo(clean, 0, dest);
  VanetPowerModel::RecordCommunication(m_useBsRelay ? "v2v_relay_upload" : "v2v_broadcast",
                                       "vehicle",
                                       m_useBsRelay ? "bs_relay" : "vehicle",
                                       bytes);
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

bool
VehicleApp::MarkMessageSeen(uint64_t messageKey, uint64_t nowUs)
{
  if (++m_seenPruneCounter >= 1024 || m_seenMessages.size() > kMaxSeenMessages)
  {
    PruneSeenMessages(nowUs);
  }

  auto [it, inserted] = m_seenMessages.emplace(messageKey, nowUs);
  if (!inserted)
  {
    it->second = nowUs;
  }
  return inserted;
}

void
VehicleApp::PruneSeenMessages(uint64_t nowUs)
{
  m_seenPruneCounter = 0;
  for (auto it = m_seenMessages.begin(); it != m_seenMessages.end();)
  {
    if (nowUs >= it->second && (nowUs - it->second) > kSeenRetentionUs)
    {
      it = m_seenMessages.erase(it);
    }
    else
    {
      ++it;
    }
  }

  while (m_seenMessages.size() > kMaxSeenMessages / 2)
  {
    m_seenMessages.erase(m_seenMessages.begin());
  }
}

} // namespace ns3
