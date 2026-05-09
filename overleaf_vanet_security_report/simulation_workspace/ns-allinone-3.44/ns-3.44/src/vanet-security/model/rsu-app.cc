#include "rsu-app.h"

#include "vanet-message.h"
#include "vanet-stats.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("RsuApp");

RsuApp::RsuApp() = default;
RsuApp::~RsuApp() = default;

TypeId
RsuApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::RsuApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<RsuApp>()
                          .AddAttribute("VehiclePort",
                                        "UDP port for vehicle registration.",
                                        UintegerValue(9100),
                                        MakeUintegerAccessor(&RsuApp::m_vehiclePort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("BsAddress",
                                        "BS address.",
                                        Ipv4AddressValue("10.2.0.1"),
                                        MakeIpv4AddressAccessor(&RsuApp::m_bsAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("BsPort",
                                        "BS port.",
                                        UintegerValue(9002),
                                        MakeUintegerAccessor(&RsuApp::m_bsPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("RsuId",
                                        "RSU identifier.",
                                        UintegerValue(0),
                                        MakeUintegerAccessor(&RsuApp::m_rsuId),
                                        MakeUintegerChecker<uint32_t>());
  return tid;
}

void
RsuApp::StartApplication()
{
  if (!m_vehicleSocket)
  {
    m_vehicleSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_vehiclePort);
    if (m_vehicleSocket->Bind(local) != 0)
    {
      NS_LOG_ERROR("RSU bind failed");
      return;
    }
    m_vehicleSocket->SetRecvCallback(MakeCallback(&RsuApp::HandleVehicleRead, this));
  }

  if (!m_bsSocket)
  {
    m_bsSocket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_bsSocket->Connect(InetSocketAddress(m_bsAddress, m_bsPort));
    m_bsSocket->SetRecvCallback(MakeCallback(&RsuApp::HandleBsRead, this));
  }

  SendRegisterToBs(m_rsuId, {});
}

void
RsuApp::StopApplication()
{
  if (m_vehicleSocket)
  {
    m_vehicleSocket->Close();
    m_vehicleSocket = nullptr;
  }
  if (m_bsSocket)
  {
    m_bsSocket->Close();
    m_bsSocket = nullptr;
  }
  m_vehicleAddress.clear();
  m_bsRxBuffer.clear();
}

void
RsuApp::SendRegisterToBs(uint32_t nodeId, const std::vector<uint8_t>& payload)
{
  if (!m_bsSocket)
  {
    return;
  }

  VanetMessageHeader header;
  header.SetType(VanetMessageType::REGISTER_REQ);
  header.SetSenderId(nodeId);
  header.SetTargetId(nodeId);
  header.SetMessageId(0);
  header.SetTimestampUs(0);
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = payload.empty() ? Create<Packet>() : Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);
  m_bsSocket->Send(packet);
}

void
RsuApp::HandleVehicleRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    VanetMessageHeader header;
    packet->RemoveHeader(header);
    if (header.GetType() == VanetMessageType::REGISTER_REQ)
    {
      uint32_t vehicleId = header.GetSenderId();
      if (InetSocketAddress::IsMatchingType(from))
      {
        auto addr = InetSocketAddress::ConvertFrom(from);
        NS_LOG_INFO("RSU " << m_rsuId << " storing addr "
                           << addr.GetIpv4() << ":" << addr.GetPort()
                           << " for vehicle " << vehicleId);
      }
      m_vehicleAddress[vehicleId] = from;
      NS_LOG_INFO("RSU " << m_rsuId << " got REGISTER_REQ from vehicle " << vehicleId);
      std::vector<uint8_t> payload(packet->GetSize());
      if (!payload.empty())
      {
        packet->CopyData(payload.data(), payload.size());
      }
      SendRegisterToBs(vehicleId, payload);
    }
    else if (header.GetType() == VanetMessageType::V2I_PING)
    {
      NS_LOG_INFO("RSU " << m_rsuId << " got V2I_PING from vehicle " << header.GetSenderId());
      uint64_t sendUs = header.GetTimestampUs();
      double delay = Simulator::Now().GetSeconds() - (static_cast<double>(sendUs) / 1e6);
      VanetStats::RecordV2iUplinkDelay(delay);

      // Echo back with current timestamp and original ping time
      std::vector<uint8_t> payload;
      WriteUint64(payload, sendUs);

      VanetMessageHeader resp;
      resp.SetType(VanetMessageType::V2I_PONG);
      resp.SetSenderId(m_rsuId);
      resp.SetTargetId(header.GetSenderId());
      resp.SetMessageId(header.GetMessageId());
      resp.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
      resp.SetPayloadSize(payload.size());

      Ptr<Packet> respPacket = Create<Packet>(payload.data(), payload.size());
      respPacket->AddHeader(resp);
      socket->SendTo(respPacket, 0, from);
    }
    packet = socket->RecvFrom(from);
  }
}

void
RsuApp::HandleBsRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    std::vector<uint8_t> chunk(packet->GetSize());
    packet->CopyData(chunk.data(), chunk.size());
    m_bsRxBuffer.insert(m_bsRxBuffer.end(), chunk.begin(), chunk.end());

    VanetMessageHeader header;
    std::vector<uint8_t> payload;
    while (TryExtractMessage(m_bsRxBuffer, header, payload))
    {
      if (header.GetType() != VanetMessageType::REGISTER_RESP)
      {
        continue;
      }

      NS_LOG_INFO("RSU " << m_rsuId << " received REGISTER_RESP for vehicle " << header.GetTargetId());
      uint32_t targetId = header.GetTargetId();

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
        NS_LOG_WARN("RSU failed to parse REGISTER_RESP");
        continue;
      }

      if (targetId == m_rsuId)
      {
        m_publicKeyPem.assign(pubBytes.begin(), pubBytes.end());
        m_privateKeyPem.assign(privBytes.begin(), privBytes.end());
        m_cert = certBytes;
      }
      else
      {
        auto it = m_vehicleAddress.find(targetId);
        if (it != m_vehicleAddress.end())
        {
          if (InetSocketAddress::IsMatchingType(it->second))
          {
            auto addr = InetSocketAddress::ConvertFrom(it->second);
            NS_LOG_INFO("RSU " << m_rsuId << " sending REGISTER_RESP to vehicle "
                               << targetId << " at " << addr.GetIpv4() << ":" << addr.GetPort());
          }
          NS_LOG_INFO("RSU " << m_rsuId << " sending REGISTER_RESP to vehicle " << targetId);
          VanetMessageHeader respHeader;
          respHeader.SetType(VanetMessageType::REGISTER_RESP);
          respHeader.SetSenderId(m_rsuId);
          respHeader.SetTargetId(targetId);
          respHeader.SetMessageId(0);
          respHeader.SetTimestampUs(0);
          respHeader.SetPayloadSize(payload.size());

          Ptr<Packet> respPacket = Create<Packet>(payload.data(), payload.size());
          respPacket->AddHeader(respHeader);
          m_vehicleSocket->SendTo(respPacket, 0, it->second);
        }
        else
        {
          NS_LOG_WARN("RSU " << m_rsuId << " has no address for vehicle " << targetId);
        }
      }
    }

    packet = socket->RecvFrom(from);
  }
}

} // namespace ns3
