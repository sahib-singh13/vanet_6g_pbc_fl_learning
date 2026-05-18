#include "bs-relay-app.h"

#include "vanet-message.h"
#include "vanet-power-model.h"
#include "vanet-stats.h"

#include "ns3/boolean.h"
#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("BsRelayApp");

BsRelayApp::BsRelayApp() = default;
BsRelayApp::~BsRelayApp() = default;

TypeId
BsRelayApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::BsRelayApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<BsRelayApp>()
                          .AddAttribute("ListenPort",
                                        "UDP port for V2V relay.",
                                        UintegerValue(9200),
                                        MakeUintegerAccessor(&BsRelayApp::m_port),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("EnablePbc",
                                        "Enable PBC aggregation and batch verification.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&BsRelayApp::m_enablePbc),
                                        MakeBooleanChecker())
                          .AddAttribute("PairingParams",
                                        "PBC pairing parameters (Type A).",
                                        StringValue(""),
                                        MakeStringAccessor(&BsRelayApp::m_pairingParams),
                                        MakeStringChecker())
                          .AddAttribute("AggregationWindowMs",
                                        "Aggregation window in milliseconds.",
                                        UintegerValue(50),
                                        MakeUintegerAccessor(&BsRelayApp::m_aggregationWindowMs),
                                        MakeUintegerChecker<uint64_t>())
                          .AddAttribute("MaxBatchSize",
                                        "Maximum signatures per aggregated batch.",
                                        UintegerValue(32),
                                        MakeUintegerAccessor(&BsRelayApp::m_maxBatchSize),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("PidValidityUs",
                                        "Validity window for the active PID in microseconds.",
                                        UintegerValue(30000000),
                                        MakeUintegerAccessor(&BsRelayApp::m_pidValidityUs),
                                        MakeUintegerChecker<uint64_t>());
  return tid;
}

void
BsRelayApp::SetUeAddresses(const std::vector<Ipv4Address>& addresses)
{
  m_ueAddresses = addresses;
}

void
BsRelayApp::SetPpubBytes(const std::vector<uint8_t>& ppubBytes)
{
  m_ppubBytes = ppubBytes;
#ifdef VANET_SECURITY_USE_PBC
  if (m_enablePbc && !m_ppubBytes.empty())
  {
    m_pbc.SetPpubBytes(m_ppubBytes);
  }
#endif
}

void
BsRelayApp::StartApplication()
{
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pairingParams.empty())
    {
      NS_FATAL_ERROR("BsRelayApp EnablePbc is true but PairingParams is empty.");
    }
    if (!m_pbc.Init(m_pairingParams))
    {
      NS_FATAL_ERROR("BsRelayApp PBC Init failed.");
    }
    if (!m_ppubBytes.empty() && !m_pbc.SetPpubBytes(m_ppubBytes))
    {
      NS_FATAL_ERROR("BsRelayApp failed to import Ppub bytes.");
    }
#else
    NS_FATAL_ERROR("BsRelayApp EnablePbc requires VANET_SECURITY_ENABLE_PBC=ON at build time.");
#endif
  }

  if (!m_socket)
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
    if (m_socket->Bind(local) != 0)
    {
      NS_LOG_ERROR("BS relay bind failed");
      return;
    }
    m_socket->SetRecvCallback(MakeCallback(&BsRelayApp::HandleRead, this));
  }
}

void
BsRelayApp::StopApplication()
{
  std::vector<std::string> batchKeys;
  batchKeys.reserve(m_batches.size());
  for (const auto& [batchKey, batch] : m_batches)
  {
    (void)batch;
    batchKeys.push_back(batchKey);
  }
  for (const auto& batchKey : batchKeys)
  {
    FlushBatch(batchKey);
  }

  if (m_socket)
  {
    m_socket->Close();
    m_socket = nullptr;
  }
}

void
BsRelayApp::HandleRead(Ptr<Socket> socket)
{
  if (m_ueAddresses.empty())
  {
    socket->Recv();
    return;
  }

  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    Ipv4Address srcAddr;
    if (InetSocketAddress::IsMatchingType(from))
    {
      srcAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
    }

    if (!m_enablePbc)
    {
      ForwardPacket(packet, srcAddr);
      packet = socket->RecvFrom(from);
      continue;
    }

#ifdef VANET_SECURITY_USE_PBC
    Ptr<Packet> inspect = packet->Copy();
    VanetPbcAuthHeader auth;
    inspect->RemoveHeader(auth);

    VanetMessageHeader header;
    inspect->RemoveHeader(header);
    if (header.GetType() != VanetMessageType::V2V_PBC_DATA)
    {
      ForwardPacket(packet, srcAddr);
      packet = socket->RecvFrom(from);
      continue;
    }
    const uint64_t msgKey =
        (static_cast<uint64_t>(header.GetSenderId()) << 32) | header.GetMessageId();
    if (m_seenMessages.find(msgKey) != m_seenMessages.end())
    {
      packet = socket->RecvFrom(from);
      continue;
    }
    m_seenMessages.insert(msgKey);

    const size_t g1Len = m_pbc.GetG1BytesLength();
    const uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
    if (auth.GetPid1().empty() || auth.GetPid2().size() != 4 || auth.GetQi().size() != g1Len ||
        auth.GetWi().size() != g1Len || auth.GetPsi().size() != g1Len ||
        auth.GetTimestampUs() > nowUs || (nowUs - auth.GetTimestampUs()) > m_pidValidityUs)
    {
      VanetStats::RecordVerificationFailure();
      packet = socket->RecvFrom(from);
      continue;
    }

    std::vector<uint8_t> messageBytes(inspect->GetSize());
    if (!messageBytes.empty())
    {
      inspect->CopyData(messageBytes.data(), messageBytes.size());
    }

    std::vector<uint8_t> pidBytes;
    if (!m_pbc.EncodePid(auth.GetPid1(), auth.GetPid2(), auth.GetTimestampUs(), pidBytes))
    {
      VanetStats::RecordVerificationFailure();
      packet = socket->RecvFrom(from);
      continue;
    }

    std::string batchKey(auth.GetState().begin(), auth.GetState().end());
    auto& batch = m_batches[batchKey];
    if (batch.entries.empty())
    {
      batch.flushEvent =
          Simulator::Schedule(MilliSeconds(m_aggregationWindowMs),
                              &BsRelayApp::FlushBatch,
                              this,
                              batchKey);
    }

    BatchEntry entry;
    entry.packet = packet->Copy();
    entry.packet->RemoveAllPacketTags();
    entry.packet->RemoveAllByteTags();
    entry.srcAddr = srcAddr;
    entry.stateBytes = auth.GetState();
    entry.pidBytes = pidBytes;
    entry.qiBytes = auth.GetQi();
    entry.wiBytes = auth.GetWi();
    entry.psiBytes = auth.GetPsi();
    entry.messageBytes = std::move(messageBytes);
    batch.entries.push_back(std::move(entry));

    if (batch.entries.size() >= m_maxBatchSize)
    {
      if (batch.flushEvent.IsPending())
      {
        batch.flushEvent.Cancel();
      }
      FlushBatch(batchKey);
    }
#endif
    packet = socket->RecvFrom(from);
  }
}

void
BsRelayApp::ForwardPacket(Ptr<Packet> packet, Ipv4Address srcAddr)
{
  if (!m_socket || !packet)
  {
    return;
  }

  for (const auto& dst : m_ueAddresses)
  {
    if (dst == srcAddr)
    {
      continue;
    }
    Ptr<Packet> copy = packet->Copy();
    copy->RemoveAllPacketTags();
    copy->RemoveAllByteTags();
    const uint64_t bytes = copy->GetSize();
    m_socket->SendTo(copy, 0, InetSocketAddress(dst, m_port));
    VanetPowerModel::RecordCommunication("v2v_relay_forward", "bs_relay", "vehicle", bytes);
  }
}

void
BsRelayApp::FlushBatch(const std::string& batchKey)
{
  auto it = m_batches.find(batchKey);
  if (it == m_batches.end())
  {
    return;
  }

  BatchState batch = std::move(it->second);
  m_batches.erase(it);
  if (batch.flushEvent.IsPending())
  {
    batch.flushEvent.Cancel();
  }
  if (batch.entries.empty())
  {
    return;
  }

  bool verified = true;
#ifdef VANET_SECURITY_USE_PBC
  std::vector<std::vector<uint8_t>> pidList;
  std::vector<std::vector<uint8_t>> qiList;
  std::vector<std::vector<uint8_t>> wiList;
  std::vector<std::vector<uint8_t>> psiList;
  std::vector<std::vector<uint8_t>> messageList;
  pidList.reserve(batch.entries.size());
  qiList.reserve(batch.entries.size());
  wiList.reserve(batch.entries.size());
  psiList.reserve(batch.entries.size());
  messageList.reserve(batch.entries.size());

  for (const auto& entry : batch.entries)
  {
    pidList.push_back(entry.pidBytes);
    qiList.push_back(entry.qiBytes);
    wiList.push_back(entry.wiBytes);
    psiList.push_back(entry.psiBytes);
    messageList.push_back(entry.messageBytes);
  }

  std::vector<uint8_t> aggregatePsiBytes;
  verified = m_pbc.AggregatePsi(psiList, aggregatePsiBytes) &&
             m_pbc.VerifyAggregate(pidList,
                                   qiList,
                                   wiList,
                                   messageList,
                                   batch.entries.front().stateBytes,
                                   aggregatePsiBytes);
#endif

  if (!verified)
  {
    for (size_t i = 0; i < batch.entries.size(); ++i)
    {
      VanetStats::RecordVerificationFailure();
    }
    return;
  }

  for (const auto& entry : batch.entries)
  {
    ForwardPacket(entry.packet, entry.srcAddr);
  }
}

} // namespace ns3
