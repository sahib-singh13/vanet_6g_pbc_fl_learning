#include "fl-vanet-apps.h"

#include "ecc-crypto.h"
#include "vanet-message.h"
#include "vanet-power-model.h"
#include "vanet-stats.h"

#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/udp-socket-factory.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <numeric>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("FlVanetApps");

namespace {

void
WriteDouble(std::vector<uint8_t>& buffer, double value)
{
  uint64_t raw = 0;
  static_assert(sizeof(raw) == sizeof(value), "double must be 64-bit");
  std::memcpy(&raw, &value, sizeof(value));
  WriteUint64(buffer, raw);
}

bool
ReadDouble(const std::vector<uint8_t>& buffer, size_t& offset, double& value)
{
  uint64_t raw = 0;
  if (!ReadUint64(buffer, offset, raw))
  {
    return false;
  }
  std::memcpy(&value, &raw, sizeof(value));
  return true;
}

void
WriteVector(std::vector<uint8_t>& buffer, const std::vector<double>& values)
{
  WriteUint32(buffer, static_cast<uint32_t>(values.size()));
  for (double value : values)
  {
    WriteDouble(buffer, value);
  }
}

bool
ReadVector(const std::vector<uint8_t>& buffer, size_t& offset, std::vector<double>& values)
{
  uint32_t dim = 0;
  if (!ReadUint32(buffer, offset, dim))
  {
    return false;
  }
  if (dim > 100000)
  {
    return false;
  }
  values.assign(dim, 0.0);
  for (double& value : values)
  {
    if (!ReadDouble(buffer, offset, value))
    {
      return false;
    }
  }
  return true;
}

std::vector<uint8_t>
StateBytesForRound(const std::string& prefix, uint32_t round)
{
  std::string state = prefix + "-" + std::to_string(round);
  return std::vector<uint8_t>(state.begin(), state.end());
}

uint64_t
Mix64(uint64_t x)
{
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

double
PairMaskValue(uint32_t round, uint32_t dim, uint32_t lowId, uint32_t highId)
{
  uint64_t seed = static_cast<uint64_t>(round + 1) * 0x9e3779b97f4a7c15ULL;
  seed ^= static_cast<uint64_t>(dim + 17) * 0xbf58476d1ce4e5b9ULL;
  seed ^= static_cast<uint64_t>(lowId + 31) << 32;
  seed ^= static_cast<uint64_t>(highId + 47);
  uint64_t mixed = Mix64(seed);
  int64_t centered = static_cast<int64_t>(mixed % 2001ULL) - 1000;
  return static_cast<double>(centered) * 1e-6;
}

double
SyntheticGradient(uint32_t vehicleId, uint32_t round, uint32_t dim)
{
  const double idTerm = static_cast<double>((vehicleId % 17) + 1);
  const double dimTerm = static_cast<double>((dim % 23) + 1);
  const double roundTerm = static_cast<double>((round % 11) + 1);
  return 0.0001 * idTerm * dimTerm * roundTerm;
}

} // namespace

FlVehicleApp::FlVehicleApp() = default;
FlVehicleApp::~FlVehicleApp() = default;

TypeId
FlVehicleApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::FlVehicleApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<FlVehicleApp>()
                          .AddAttribute("ListenPort",
                                        "UDP port for FL model downloads.",
                                        UintegerValue(9402),
                                        MakeUintegerAccessor(&FlVehicleApp::m_listenPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("RsuAddress",
                                        "Serving FL RSU address.",
                                        Ipv4AddressValue("10.2.0.2"),
                                        MakeIpv4AddressAccessor(&FlVehicleApp::m_rsuAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("RsuPort",
                                        "Serving FL RSU port.",
                                        UintegerValue(9401),
                                        MakeUintegerAccessor(&FlVehicleApp::m_rsuPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("VehicleId",
                                        "Vehicle identifier used in FL payloads.",
                                        UintegerValue(0),
                                        MakeUintegerAccessor(&FlVehicleApp::m_vehicleId),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("DatasetSize",
                                        "Local dataset size |D_i|.",
                                        UintegerValue(1000),
                                        MakeUintegerAccessor(&FlVehicleApp::m_datasetSize),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("ModelDim",
                                        "Number of model-vector parameters.",
                                        UintegerValue(64),
                                        MakeUintegerAccessor(&FlVehicleApp::m_modelDim),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("LocalEpochs",
                                        "Number of synthetic local epochs per FL round.",
                                        UintegerValue(1),
                                        MakeUintegerAccessor(&FlVehicleApp::m_localEpochs),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("LearningRate",
                                        "Synthetic FL learning rate eta.",
                                        DoubleValue(0.01),
                                        MakeDoubleAccessor(&FlVehicleApp::m_learningRate),
                                        MakeDoubleChecker<double>())
                          .AddAttribute("EnablePbc",
                                        "Use PBC signatures for FL updates.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&FlVehicleApp::m_enablePbc),
                                        MakeBooleanChecker())
                          .AddAttribute("EnableMasking",
                                        "Enable deterministic pairwise secure-aggregation masks.",
                                        BooleanValue(true),
                                        MakeBooleanAccessor(&FlVehicleApp::m_enableMasking),
                                        MakeBooleanChecker())
                          .AddAttribute("SecurityMode",
                                        "FL security mode label: pbc or ecc.",
                                        StringValue("pbc"),
                                        MakeStringAccessor(&FlVehicleApp::m_securityMode),
                                        MakeStringChecker())
                          .AddAttribute("PairingParams",
                                        "PBC pairing parameters.",
                                        StringValue(""),
                                        MakeStringAccessor(&FlVehicleApp::m_pairingParams),
                                        MakeStringChecker())
                          .AddAttribute("StatePrefix",
                                        "PBC theta prefix for FL rounds.",
                                        StringValue("fl-round"),
                                        MakeStringAccessor(&FlVehicleApp::m_statePrefix),
                                        MakeStringChecker())
                          .AddAttribute("PidValidityUs",
                                        "FL PID validity window in microseconds.",
                                        UintegerValue(300000000),
                                        MakeUintegerAccessor(&FlVehicleApp::m_pidValidityUs),
                                        MakeUintegerChecker<uint64_t>());
  return tid;
}

void
FlVehicleApp::SetGroupInfo(const std::vector<uint32_t>& vehicleIds,
                           const std::vector<uint32_t>& datasetSizes)
{
  m_groupVehicleIds = vehicleIds;
  m_groupDatasetSizes = datasetSizes;
}

void
FlVehicleApp::SetEccKeys(const std::string& publicKeyPem, const std::string& privateKeyPem)
{
  m_publicKeyPem = publicKeyPem;
  m_privateKeyPem = privateKeyPem;
}

void
FlVehicleApp::SetPbcCredentials(const std::vector<uint8_t>& pid1,
                                const std::vector<uint8_t>& pid2,
                                uint64_t tiUs,
                                const std::vector<uint8_t>& partialKey,
                                const std::vector<uint8_t>& secretXi,
                                const std::vector<uint8_t>& publicQi)
{
  m_pid1 = pid1;
  m_pid2 = pid2;
  m_pidTiUs = tiUs;
  m_partialKey = partialKey;
  m_secretXi = secretXi;
  m_publicQi = publicQi;
}

void
FlVehicleApp::StartApplication()
{
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pairingParams.empty() || !m_pbc.Init(m_pairingParams))
    {
      NS_FATAL_ERROR("FlVehicleApp PBC initialization failed.");
    }
#else
    NS_FATAL_ERROR("FlVehicleApp EnablePbc requires VANET_SECURITY_ENABLE_PBC=ON.");
#endif
  }
  else if (m_privateKeyPem.empty())
  {
    auto keys = EccCrypto::GenerateKeyPair();
    m_publicKeyPem = keys.publicPem;
    m_privateKeyPem = keys.privatePem;
  }

  if (!m_socket)
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    if (m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_listenPort)) != 0)
    {
      NS_LOG_ERROR("FL vehicle bind failed");
      return;
    }
    m_socket->SetRecvCallback(MakeCallback(&FlVehicleApp::HandleRead, this));
  }
}

void
FlVehicleApp::StopApplication()
{
  if (m_socket)
  {
    m_socket->Close();
    m_socket = nullptr;
  }
}

void
FlVehicleApp::HandleRead(Ptr<Socket> socket)
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
    if (header.GetType() == VanetMessageType::FL_MODEL_DOWNLOAD ||
        header.GetType() == VanetMessageType::FL_GLOBAL_MODEL ||
        header.GetType() == VanetMessageType::FL_ROUND_START)
    {
      std::vector<uint8_t> payload(packet->GetSize());
      if (!payload.empty())
      {
        packet->CopyData(payload.data(), payload.size());
      }
      HandleModelPayload(payload);
    }
    packet = socket->RecvFrom(from);
  }
}

void
FlVehicleApp::HandleModelPayload(const std::vector<uint8_t>& payload)
{
  size_t offset = 0;
  uint32_t round = 0;
  std::vector<double> globalModel;
  if (!ReadUint32(payload, offset, round) || !ReadVector(payload, offset, globalModel))
  {
    NS_LOG_WARN("FL vehicle " << m_vehicleId << " failed to parse model payload");
    return;
  }
  if (globalModel.empty())
  {
    return;
  }
  m_modelDim = static_cast<uint32_t>(globalModel.size());
  std::vector<double> update = TrainLocalModel(round, globalModel);
  std::vector<double> mask = BuildMask(round, static_cast<uint32_t>(update.size()));
  if (mask.size() == update.size())
  {
    VanetPowerModel::ScopedTimer timer("fl_mask_generate", "vehicle");
    for (size_t i = 0; i < update.size(); ++i)
    {
      update[i] += mask[i];
    }
  }
  SendUpdate(round, update);
}

std::vector<double>
FlVehicleApp::TrainLocalModel(uint32_t round, const std::vector<double>& globalModel)
{
  VanetPowerModel::ScopedTimer timer("fl_local_train", "vehicle");
  std::vector<double> local = globalModel;
  for (uint32_t epoch = 0; epoch < std::max(1u, m_localEpochs); ++epoch)
  {
    for (uint32_t dim = 0; dim < local.size(); ++dim)
    {
      local[dim] -= m_learningRate * SyntheticGradient(m_vehicleId, round + epoch, dim);
    }
  }
  return local;
}

std::vector<double>
FlVehicleApp::BuildMask(uint32_t round, uint32_t dim) const
{
  std::vector<double> mask(dim, 0.0);
  if (!m_enableMasking || m_groupVehicleIds.empty() || m_groupVehicleIds.size() != m_groupDatasetSizes.size())
  {
    return mask;
  }

  uint32_t totalDataset = std::accumulate(m_groupDatasetSizes.begin(), m_groupDatasetSizes.end(), 0u);
  if (totalDataset == 0 || m_datasetSize == 0)
  {
    return mask;
  }
  const double ownWeight = static_cast<double>(m_datasetSize) / static_cast<double>(totalDataset);
  if (ownWeight <= 0.0)
  {
    return mask;
  }

  for (uint32_t otherId : m_groupVehicleIds)
  {
    if (otherId == m_vehicleId)
    {
      continue;
    }
    uint32_t low = std::min(m_vehicleId, otherId);
    uint32_t high = std::max(m_vehicleId, otherId);
    const double sign = (m_vehicleId < otherId) ? 1.0 : -1.0;
    for (uint32_t d = 0; d < dim; ++d)
    {
      mask[d] += sign * PairMaskValue(round, d, low, high) / ownWeight;
    }
  }
  return mask;
}

void
FlVehicleApp::SendUpdate(uint32_t round, const std::vector<double>& update)
{
  if (!m_socket)
  {
    return;
  }

  std::vector<uint8_t> payload;
  WriteUint32(payload, round);
  WriteUint32(payload, m_vehicleId);
  WriteUint32(payload, m_datasetSize);
  WriteVector(payload, update);

  VanetMessageHeader header;
  header.SetType(VanetMessageType::FL_UPDATE_UPLOAD);
  header.SetSenderId(m_vehicleId);
  header.SetTargetId(0);
  header.SetMessageId(round);
  header.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
  header.SetPayloadSize(payload.size());

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  packet->AddHeader(header);

  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    const uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
    if (m_pid1.empty() || m_pid2.empty() || m_partialKey.empty() || m_secretXi.empty() ||
        m_publicQi.empty() || nowUs < m_pidTiUs || (nowUs - m_pidTiUs) > m_pidValidityUs)
    {
      NS_LOG_WARN("FL vehicle " << m_vehicleId << " missing/expired PBC material");
      return;
    }
    std::vector<uint8_t> pidBytes;
    std::vector<uint8_t> thetaBytes = StateBytesForRound(m_statePrefix, round);
    std::vector<uint8_t> wiBytes;
    std::vector<uint8_t> psiBytes;
    if (!m_pbc.EncodePid(m_pid1, m_pid2, m_pidTiUs, pidBytes) ||
        !m_pbc.SignMessage(m_partialKey, m_secretXi, pidBytes, thetaBytes, payload, wiBytes, psiBytes))
    {
      NS_LOG_WARN("FL vehicle " << m_vehicleId << " failed to sign PBC update");
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
    auth.SetPublicKey(std::vector<uint8_t>(m_publicKeyPem.begin(), m_publicKeyPem.end()));
    auth.SetSignature(signature);
    packet->AddHeader(auth);
  }

  const uint64_t bytes = packet->GetSize();
  m_socket->SendTo(packet, 0, InetSocketAddress(m_rsuAddress, m_rsuPort));
  VanetPowerModel::RecordCommunication("fl_update_upload", "vehicle", "rsu", bytes);
}

FlRsuAggregatorApp::FlRsuAggregatorApp() = default;
FlRsuAggregatorApp::~FlRsuAggregatorApp() = default;

TypeId
FlRsuAggregatorApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::FlRsuAggregatorApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<FlRsuAggregatorApp>()
                          .AddAttribute("ListenPort",
                                        "UDP port for FL RSU ingress.",
                                        UintegerValue(9401),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_listenPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("BsAddress",
                                        "FL BS aggregator address.",
                                        Ipv4AddressValue("10.2.0.1"),
                                        MakeIpv4AddressAccessor(&FlRsuAggregatorApp::m_bsAddress),
                                        MakeIpv4AddressChecker())
                          .AddAttribute("BsPort",
                                        "FL BS aggregator port.",
                                        UintegerValue(9400),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_bsPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("VehiclePort",
                                        "FL vehicle model-download port.",
                                        UintegerValue(9402),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_vehiclePort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("RsuId",
                                        "FL RSU identifier.",
                                        UintegerValue(0),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_rsuId),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("ExpectedUpdates",
                                        "Number of vehicle updates expected per round.",
                                        UintegerValue(0),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_expectedUpdates),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("FlushTimeout",
                                        "Maximum wait for expected FL updates before partial aggregation is allowed. Zero keeps strict all-update aggregation.",
                                        TimeValue(Seconds(0.0)),
                                        MakeTimeAccessor(&FlRsuAggregatorApp::m_flushTimeout),
                                        MakeTimeChecker())
                          .AddAttribute("MinFlushFraction",
                                        "Minimum fraction of expected updates required for timeout-based partial aggregation.",
                                        DoubleValue(1.0),
                                        MakeDoubleAccessor(&FlRsuAggregatorApp::m_minFlushFraction),
                                        MakeDoubleChecker<double>(0.0, 1.0))
                          .AddAttribute("ModelDim",
                                        "Number of model-vector parameters.",
                                        UintegerValue(64),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_modelDim),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("EnablePbc",
                                        "Verify PBC aggregate signatures for FL updates.",
                                        BooleanValue(false),
                                        MakeBooleanAccessor(&FlRsuAggregatorApp::m_enablePbc),
                                        MakeBooleanChecker())
                          .AddAttribute("SecurityMode",
                                        "FL security mode label.",
                                        StringValue("pbc"),
                                        MakeStringAccessor(&FlRsuAggregatorApp::m_securityMode),
                                        MakeStringChecker())
                          .AddAttribute("PairingParams",
                                        "PBC pairing parameters.",
                                        StringValue(""),
                                        MakeStringAccessor(&FlRsuAggregatorApp::m_pairingParams),
                                        MakeStringChecker())
                          .AddAttribute("PidValidityUs",
                                        "FL PID validity window in microseconds.",
                                        UintegerValue(300000000),
                                        MakeUintegerAccessor(&FlRsuAggregatorApp::m_pidValidityUs),
                                        MakeUintegerChecker<uint64_t>());
  return tid;
}

void
FlRsuAggregatorApp::SetVehicleAddresses(const std::vector<Ipv4Address>& addresses)
{
  m_vehicleAddresses = addresses;
}

void
FlRsuAggregatorApp::SetPpubBytes(const std::vector<uint8_t>& ppubBytes)
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
FlRsuAggregatorApp::StartApplication()
{
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    if (m_pairingParams.empty() || !m_pbc.Init(m_pairingParams))
    {
      NS_FATAL_ERROR("FlRsuAggregatorApp PBC initialization failed.");
    }
    if (!m_ppubBytes.empty() && !m_pbc.SetPpubBytes(m_ppubBytes))
    {
      NS_FATAL_ERROR("FlRsuAggregatorApp failed to import Ppub.");
    }
#else
    NS_FATAL_ERROR("FlRsuAggregatorApp EnablePbc requires VANET_SECURITY_ENABLE_PBC=ON.");
#endif
  }

  if (!m_socket)
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    if (m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_listenPort)) != 0)
    {
      NS_LOG_ERROR("FL RSU bind failed");
      return;
    }
    m_socket->SetRecvCallback(MakeCallback(&FlRsuAggregatorApp::HandleRead, this));
  }
}

void
FlRsuAggregatorApp::StopApplication()
{
  if (m_socket)
  {
    m_socket->Close();
    m_socket = nullptr;
  }
  for (auto& item : m_rounds)
  {
    if (item.second.flushEvent.IsRunning())
    {
      item.second.flushEvent.Cancel();
    }
  }
  m_rounds.clear();
}

void
FlRsuAggregatorApp::HandleRead(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    Ipv4Address src;
    if (InetSocketAddress::IsMatchingType(from))
    {
      src = InetSocketAddress::ConvertFrom(from).GetIpv4();
    }

    if (src == m_bsAddress)
    {
      VanetMessageHeader header;
      if (!TryRemoveVanetMessageHeader(packet, header) ||
          header.GetPayloadSize() != packet->GetSize())
      {
        packet = socket->RecvFrom(from);
        continue;
      }
      std::vector<uint8_t> payload(packet->GetSize());
      if (!payload.empty())
      {
        packet->CopyData(payload.data(), payload.size());
      }
      HandleModelDownload(header, payload);
    }
    else
    {
      HandleVehicleUpdate(packet, from);
    }
    packet = socket->RecvFrom(from);
  }
}

void
FlRsuAggregatorApp::HandleModelDownload(const VanetMessageHeader& header,
                                        const std::vector<uint8_t>& payload)
{
  if (header.GetType() != VanetMessageType::FL_MODEL_DOWNLOAD &&
      header.GetType() != VanetMessageType::FL_GLOBAL_MODEL &&
      header.GetType() != VanetMessageType::FL_ROUND_START)
  {
    return;
  }

  size_t offset = 0;
  uint32_t round = 0;
  std::vector<double> globalModel;
  if (!ReadUint32(payload, offset, round) || !ReadVector(payload, offset, globalModel))
  {
    NS_LOG_WARN("FL RSU " << m_rsuId << " failed to parse model download");
    return;
  }

  RoundState& state = m_rounds[round];
  if (state.flushEvent.IsRunning())
  {
    state.flushEvent.Cancel();
  }
  state.round = round;
  state.globalModel = globalModel;
  state.updates.clear();
  state.seenVehicles.clear();
  state.rejected = 0;
  state.flushDeadlineExpired = false;

  for (const Ipv4Address& vehicle : m_vehicleAddresses)
  {
    Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
    VanetMessageHeader forward;
    forward.SetType(VanetMessageType::FL_MODEL_DOWNLOAD);
    forward.SetSenderId(m_rsuId);
    forward.SetTargetId(0);
    forward.SetMessageId(round);
    forward.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
    forward.SetPayloadSize(payload.size());
    packet->AddHeader(forward);
    const uint64_t bytes = packet->GetSize();
    m_socket->SendTo(packet, 0, InetSocketAddress(vehicle, m_vehiclePort));
    VanetPowerModel::RecordCommunication("fl_model_download", "rsu", "vehicle", bytes);
  }

  if (!m_flushTimeout.IsZero())
  {
    state.flushEvent =
        Simulator::Schedule(m_flushTimeout, &FlRsuAggregatorApp::FlushRoundOnTimeout, this, round);
  }
}

void
FlRsuAggregatorApp::HandleVehicleUpdate(Ptr<Packet> packet, const Address& from)
{
  (void)from;
  Ptr<Packet> inspect = packet->Copy();
  UpdateEntry entry;

  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    VanetPbcAuthHeader auth;
    if (!TryRemoveVanetPbcAuthHeader(inspect, auth))
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    VanetMessageHeader header;
    if (!TryRemoveVanetMessageHeader(inspect, header) ||
        header.GetType() != VanetMessageType::FL_UPDATE_UPLOAD ||
        header.GetPayloadSize() != inspect->GetSize())
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    std::vector<uint8_t> payload(inspect->GetSize());
    if (!payload.empty())
    {
      inspect->CopyData(payload.data(), payload.size());
    }

    const size_t g1Len = m_pbc.GetG1BytesLength();
    const uint64_t nowUs = static_cast<uint64_t>(Simulator::Now().GetMicroSeconds());
    if (auth.GetPid1().empty() || auth.GetPid2().size() != 4 || auth.GetQi().size() != g1Len ||
        auth.GetWi().size() != g1Len || auth.GetPsi().size() != g1Len ||
        auth.GetTimestampUs() > nowUs || (nowUs - auth.GetTimestampUs()) > m_pidValidityUs ||
        !m_pbc.EncodePid(auth.GetPid1(), auth.GetPid2(), auth.GetTimestampUs(), entry.pidBytes))
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    entry.stateBytes = auth.GetState();
    entry.qiBytes = auth.GetQi();
    entry.wiBytes = auth.GetWi();
    entry.psiBytes = auth.GetPsi();
    entry.messageBytes = payload;

    size_t offset = 0;
    uint32_t round = 0;
    if (!ReadUint32(payload, offset, round) || !ReadUint32(payload, offset, entry.vehicleId) ||
        !ReadUint32(payload, offset, entry.datasetSize) || !ReadVector(payload, offset, entry.update))
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    RoundState& state = m_rounds[round];
    state.round = round;
    if (!state.seenVehicles.insert(entry.vehicleId).second)
    {
      return;
    }
    state.updates.push_back(std::move(entry));
    TryFlushRound(round);
#endif
  }
  else
  {
    VanetAuthHeader auth;
    if (!TryRemoveVanetAuthHeader(inspect, auth))
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    std::vector<uint8_t> signData(inspect->GetSize());
    inspect->CopyData(signData.data(), signData.size());

    VanetMessageHeader header;
    if (!TryRemoveVanetMessageHeader(inspect, header) ||
        header.GetType() != VanetMessageType::FL_UPDATE_UPLOAD ||
        header.GetPayloadSize() != inspect->GetSize())
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    std::vector<uint8_t> payload(inspect->GetSize());
    if (!payload.empty())
    {
      inspect->CopyData(payload.data(), payload.size());
    }

    bool verified = false;
    std::string publicKey(auth.GetPublicKey().begin(), auth.GetPublicKey().end());
    {
      VanetPowerModel::ScopedTimer timer("ecc_verify", "rsu");
      verified = EccCrypto::Verify(publicKey, signData.data(), signData.size(), auth.GetSignature());
    }
    if (!verified)
    {
      VanetStats::RecordVerificationFailure();
      return;
    }

    size_t offset = 0;
    uint32_t round = 0;
    if (!ReadUint32(payload, offset, round) || !ReadUint32(payload, offset, entry.vehicleId) ||
        !ReadUint32(payload, offset, entry.datasetSize) || !ReadVector(payload, offset, entry.update))
    {
      VanetStats::RecordVerificationFailure();
      return;
    }
    RoundState& state = m_rounds[round];
    state.round = round;
    if (!state.seenVehicles.insert(entry.vehicleId).second)
    {
      return;
    }
    state.updates.push_back(std::move(entry));
    TryFlushRound(round);
  }
}

void
FlRsuAggregatorApp::TryFlushRound(uint32_t round, bool deadlineExpired)
{
  auto it = m_rounds.find(round);
  if (it == m_rounds.end())
  {
    return;
  }
  RoundState& state = it->second;
  if (deadlineExpired)
  {
    state.flushDeadlineExpired = true;
  }
  if (state.updates.empty())
  {
    return;
  }
  const uint32_t received = static_cast<uint32_t>(state.updates.size());
  const bool hasAllExpected = (m_expectedUpdates == 0 || received >= m_expectedUpdates);
  const bool deadlineAllowsPartial =
      state.flushDeadlineExpired && received >= GetMinFlushUpdates();
  if (!hasAllExpected && !deadlineAllowsPartial)
  {
    return;
  }
  if (state.flushEvent.IsRunning())
  {
    state.flushEvent.Cancel();
  }

  uint32_t verified = static_cast<uint32_t>(state.updates.size());
  if (m_enablePbc)
  {
#ifdef VANET_SECURITY_USE_PBC
    std::vector<std::vector<uint8_t>> pidList;
    std::vector<std::vector<uint8_t>> qiList;
    std::vector<std::vector<uint8_t>> wiList;
    std::vector<std::vector<uint8_t>> psiList;
    std::vector<std::vector<uint8_t>> messageList;
    for (const UpdateEntry& entry : state.updates)
    {
      pidList.push_back(entry.pidBytes);
      qiList.push_back(entry.qiBytes);
      wiList.push_back(entry.wiBytes);
      psiList.push_back(entry.psiBytes);
      messageList.push_back(entry.messageBytes);
    }
    std::vector<uint8_t> aggregatePsi;
    bool ok = m_pbc.AggregatePsi(psiList, aggregatePsi) &&
              m_pbc.VerifyAggregate(pidList,
                                    qiList,
                                    wiList,
                                    messageList,
                                    state.updates.front().stateBytes,
                                    aggregatePsi);
    if (!ok)
    {
      for (uint32_t i = 0; i < verified; ++i)
      {
        VanetStats::RecordVerificationFailure();
      }
      state.rejected += verified;
      verified = 0;
    }
#endif
  }

  uint32_t totalDataset = 0;
  for (const UpdateEntry& entry : state.updates)
  {
    totalDataset += entry.datasetSize;
  }

  std::vector<double> aggregate(m_modelDim, 0.0);
  {
    VanetPowerModel::ScopedTimer timer("fl_edge_aggregate", "rsu");
    if (verified > 0 && totalDataset > 0)
    {
      for (const UpdateEntry& entry : state.updates)
      {
        const double weight = static_cast<double>(entry.datasetSize) / static_cast<double>(totalDataset);
        const uint32_t dim = std::min<uint32_t>(aggregate.size(), entry.update.size());
        for (uint32_t d = 0; d < dim; ++d)
        {
          aggregate[d] += weight * entry.update[d];
        }
      }
    }
  }

  SendAggregate(round, aggregate, verified, state.rejected, totalDataset);
  m_rounds.erase(it);
}

void
FlRsuAggregatorApp::FlushRoundOnTimeout(uint32_t round)
{
  TryFlushRound(round, true);
}

uint32_t
FlRsuAggregatorApp::GetMinFlushUpdates() const
{
  if (m_expectedUpdates == 0)
  {
    return 1;
  }
  const double fraction = std::max(0.0, std::min(1.0, m_minFlushFraction));
  const uint32_t minUpdates =
      static_cast<uint32_t>(std::ceil(static_cast<double>(m_expectedUpdates) * fraction));
  return std::max(1u, std::min(m_expectedUpdates, minUpdates));
}

void
FlRsuAggregatorApp::SendAggregate(uint32_t round,
                                  const std::vector<double>& aggregate,
                                  uint32_t verified,
                                  uint32_t rejected,
                                  uint32_t totalDataset)
{
  std::vector<uint8_t> payload;
  WriteUint32(payload, round);
  WriteUint32(payload, m_rsuId);
  WriteUint32(payload, verified);
  WriteUint32(payload, rejected);
  WriteUint32(payload, totalDataset);
  WriteVector(payload, aggregate);

  Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
  VanetMessageHeader header;
  header.SetType(VanetMessageType::FL_RSU_AGGREGATE);
  header.SetSenderId(m_rsuId);
  header.SetTargetId(0);
  header.SetMessageId(round);
  header.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
  header.SetPayloadSize(payload.size());
  packet->AddHeader(header);

  const uint64_t bytes = packet->GetSize();
  m_socket->SendTo(packet, 0, InetSocketAddress(m_bsAddress, m_bsPort));
  VanetPowerModel::RecordCommunication("fl_rsu_aggregate_upload", "rsu", "bs", bytes);
}

FlBsAggregatorApp::FlBsAggregatorApp() = default;
FlBsAggregatorApp::~FlBsAggregatorApp() = default;

TypeId
FlBsAggregatorApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::FlBsAggregatorApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<FlBsAggregatorApp>()
                          .AddAttribute("ListenPort",
                                        "UDP port for FL BS aggregate ingress.",
                                        UintegerValue(9400),
                                        MakeUintegerAccessor(&FlBsAggregatorApp::m_listenPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("RsuPort",
                                        "FL RSU model-download port.",
                                        UintegerValue(9401),
                                        MakeUintegerAccessor(&FlBsAggregatorApp::m_rsuPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("Rounds",
                                        "Number of FL communication rounds.",
                                        UintegerValue(20),
                                        MakeUintegerAccessor(&FlBsAggregatorApp::m_rounds),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("ModelDim",
                                        "Number of model-vector parameters.",
                                        UintegerValue(64),
                                        MakeUintegerAccessor(&FlBsAggregatorApp::m_modelDim),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("SelectedVehicles",
                                        "Number of FL participant vehicles.",
                                        UintegerValue(0),
                                        MakeUintegerAccessor(&FlBsAggregatorApp::m_selectedVehicles),
                                        MakeUintegerChecker<uint32_t>())
                          .AddAttribute("RoundInterval",
                                        "Delay between completed FL rounds.",
                                        TimeValue(Seconds(1.0)),
                                        MakeTimeAccessor(&FlBsAggregatorApp::m_roundInterval),
                                        MakeTimeChecker())
                          .AddAttribute("InitialDelay",
                                        "Delay before the first FL round starts.",
                                        TimeValue(Seconds(3.0)),
                                        MakeTimeAccessor(&FlBsAggregatorApp::m_initialDelay),
                                        MakeTimeChecker())
                          .AddAttribute("FlCsv",
                                        "Output CSV for FL round metrics.",
                                        StringValue("results/fl/fl_metrics.csv"),
                                        MakeStringAccessor(&FlBsAggregatorApp::m_flCsvPath),
                                        MakeStringChecker())
                          .AddAttribute("NetworkLabel",
                                        "Network profile label.",
                                        StringValue("5g_lte"),
                                        MakeStringAccessor(&FlBsAggregatorApp::m_networkLabel),
                                        MakeStringChecker())
                          .AddAttribute("SecurityMode",
                                        "Security mode label.",
                                        StringValue("pbc"),
                                        MakeStringAccessor(&FlBsAggregatorApp::m_securityMode),
                                        MakeStringChecker());
  return tid;
}

void
FlBsAggregatorApp::SetRsuAddresses(const std::vector<Ipv4Address>& addresses)
{
  m_rsuAddresses = addresses;
}

void
FlBsAggregatorApp::StartApplication()
{
  m_globalModel.assign(std::max(1u, m_modelDim), 0.0);
  if (!m_socket)
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    if (m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_listenPort)) != 0)
    {
      NS_LOG_ERROR("FL BS bind failed");
      return;
    }
    m_socket->SetRecvCallback(MakeCallback(&FlBsAggregatorApp::HandleRead, this));
  }
  if (!m_flCsvPath.empty())
  {
    m_csv.open(m_flCsvPath);
    WriteCsvHeader();
  }
  Simulator::Schedule(m_initialDelay, &FlBsAggregatorApp::StartRound, this);
}

void
FlBsAggregatorApp::StopApplication()
{
  if (m_socket)
  {
    m_socket->Close();
    m_socket = nullptr;
  }
  if (m_csv.is_open())
  {
    m_csv.close();
  }
  m_roundAggregates.clear();
  m_seenRsuAggregates.clear();
}

void
FlBsAggregatorApp::StartRound()
{
  if (m_currentRound >= m_rounds || m_rsuAddresses.empty())
  {
    return;
  }

  std::vector<uint8_t> payload;
  WriteUint32(payload, m_currentRound);
  WriteVector(payload, m_globalModel);

  for (const Ipv4Address& rsu : m_rsuAddresses)
  {
    Ptr<Packet> packet = Create<Packet>(payload.data(), payload.size());
    VanetMessageHeader header;
    header.SetType(VanetMessageType::FL_MODEL_DOWNLOAD);
    header.SetSenderId(0);
    header.SetTargetId(0);
    header.SetMessageId(m_currentRound);
    header.SetTimestampUs(static_cast<uint64_t>(Simulator::Now().GetMicroSeconds()));
    header.SetPayloadSize(payload.size());
    packet->AddHeader(header);
    const uint64_t bytes = packet->GetSize();
    m_socket->SendTo(packet, 0, InetSocketAddress(rsu, m_rsuPort));
    VanetPowerModel::RecordCommunication("fl_model_download", "bs", "rsu", bytes);
  }
}

void
FlBsAggregatorApp::HandleRead(Ptr<Socket> socket)
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
    if (header.GetType() == VanetMessageType::FL_RSU_AGGREGATE)
    {
      std::vector<uint8_t> payload(packet->GetSize());
      if (!payload.empty())
      {
        packet->CopyData(payload.data(), payload.size());
      }
      size_t offset = 0;
      uint32_t round = 0;
      RsuAggregate aggregate;
      if (ReadUint32(payload, offset, round) && ReadUint32(payload, offset, aggregate.rsuId) &&
          ReadUint32(payload, offset, aggregate.verified) &&
          ReadUint32(payload, offset, aggregate.rejected) &&
          ReadUint32(payload, offset, aggregate.datasetSize) &&
          ReadVector(payload, offset, aggregate.weights))
      {
        if (!m_seenRsuAggregates[round].insert(aggregate.rsuId).second)
        {
          packet = socket->RecvFrom(from);
          continue;
        }
        m_roundAggregates[round].push_back(std::move(aggregate));
        if (m_roundAggregates[round].size() >= m_rsuAddresses.size())
        {
          CompleteRound(round);
        }
      }
    }
    packet = socket->RecvFrom(from);
  }
}

void
FlBsAggregatorApp::CompleteRound(uint32_t round)
{
  auto it = m_roundAggregates.find(round);
  if (it == m_roundAggregates.end())
  {
    return;
  }
  const auto aggregates = std::move(it->second);
  m_roundAggregates.erase(it);
  m_seenRsuAggregates.erase(round);

  uint32_t totalDataset = 0;
  uint32_t verified = 0;
  uint32_t rejected = 0;
  for (const RsuAggregate& aggregate : aggregates)
  {
    totalDataset += aggregate.datasetSize;
    verified += aggregate.verified;
    rejected += aggregate.rejected;
  }

  {
    VanetPowerModel::ScopedTimer timer("fl_global_aggregate", "bs");
    std::vector<double> nextModel(m_globalModel.size(), 0.0);
    if (totalDataset > 0)
    {
      for (const RsuAggregate& aggregate : aggregates)
      {
        const double weight = static_cast<double>(aggregate.datasetSize) /
                              static_cast<double>(totalDataset);
        const uint32_t dim = std::min<uint32_t>(nextModel.size(), aggregate.weights.size());
        for (uint32_t d = 0; d < dim; ++d)
        {
          nextModel[d] += weight * aggregate.weights[d];
        }
      }
      m_globalModel = std::move(nextModel);
    }
  }

  WriteCsvRow(round, verified, rejected, totalDataset);
  ++m_currentRound;
  if (m_currentRound < m_rounds)
  {
    Simulator::Schedule(m_roundInterval, &FlBsAggregatorApp::StartRound, this);
  }
}

void
FlBsAggregatorApp::WriteCsvHeader()
{
  if (!m_csv.is_open())
  {
    return;
  }
  m_csv << "time,round,network_label,security_mode,selected_vehicles,rsu_count,"
           "updates_sent,updates_verified,updates_rejected,edge_aggregates_sent,"
           "global_round_completed,avg_local_train_ms,avg_update_sign_ms,"
           "avg_update_verify_ms,avg_edge_aggregate_ms,avg_global_aggregate_ms,"
           "fl_security_energy_j,fl_comm_energy_j,fl_total_energy_j,avg_fl_power_w,"
           "model_download_bytes,update_upload_bytes,global_loss_proxy,global_accuracy_proxy\n";
}

void
FlBsAggregatorApp::WriteCsvRow(uint32_t round,
                               uint32_t verified,
                               uint32_t rejected,
                               uint32_t totalDataset)
{
  if (!m_csv.is_open())
  {
    return;
  }
  const double time = Simulator::Now().GetSeconds();
  double avgSignS = VanetPowerModel::GetAvgSecurityLatency("pbc_sign");
  if (avgSignS == 0.0)
  {
    avgSignS = VanetPowerModel::GetAvgSecurityLatency("ecc_sign");
  }
  double avgVerifyS = VanetPowerModel::GetAvgSecurityLatency("pbc_verify_aggregate");
  if (avgVerifyS == 0.0)
  {
    avgVerifyS = VanetPowerModel::GetAvgSecurityLatency("ecc_verify");
  }
  const double securityEnergy = VanetPowerModel::GetSecurityEnergyJ();
  const double commEnergy = VanetPowerModel::GetCommunicationEnergyJ();
  const double totalEnergy = VanetPowerModel::GetTotalEnergyJ();
  const double avgPower = VanetPowerModel::GetAvgTotalPowerW(time);
  const double lossProxy = 1.0 / static_cast<double>(round + 2);
  const double accuracyProxy = std::max(0.0, 1.0 - lossProxy);
  const uint64_t modelBytes = static_cast<uint64_t>((m_globalModel.size() * sizeof(double)) + 8) *
                              static_cast<uint64_t>(m_rsuAddresses.size() + m_selectedVehicles);
  const uint64_t updateBytes = static_cast<uint64_t>((m_globalModel.size() * sizeof(double)) + 16) *
                               static_cast<uint64_t>(verified + rejected);

  m_csv << std::fixed << std::setprecision(6) << time << ',' << round << ',' << m_networkLabel
        << ',' << m_securityMode << ',' << m_selectedVehicles << ',' << m_rsuAddresses.size()
        << ',' << (verified + rejected) << ',' << verified << ',' << rejected << ','
        << m_rsuAddresses.size() << ",1," << VanetPowerModel::GetAvgSecurityLatency("fl_local_train") * 1000.0
        << ',' << avgSignS * 1000.0 << ',' << avgVerifyS * 1000.0 << ','
        << VanetPowerModel::GetAvgSecurityLatency("fl_edge_aggregate") * 1000.0 << ','
        << VanetPowerModel::GetAvgSecurityLatency("fl_global_aggregate") * 1000.0 << ','
        << securityEnergy << ',' << commEnergy << ',' << totalEnergy << ',' << avgPower << ','
        << modelBytes << ',' << updateBytes << ',' << lossProxy << ',' << accuracyProxy << '\n';
  m_csv.flush();
  (void)totalDataset;
}

} // namespace ns3
