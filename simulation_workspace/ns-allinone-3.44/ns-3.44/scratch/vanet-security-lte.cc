#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/lte-module.h"

#include "ns3/vanet-security-module.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iostream>
#include <regex>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VanetSecurityLte");

namespace {

bool g_progressLog = true;

uint32_t
CountNodesFromTrace(const std::string& path)
{
  std::ifstream input(path);
  if (!input.is_open())
  {
    NS_LOG_WARN("Failed to open trace file: " << path);
    return 0;
  }

  std::regex re("node_\\((\\d+)\\)");
  std::string line;
  uint32_t maxId = 0;
  bool found = false;
  while (std::getline(input, line))
  {
    std::smatch match;
    if (std::regex_search(line, match, re) && match.size() > 1)
    {
      uint32_t id = static_cast<uint32_t>(std::stoul(match[1].str()));
      if (!found || id > maxId)
      {
        maxId = id;
        found = true;
      }
    }
  }
  if (!found)
  {
    return 0;
  }
  return maxId + 1;
}

struct TraceBounds
{
  bool foundX{false};
  bool foundY{false};
  double minX{0.0};
  double maxX{0.0};
  double minY{0.0};
  double maxY{0.0};
};

TraceBounds
GetTraceBounds(const std::string& path)
{
  TraceBounds bounds;
  std::ifstream input(path);
  if (!input.is_open())
  {
    return bounds;
  }

  std::regex setdestRe("setdest\\s+(-?\\d+\\.?\\d*)\\s+(-?\\d+\\.?\\d*)");
  std::regex setXRe("set X_\\s+(-?\\d+\\.?\\d*)");
  std::regex setYRe("set Y_\\s+(-?\\d+\\.?\\d*)");

  std::string line;
  while (std::getline(input, line))
  {
    std::smatch match;
    if (std::regex_search(line, match, setdestRe) && match.size() > 2)
    {
      double x = std::stod(match[1].str());
      double y = std::stod(match[2].str());
      if (!bounds.foundX)
      {
        bounds.minX = bounds.maxX = x;
        bounds.foundX = true;
      }
      else
      {
        bounds.minX = std::min(bounds.minX, x);
        bounds.maxX = std::max(bounds.maxX, x);
      }
      if (!bounds.foundY)
      {
        bounds.minY = bounds.maxY = y;
        bounds.foundY = true;
      }
      else
      {
        bounds.minY = std::min(bounds.minY, y);
        bounds.maxY = std::max(bounds.maxY, y);
      }
      continue;
    }

    if (std::regex_search(line, match, setXRe) && match.size() > 1)
    {
      double x = std::stod(match[1].str());
      if (!bounds.foundX)
      {
        bounds.minX = bounds.maxX = x;
        bounds.foundX = true;
      }
      else
      {
        bounds.minX = std::min(bounds.minX, x);
        bounds.maxX = std::max(bounds.maxX, x);
      }
      continue;
    }

    if (std::regex_search(line, match, setYRe) && match.size() > 1)
    {
      double y = std::stod(match[1].str());
      if (!bounds.foundY)
      {
        bounds.minY = bounds.maxY = y;
        bounds.foundY = true;
      }
      else
      {
        bounds.minY = std::min(bounds.minY, y);
        bounds.maxY = std::max(bounds.maxY, y);
      }
      continue;
    }
  }

  return bounds;
}

void
ApplyVehicleZOffset(Ptr<const MobilityModel> mobility)
{
  if (!mobility)
  {
    return;
  }
  Ptr<Node> node = mobility->GetObject<Node>();
  if (!node)
  {
    return;
  }
  uint32_t id = node->GetId();
  double z = 1.5 + 0.01 * static_cast<double>(id % 10000);
  Vector pos = mobility->GetPosition();
  if (std::abs(pos.z - z) < 1e-6)
  {
    return;
  }
  auto* nonConst = const_cast<MobilityModel*>(PeekPointer(mobility));
  nonConst->SetPosition(Vector(pos.x, pos.y, z));
}

void
LogStats(std::ofstream* stream)
{
  if (!stream || !stream->is_open())
  {
    return;
  }
  double time = Simulator::Now().GetSeconds();
  double v2vMs = VanetStats::GetAvgV2vDelay() * 1000.0;
  double v2iUpMs = VanetStats::GetAvgV2iUplinkDelay() * 1000.0;
  double v2iDownMs = VanetStats::GetAvgV2iDownlinkDelay() * 1000.0;
  double v2iRttMs = VanetStats::GetAvgV2iRtt() * 1000.0;
  double regMs = VanetStats::GetAvgRegistrationDelay() * 1000.0;
  double kgcMs = VanetStats::GetAvgKgcRtt() * 1000.0;
  double taMs = VanetStats::GetAvgTaRtt() * 1000.0;
  double securityEnergyJ = VanetPowerModel::GetSecurityEnergyJ();
  double commEnergyJ = VanetPowerModel::GetCommunicationEnergyJ();
  double totalEnergyJ = VanetPowerModel::GetTotalEnergyJ();
  double avgSecurityPowerW = VanetPowerModel::GetAvgSecurityPowerW(time);
  double avgCommPowerW = VanetPowerModel::GetAvgCommunicationPowerW(time);
  double avgTotalPowerW = VanetPowerModel::GetAvgTotalPowerW(time);
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
  double avgAggregateMs = VanetPowerModel::GetAvgSecurityLatency("pbc_aggregate") * 1000.0;
  double avgPartialKeyMs = VanetPowerModel::GetAvgSecurityLatency("pbc_partial_key") * 1000.0;
  if (g_progressLog)
  {
    std::cout << "SimTime " << time << " s" << std::endl;
  }
  *stream << time << "," << VanetStats::GetInfectedRatio() << ","
          << VanetStats::GetMaxPropagationDistance() << ","
          << VanetStats::GetVerificationFailures() << ","
          << v2vMs << "," << v2iUpMs << "," << v2iDownMs << "," << v2iRttMs
          << "," << regMs << "," << kgcMs << "," << taMs << ","
          << securityEnergyJ << "," << commEnergyJ << "," << totalEnergyJ << ","
          << avgSecurityPowerW << "," << avgCommPowerW << "," << avgTotalPowerW << ","
          << avgSignS * 1000.0 << "," << avgAggregateMs << "," << avgVerifyS * 1000.0
          << "," << avgPartialKeyMs << "\n";
  stream->flush();
  Simulator::Schedule(Seconds(1.0), &LogStats, stream);
}

} // namespace

int main(int argc, char* argv[])
{
  std::string tracePath = "../../integration_test/mobility_trace.tcl";
  double simTime = 150.0;
  double msgInterval = 1.0;
  bool verifySignatures = true;
  uint32_t rsuCount = 2;
  std::string securityMode = "pbc";
  std::string outCsv = "vanet-security-metrics-lte.csv";
  std::string stageCsv = "vanet-power-stages-lte.csv";
  std::string networkLabel = "5g_lte";
  bool progressLog = true;
  double vehicleCpuPowerW = 2.5;
  double infraCpuPowerW = 15.0;
  double vehicleRxPowerW = 0.8;
  double infraRxPowerW = 5.0;
  double vehicleTxPowerDbm = 23.0;
  double infraTxPowerDbm = 30.0;
  double effectiveRateMbps = 100.0;
  double pidValiditySeconds = 0.0;
  bool enableFl = false;
  uint32_t flRounds = 20;
  uint32_t flParticipants = 50;
  uint32_t flModelDim = 64;
  double flRoundInterval = 1.0;
  uint32_t flLocalEpochs = 1;
  double flLearningRate = 0.01;
  bool flMasking = true;
  double flRsuFlushTimeout = 0.0;
  double flRsuMinFlushFraction = 1.0;
  std::string flCsv = "results/fl/lte_fl.csv";
  std::string flStageCsv = "";
  std::string flSecurityMode = "";

  CommandLine cmd;
  cmd.AddValue("trace", "Path to SUMO ns-2 mobility trace", tracePath);
  cmd.AddValue("simTime", "Simulation time (s)", simTime);
  cmd.AddValue("msgInterval", "Source message interval (s)", msgInterval);
  cmd.AddValue("verifySignatures", "Enable ECDSA verification", verifySignatures);
  cmd.AddValue("rsuCount", "Number of RSU/eNB nodes", rsuCount);
  cmd.AddValue("securityMode", "Security mode: pbc or ecc", securityMode);
  cmd.AddValue("outCsv", "Output CSV path", outCsv);
  cmd.AddValue("stageCsv", "Per-stage power/latency CSV path", stageCsv);
  cmd.AddValue("networkLabel", "Network label for power summaries", networkLabel);
  cmd.AddValue("progressLog", "Print progress each simulated second", progressLog);
  cmd.AddValue("vehicleCpuPowerW", "Analytical vehicle CPU power in watts", vehicleCpuPowerW);
  cmd.AddValue("infraCpuPowerW", "Analytical infrastructure CPU power in watts", infraCpuPowerW);
  cmd.AddValue("vehicleRxPowerW", "Analytical vehicle RX power in watts", vehicleRxPowerW);
  cmd.AddValue("infraRxPowerW", "Analytical infrastructure RX power in watts", infraRxPowerW);
  cmd.AddValue("vehicleTxPowerDbm", "Analytical vehicle TX power in dBm", vehicleTxPowerDbm);
  cmd.AddValue("infraTxPowerDbm", "Analytical infrastructure TX power in dBm", infraTxPowerDbm);
  cmd.AddValue("effectiveRateMbps", "Analytical effective communication rate in Mbps", effectiveRateMbps);
  cmd.AddValue("pidValiditySeconds",
               "PBC PID validity window in seconds; 0 means simTime + 60 seconds",
               pidValiditySeconds);
  cmd.AddValue("enableFl", "Enable lightweight hierarchical federated learning traffic", enableFl);
  cmd.AddValue("flRounds", "Number of federated learning communication rounds", flRounds);
  cmd.AddValue("flParticipants", "Number of participating vehicles for FL", flParticipants);
  cmd.AddValue("flModelDim", "Federated model vector dimension", flModelDim);
  cmd.AddValue("flRoundInterval", "Delay between completed FL rounds in seconds", flRoundInterval);
  cmd.AddValue("flLocalEpochs", "Synthetic local epochs per FL round", flLocalEpochs);
  cmd.AddValue("flLearningRate", "Synthetic FL learning rate", flLearningRate);
  cmd.AddValue("flMasking", "Enable FL deterministic pairwise masks", flMasking);
  cmd.AddValue("flRsuFlushTimeout",
               "Seconds an FL RSU waits before allowing threshold-based partial aggregation",
               flRsuFlushTimeout);
  cmd.AddValue("flRsuMinFlushFraction",
               "Minimum fraction of expected FL vehicle updates required after timeout",
               flRsuMinFlushFraction);
  cmd.AddValue("flCsv", "FL round metrics CSV path", flCsv);
  cmd.AddValue("flStageCsv", "Optional FL-focused stage summary CSV path", flStageCsv);
  cmd.AddValue("flSecurityMode", "FL security mode override: pbc or ecc; default follows securityMode", flSecurityMode);
  cmd.Parse(argc, argv);
  g_progressLog = progressLog;

  std::transform(securityMode.begin(),
                 securityMode.end(),
                 securityMode.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  bool enablePbc = false;
  if (securityMode == "pbc")
  {
    enablePbc = true;
  }
  else if (securityMode == "ecc")
  {
    enablePbc = false;
  }
  else
  {
    NS_LOG_ERROR("Invalid --securityMode value '" << securityMode << "' (expected pbc or ecc)");
    return 1;
  }
  if (flSecurityMode.empty())
  {
    flSecurityMode = securityMode;
  }
  std::transform(flSecurityMode.begin(),
                 flSecurityMode.end(),
                 flSecurityMode.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (flSecurityMode != "pbc" && flSecurityMode != "ecc")
  {
    NS_LOG_ERROR("Invalid --flSecurityMode value '" << flSecurityMode << "' (expected pbc or ecc)");
    return 1;
  }
  const bool flEnablePbc = (flSecurityMode == "pbc");
  if (pidValiditySeconds <= 0.0)
  {
    pidValiditySeconds = simTime + 60.0;
  }
  const uint64_t pidValidityUs = static_cast<uint64_t>(pidValiditySeconds * 1e6);

  uint32_t vehicleCount = CountNodesFromTrace(tracePath);
  if (vehicleCount == 0)
  {
    NS_LOG_ERROR("No vehicles found in trace. Check trace path.");
    return 1;
  }

  VanetStats::Reset();
  VanetStats::SetTotalVehicles(vehicleCount);
  VanetPowerModel::Reset();
  VanetPowerModel::Config powerConfig;
  powerConfig.vehicleCpuPowerW = vehicleCpuPowerW;
  powerConfig.infraCpuPowerW = infraCpuPowerW;
  powerConfig.vehicleRxPowerW = vehicleRxPowerW;
  powerConfig.infraRxPowerW = infraRxPowerW;
  powerConfig.vehicleTxPowerDbm = vehicleTxPowerDbm;
  powerConfig.infraTxPowerDbm = infraTxPowerDbm;
  powerConfig.effectiveRateMbps = effectiveRateMbps;
  VanetPowerModel::Configure(powerConfig);

  NodeContainer vehicleNodes;
  vehicleNodes.Create(vehicleCount);

  NodeContainer rsuNodes;
  rsuNodes.Create(rsuCount);

  NodeContainer taNode;
  taNode.Create(1);

  NodeContainer kgcNode;
  kgcNode.Create(1);

  NodeContainer bsNode;
  bsNode.Create(1);

  InternetStackHelper internet;
  internet.Install(vehicleNodes);
  internet.Install(rsuNodes);
  internet.Install(taNode);
  internet.Install(kgcNode);
  internet.Install(bsNode);

  bsNode.Get(0)->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
  for (uint32_t i = 0; i < rsuNodes.GetN(); ++i)
  {
    rsuNodes.Get(i)->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
  }

  // Mobility for vehicles from SUMO trace
  Ns2MobilityHelper ns2(tracePath);
  ns2.Install();

  for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
  {
    Ptr<MobilityModel> mob = vehicleNodes.Get(i)->GetObject<MobilityModel>();
    if (mob)
    {
      mob->TraceConnectWithoutContext("CourseChange", MakeCallback(&ApplyVehicleZOffset));
      ApplyVehicleZOffset(mob);
    }
  }

  // RSU/eNB fixed positions
  MobilityHelper rsuMobility;
  rsuMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  Ptr<ListPositionAllocator> rsuPositions = CreateObject<ListPositionAllocator>();
  TraceBounds bounds = GetTraceBounds(tracePath);
  double minX = bounds.foundX ? bounds.minX : 0.0;
  double maxX = bounds.foundX ? bounds.maxX : 1000.0;
  double span = std::max(1.0, maxX - minX);
  double baseY = bounds.foundY ? 0.5 * (bounds.minY + bounds.maxY) : 10.0;

  if (rsuCount == 1)
  {
    rsuPositions->Add(Vector(minX + span * 0.5, baseY, 10.0));
  }
  else
  {
    for (uint32_t i = 0; i < rsuCount; ++i)
    {
      double frac = static_cast<double>(i) / static_cast<double>(rsuCount - 1);
      double z = 10.0 + 0.1 * static_cast<double>(i);
      rsuPositions->Add(Vector(minX + span * frac, baseY, z));
    }
  }
  rsuMobility.SetPositionAllocator(rsuPositions);
  rsuMobility.Install(rsuNodes);

  // LTE helper setup
  Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
  Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
  lteHelper->SetEpcHelper(epcHelper);

  // Favor low-latency settings
  // Use Rel-15 bearer definitions so NGBR_LOW_LAT_EMBB is available.
  Config::SetDefault("ns3::EpsBearer::Release", UintegerValue(15));
  Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999999));
  Config::SetDefault("ns3::LteEnbRrc::EpsBearerToRlcMapping",
                     EnumValue(LteEnbRrc::RLC_UM_ALWAYS));
  Config::SetDefault("ns3::LteEnbPhy::TxPower", DoubleValue(infraTxPowerDbm));
  Config::SetDefault("ns3::LteUePhy::TxPower", DoubleValue(vehicleTxPowerDbm));

  NetDeviceContainer enbDevs = lteHelper->InstallEnbDevice(rsuNodes);
  NetDeviceContainer ueDevs = lteHelper->InstallUeDevice(vehicleNodes);

  lteHelper->AttachToClosestEnb(ueDevs, enbDevs);

  // EPC: connect PGW to BS (remote host)
  Ptr<Node> pgw = epcHelper->GetPgwNode();
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("100Gbps"));
  p2p.SetChannelAttribute("Delay", StringValue("1ms"));
  NetDeviceContainer pgwBsDevices = p2p.Install(pgw, bsNode.Get(0));

  Ipv4AddressHelper p2pAddr;
  p2pAddr.SetBase("1.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer pgwBsIfs = p2pAddr.Assign(pgwBsDevices);

  // Assign IP to UEs
  Ipv4InterfaceContainer ueIfs = epcHelper->AssignUeIpv4Address(ueDevs);

  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  // UE default route to PGW
  for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
  {
    Ptr<Ipv4StaticRouting> ueStaticRouting =
        ipv4RoutingHelper.GetStaticRouting(vehicleNodes.Get(i)->GetObject<Ipv4>());
    ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
  }

  // Activate a bearer that matches all traffic so downlink packets are delivered to UEs.
  EpsBearer bearer(EpsBearer::NGBR_LOW_LAT_EMBB);
  // NGBR_LOW_LAT_EMBB is defined in Rel-15+; default is Rel-11.
  bearer.SetRelease(15);
  bearer.arp.priorityLevel = 15;
  Ptr<EpcTft> tft = EpcTft::Default();
  for (auto it = ueDevs.Begin(); it != ueDevs.End(); ++it)
  {
    lteHelper->ActivateDedicatedEpsBearer(*it, bearer, tft);
  }

  // BS routing to UE subnet via PGW
  uint32_t bsPgwIfIndex = bsNode.Get(0)->GetObject<Ipv4>()->GetInterfaceForDevice(pgwBsDevices.Get(1));
  Ptr<Ipv4StaticRouting> bsStatic =
      ipv4RoutingHelper.GetStaticRouting(bsNode.Get(0)->GetObject<Ipv4>());
  bsStatic->SetDefaultRoute(pgwBsIfs.GetAddress(0), bsPgwIfIndex);

  // PGW route to RSU subnet via BS
  uint32_t pgwIfIndex = pgw->GetObject<Ipv4>()->GetInterfaceForDevice(pgwBsDevices.Get(0));
  Ptr<Ipv4StaticRouting> pgwStatic = ipv4RoutingHelper.GetStaticRouting(pgw->GetObject<Ipv4>());
  pgwStatic->AddNetworkRouteTo(Ipv4Address("10.2.0.0"), Ipv4Mask("255.255.255.0"),
                               pgwBsIfs.GetAddress(1), pgwIfIndex);

  // CSMA BS-RSU backhaul
  NodeContainer bsRsuNodes;
  bsRsuNodes.Add(bsNode);
  bsRsuNodes.Add(rsuNodes);

  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
  csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));
  NetDeviceContainer bsRsuDevices = csma.Install(bsRsuNodes);

  Ipv4AddressHelper csmaAddr;
  csmaAddr.SetBase("10.2.0.0", "255.255.255.0");
  Ipv4InterfaceContainer bsRsuIfs = csmaAddr.Assign(bsRsuDevices);

  // RSU default routes to BS
  for (uint32_t i = 0; i < rsuNodes.GetN(); ++i)
  {
    uint32_t ifIndex = rsuNodes.Get(i)->GetObject<Ipv4>()->GetInterfaceForDevice(
        bsRsuDevices.Get(1 + i));
    Ptr<Ipv4StaticRouting> rsuStatic =
        ipv4RoutingHelper.GetStaticRouting(rsuNodes.Get(i)->GetObject<Ipv4>());
    rsuStatic->SetDefaultRoute(bsRsuIfs.GetAddress(0), ifIndex);
  }

  // P2P links: BS-TA and BS-KGC
  PointToPointHelper cloudP2p;
  cloudP2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  cloudP2p.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer bsTaDevices = cloudP2p.Install(bsNode.Get(0), taNode.Get(0));
  NetDeviceContainer bsKgcDevices = cloudP2p.Install(bsNode.Get(0), kgcNode.Get(0));

  Ipv4AddressHelper cloudAddr;
  cloudAddr.SetBase("10.3.0.0", "255.255.255.0");
  Ipv4InterfaceContainer bsTaIfs = cloudAddr.Assign(bsTaDevices);
  cloudAddr.SetBase("10.4.0.0", "255.255.255.0");
  Ipv4InterfaceContainer bsKgcIfs = cloudAddr.Assign(bsKgcDevices);

  // ECC keys for TA
  auto taKeys = EccCrypto::GenerateKeyPair();

  std::string pbcParams = R"(type a
q 5016916071032417911863923687783915420518698834988272735086782217043042258214706291487114949230487855429610676959493682417064495802878387205742192057730447
h 6865426548812704696509566582849235473375093961437097302961574578811789461292366439277723796099293963270768
r 730750818665452757176057050065048642452048576511
exp2 159
exp1 110
sign1 1
sign0 -1
)";

  // Install TA app
  Ptr<TaApp> taApp = CreateObject<TaApp>();
  taApp->SetAttribute("PrivateKeyPem", StringValue(taKeys.privatePem));
  taApp->SetAttribute("PublicKeyPem", StringValue(taKeys.publicPem));
  taApp->SetAttribute("EnablePbc", BooleanValue(enablePbc));
  taApp->SetAttribute("PairingParams", StringValue(pbcParams));
  taNode.Get(0)->AddApplication(taApp);
  taApp->SetStartTime(Seconds(0.1));

  // Install KGC app
  Ptr<KgcApp> kgcApp = CreateObject<KgcApp>();
  kgcApp->SetAttribute("EnablePbc", BooleanValue(enablePbc));
  kgcApp->SetAttribute("PairingParams", StringValue(pbcParams));
  kgcNode.Get(0)->AddApplication(kgcApp);
  kgcApp->SetStartTime(Seconds(0.1));

  // Install BS app
  Ptr<BsApp> bsApp = CreateObject<BsApp>();
  bsApp->SetAttribute("TaAddress", Ipv4AddressValue(bsTaIfs.GetAddress(1)));
  bsApp->SetAttribute("KgcAddress", Ipv4AddressValue(bsKgcIfs.GetAddress(1)));
  bsNode.Get(0)->AddApplication(bsApp);
  bsApp->SetStartTime(Seconds(0.2));

  // RSU apps
  for (uint32_t i = 0; i < rsuCount; ++i)
  {
    Ptr<RsuApp> rsuApp = CreateObject<RsuApp>();
    rsuApp->SetAttribute("BsAddress", Ipv4AddressValue(bsRsuIfs.GetAddress(0)));
    rsuApp->SetAttribute("RsuId", UintegerValue(rsuNodes.Get(i)->GetId()));
    rsuNodes.Get(i)->AddApplication(rsuApp);
    rsuApp->SetStartTime(Seconds(0.3 + 0.1 * i));
  }

  // V2V via BS relay
  Ptr<BsRelayApp> relayApp = CreateObject<BsRelayApp>();
  relayApp->SetAttribute("EnablePbc", BooleanValue(enablePbc));
  relayApp->SetAttribute("PairingParams", StringValue(pbcParams));
  relayApp->SetAttribute("PidValidityUs", UintegerValue(pidValidityUs));
  bsNode.Get(0)->AddApplication(relayApp);
  relayApp->SetStartTime(Seconds(0.4));
  if (enablePbc)
  {
    Simulator::Schedule(Seconds(0.2),
                        [relayApp, kgcApp]() { relayApp->SetPpubBytes(kgcApp->GetPpubBytes()); });
  }

  std::vector<Ipv4Address> ueAddrs;
  ueAddrs.reserve(vehicleCount);
  for (uint32_t i = 0; i < vehicleCount; ++i)
  {
    ueAddrs.push_back(ueIfs.GetAddress(i));
  }
  relayApp->SetUeAddresses(ueAddrs);

  // Vehicle apps
  Ipv4Address rsuAddress = bsRsuIfs.GetAddress(1); // first RSU on CSMA
  Ipv4Address relayAddress = pgwBsIfs.GetAddress(1); // BS address toward EPC
  for (uint32_t i = 0; i < vehicleCount; ++i)
  {
    Ptr<VehicleApp> vehicleApp = CreateObject<VehicleApp>();
    vehicleApp->SetAttribute("RsuAddress", Ipv4AddressValue(rsuAddress));
    vehicleApp->SetAttribute("MessageInterval", TimeValue(Seconds(msgInterval)));
    vehicleApp->SetAttribute("VerifySignatures", BooleanValue(verifySignatures));
    vehicleApp->SetAttribute("BroadcastRegister", BooleanValue(false));
    vehicleApp->SetAttribute("EnablePbc", BooleanValue(enablePbc));
    vehicleApp->SetAttribute("PairingParams", StringValue(pbcParams));
    vehicleApp->SetAttribute("PidValidityUs", UintegerValue(pidValidityUs));
    vehicleApp->SetAttribute("TaPublicKeyPem", StringValue(taKeys.publicPem));
    vehicleApp->SetAttribute("UseBsRelay", BooleanValue(true));
    vehicleApp->SetAttribute("RelayAddress", Ipv4AddressValue(relayAddress));
    vehicleNodes.Get(i)->AddApplication(vehicleApp);
    vehicleApp->SetStartTime(Seconds(0.5 + 0.01 * i));
  }

  if (enableFl)
  {
    const uint32_t selectedVehicles = std::min(flParticipants, vehicleCount);
    std::vector<Ipv4Address> flRsuAddresses;
    flRsuAddresses.reserve(rsuCount);
    for (uint32_t r = 0; r < rsuCount; ++r)
    {
      flRsuAddresses.push_back(bsRsuIfs.GetAddress(1 + r));
    }

    std::vector<std::vector<uint32_t>> groupIds(rsuCount);
    std::vector<std::vector<uint32_t>> groupSizes(rsuCount);
    std::vector<std::vector<Ipv4Address>> groupAddrs(rsuCount);
    for (uint32_t i = 0; i < selectedVehicles; ++i)
    {
      uint32_t group = rsuCount > 0 ? (i % rsuCount) : 0;
      uint32_t datasetSize = 1000 + 100 * (i % 7);
      groupIds[group].push_back(i);
      groupSizes[group].push_back(datasetSize);
      groupAddrs[group].push_back(ueIfs.GetAddress(i));
    }

    Ptr<FlBsAggregatorApp> flBs = CreateObject<FlBsAggregatorApp>();
    flBs->SetAttribute("Rounds", UintegerValue(flRounds));
    flBs->SetAttribute("ModelDim", UintegerValue(flModelDim));
    flBs->SetAttribute("SelectedVehicles", UintegerValue(selectedVehicles));
    flBs->SetAttribute("RoundInterval", TimeValue(Seconds(flRoundInterval)));
    flBs->SetAttribute("FlCsv", StringValue(flCsv));
    flBs->SetAttribute("NetworkLabel", StringValue(networkLabel));
    flBs->SetAttribute("SecurityMode", StringValue(flSecurityMode));
    flBs->SetRsuAddresses(flRsuAddresses);
    bsNode.Get(0)->AddApplication(flBs);
    flBs->SetStartTime(Seconds(0.8));

    std::vector<uint8_t> flPpub;
#ifdef VANET_SECURITY_USE_PBC
    PbcCrypto flKgc;
    PbcCrypto flTa;
    if (flEnablePbc)
    {
      if (!flKgc.Init(pbcParams) || !flKgc.SetupKgc() || !flTa.Init(pbcParams) ||
          !flTa.SetupTa())
      {
        NS_FATAL_ERROR("Failed to set up PBC material for FL apps.");
      }
      flPpub = flKgc.GetPpubBytes();
    }
#else
    if (flEnablePbc)
    {
      NS_FATAL_ERROR("FL PBC mode requires VANET_SECURITY_ENABLE_PBC=ON at build time.");
    }
#endif

    for (uint32_t r = 0; r < rsuCount; ++r)
    {
      Ptr<FlRsuAggregatorApp> flRsu = CreateObject<FlRsuAggregatorApp>();
      flRsu->SetAttribute("BsAddress", Ipv4AddressValue(bsRsuIfs.GetAddress(0)));
      flRsu->SetAttribute("RsuId", UintegerValue(r));
      flRsu->SetAttribute("ExpectedUpdates", UintegerValue(groupIds[r].size()));
      flRsu->SetAttribute("FlushTimeout", TimeValue(Seconds(flRsuFlushTimeout)));
      flRsu->SetAttribute("MinFlushFraction", DoubleValue(flRsuMinFlushFraction));
      flRsu->SetAttribute("ModelDim", UintegerValue(flModelDim));
      flRsu->SetAttribute("EnablePbc", BooleanValue(flEnablePbc));
      flRsu->SetAttribute("SecurityMode", StringValue(flSecurityMode));
      flRsu->SetAttribute("PairingParams", StringValue(pbcParams));
      flRsu->SetAttribute("PidValidityUs", UintegerValue(pidValidityUs));
      flRsu->SetVehicleAddresses(groupAddrs[r]);
      if (flEnablePbc)
      {
        flRsu->SetPpubBytes(flPpub);
      }
      rsuNodes.Get(r)->AddApplication(flRsu);
      flRsu->SetStartTime(Seconds(0.7 + 0.05 * r));
    }

    for (uint32_t i = 0; i < selectedVehicles; ++i)
    {
      uint32_t group = rsuCount > 0 ? (i % rsuCount) : 0;
      uint32_t datasetSize = 1000 + 100 * (i % 7);
      Ptr<FlVehicleApp> flVehicle = CreateObject<FlVehicleApp>();
      flVehicle->SetAttribute("VehicleId", UintegerValue(i));
      flVehicle->SetAttribute("DatasetSize", UintegerValue(datasetSize));
      flVehicle->SetAttribute("ModelDim", UintegerValue(flModelDim));
      flVehicle->SetAttribute("LocalEpochs", UintegerValue(flLocalEpochs));
      flVehicle->SetAttribute("LearningRate", DoubleValue(flLearningRate));
      flVehicle->SetAttribute("EnableMasking", BooleanValue(flMasking));
      flVehicle->SetAttribute("EnablePbc", BooleanValue(flEnablePbc));
      flVehicle->SetAttribute("SecurityMode", StringValue(flSecurityMode));
      flVehicle->SetAttribute("PairingParams", StringValue(pbcParams));
      flVehicle->SetAttribute("PidValidityUs", UintegerValue(pidValidityUs));
      flVehicle->SetAttribute("RsuAddress", Ipv4AddressValue(flRsuAddresses[group]));
      flVehicle->SetGroupInfo(groupIds[group], groupSizes[group]);

      if (flEnablePbc)
      {
#ifdef VANET_SECURITY_USE_PBC
        PbcCrypto flVehiclePbc;
        std::vector<uint8_t> pid1;
        std::vector<uint8_t> di;
        std::vector<uint8_t> pid2;
        std::vector<uint8_t> partialKey;
        std::vector<uint8_t> xi;
        std::vector<uint8_t> qi;
        uint64_t tiUs = 0;
        if (!flVehiclePbc.Init(pbcParams) || !flVehiclePbc.GeneratePid1(pid1, di) ||
            !flTa.ComputePid2(i, pid1, pid2) ||
            !flKgc.ComputePartialKey(pid1, pid2, tiUs, partialKey) ||
            !flVehiclePbc.GenerateVerificationKey(xi, qi))
        {
          NS_FATAL_ERROR("Failed to provision FL PBC credentials for vehicle " << i);
        }
        flVehicle->SetPbcCredentials(pid1, pid2, tiUs, partialKey, xi, qi);
#endif
      }
      else
      {
        auto keys = EccCrypto::GenerateKeyPair();
        flVehicle->SetEccKeys(keys.publicPem, keys.privatePem);
      }

      vehicleNodes.Get(i)->AddApplication(flVehicle);
      flVehicle->SetStartTime(Seconds(0.9 + 0.005 * i));
    }
  }

  std::ofstream statsFile(outCsv);
  statsFile << "time,infected_ratio,propagation_distance,verification_failures,"
               "avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,"
               "avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms,"
               "security_energy_j,comm_energy_j,total_energy_j,"
               "avg_security_power_w,avg_comm_power_w,avg_total_power_w,"
               "avg_sign_ms,avg_aggregate_ms,avg_verify_ms,avg_partial_key_ms\n";
  Simulator::Schedule(Seconds(1.0), &LogStats, &statsFile);

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  VanetPowerModel::WriteStageSummaryCsv(stageCsv, networkLabel, securityMode);
  if (!flStageCsv.empty())
  {
    VanetPowerModel::WriteStageSummaryCsv(flStageCsv, networkLabel, flSecurityMode);
  }
  Simulator::Destroy();

  statsFile.close();
  return 0;
}
