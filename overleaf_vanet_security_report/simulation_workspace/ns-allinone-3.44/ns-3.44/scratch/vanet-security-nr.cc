#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/nr-module.h"
#include "ns3/isotropic-antenna-model.h"
#include "ns3/ideal-beamforming-helper.h"

#include "ns3/vanet-security-module.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iostream>
#include <regex>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VanetSecurityNr");

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
  if (g_progressLog)
  {
    std::cout << "SimTime " << time << " s" << std::endl;
  }
  *stream << time << "," << VanetStats::GetInfectedRatio() << ","
          << VanetStats::GetMaxPropagationDistance() << ","
          << VanetStats::GetVerificationFailures() << ","
          << v2vMs << "," << v2iUpMs << "," << v2iDownMs << "," << v2iRttMs
          << "," << regMs << "," << kgcMs << "," << taMs << "\n";
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
  double nrFreq = 60e9;
  double nrBw = 400e6;
  uint16_t nrMu = 3;
  std::string v2vMode = "sidelink";
  std::string securityMode = "pbc";
  std::string outCsv = "vanet-security-metrics-nr.csv";
  bool progressLog = true;

  CommandLine cmd;
  cmd.AddValue("trace", "Path to SUMO ns-2 mobility trace", tracePath);
  cmd.AddValue("simTime", "Simulation time (s)", simTime);
  cmd.AddValue("msgInterval", "Source message interval (s)", msgInterval);
  cmd.AddValue("verifySignatures", "Enable ECDSA verification", verifySignatures);
  cmd.AddValue("rsuCount", "Number of RSU/gNB nodes", rsuCount);
  cmd.AddValue("nrFreq", "NR carrier frequency (Hz)", nrFreq);
  cmd.AddValue("nrBw", "NR bandwidth (Hz)", nrBw);
  cmd.AddValue("nrMu", "NR numerology (mu)", nrMu);
  cmd.AddValue("v2vMode", "V2V mode: sidelink or relay", v2vMode);
  cmd.AddValue("securityMode", "Security mode: pbc or ecc", securityMode);
  cmd.AddValue("outCsv", "Output CSV path", outCsv);
  cmd.AddValue("progressLog", "Print progress each simulated second", progressLog);
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

  uint32_t vehicleCount = CountNodesFromTrace(tracePath);
  if (vehicleCount == 0)
  {
    NS_LOG_ERROR("No vehicles found in trace. Check trace path.");
    return 1;
  }

  VanetStats::Reset();
  VanetStats::SetTotalVehicles(vehicleCount);

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

  // Ensure unique Z offsets for vehicles to avoid zero-distance pairs in NYU model
  for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
  {
    Ptr<MobilityModel> mob = vehicleNodes.Get(i)->GetObject<MobilityModel>();
    if (mob)
    {
      mob->TraceConnectWithoutContext("CourseChange", MakeCallback(&ApplyVehicleZOffset));
      ApplyVehicleZOffset(mob);
    }
  }

  // RSU/gNB fixed positions
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

  // NR helper setup
  Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
  Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();
  Ptr<NrChannelHelper> channelHelper = CreateObject<NrChannelHelper>();
  nrHelper->SetEpcHelper(epcHelper);

  // Prefer low-latency scheduler
  nrHelper->SetSchedulerTypeId(TypeId::LookupByName("ns3::NrMacSchedulerTdmaRR"));

  // Use RLC UM for lower latency
  Config::SetDefault("ns3::NrRlcUm::MaxTxBufferSize", UintegerValue(999999999));
  Config::SetDefault("ns3::NrGnbRrc::EpsBearerToRlcMapping",
                     EnumValue(NrGnbRrc::RLC_UM_ALWAYS));

  // Beamforming and antennas
  Ptr<IdealBeamformingHelper> bfHelper = CreateObject<IdealBeamformingHelper>();
  nrHelper->SetBeamformingHelper(bfHelper);
  bfHelper->SetAttribute("BeamformingMethod", TypeIdValue(DirectPathBeamforming::GetTypeId()));

  nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(1));
  nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(1));
  nrHelper->SetUeAntennaAttribute("AntennaElement",
                                 PointerValue(CreateObject<IsotropicAntennaModel>()));

  nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
  nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
  nrHelper->SetGnbAntennaAttribute("AntennaElement",
                                  PointerValue(CreateObject<IsotropicAntennaModel>()));

  // Configure band and channel (NYUSIM)
  CcBwpCreator ccBwpCreator;
  CcBwpCreator::SimpleOperationBandConf bandConf(nrFreq, nrBw, 1);
  bandConf.m_numBwp = 1;
  OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);

  channelHelper->ConfigureFactories("UMa", "Default", "NYU");
  channelHelper->SetChannelConditionModelAttribute("UpdatePeriod",
                                                   TimeValue(MilliSeconds(100)));
  channelHelper->AssignChannelsToBands({band});
  auto allBwps = CcBwpCreator::GetAllBwps({band});

  nrHelper->SetGnbPhyAttribute("TxPower", DoubleValue(30.0));
  nrHelper->SetGnbPhyAttribute("Numerology", UintegerValue(nrMu));
  nrHelper->SetUePhyAttribute("TxPower", DoubleValue(23.0));

  NetDeviceContainer gnbDevs = nrHelper->InstallGnbDevice(rsuNodes, allBwps);
  NetDeviceContainer ueDevs = nrHelper->InstallUeDevice(vehicleNodes, allBwps);

  nrHelper->AttachToClosestGnb(ueDevs, gnbDevs);

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

  // Activate a bearer that matches all traffic so downlink packets are delivered to UEs.
  NrEpsBearer bearer(NrEpsBearer::NGBR_LOW_LAT_EMBB);
  bearer.arp.priorityLevel = 15;
  Ptr<NrEpcTft> tft = NrEpcTft::Default();
  for (auto it = ueDevs.Begin(); it != ueDevs.End(); ++it)
  {
    nrHelper->ActivateDedicatedEpsBearer(*it, bearer, tft);
  }

  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  // UE default route to PGW
  for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
  {
    Ptr<Ipv4StaticRouting> ueStaticRouting =
        ipv4RoutingHelper.GetStaticRouting(vehicleNodes.Get(i)->GetObject<Ipv4>());
    ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
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

  bool useRelay = true;
  if (v2vMode == "sidelink")
  {
    NS_LOG_WARN("NR sidelink/V2X not available in this 5G-LENA branch. Falling back to BS relay.");
    useRelay = true;
  }
  else if (v2vMode == "relay")
  {
    useRelay = true;
  }
  else
  {
    NS_LOG_WARN("Unknown v2vMode value, defaulting to relay.");
    useRelay = true;
  }

  Ptr<BsRelayApp> relayApp;
  if (useRelay)
  {
    relayApp = CreateObject<BsRelayApp>();
    relayApp->SetAttribute("EnablePbc", BooleanValue(enablePbc));
    relayApp->SetAttribute("PairingParams", StringValue(pbcParams));
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
  }

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
    vehicleApp->SetAttribute("TaPublicKeyPem", StringValue(taKeys.publicPem));
    vehicleApp->SetAttribute("UseBsRelay", BooleanValue(useRelay));
    vehicleApp->SetAttribute("RelayAddress", Ipv4AddressValue(relayAddress));
    vehicleNodes.Get(i)->AddApplication(vehicleApp);
    vehicleApp->SetStartTime(Seconds(0.5 + 0.01 * i));
  }

  std::ofstream statsFile(outCsv);
  statsFile << "time,infected_ratio,propagation_distance,verification_failures,"
               "avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,"
               "avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms\n";
  Simulator::Schedule(Seconds(1.0), &LogStats, &statsFile);

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

  statsFile.close();
  return 0;
}
