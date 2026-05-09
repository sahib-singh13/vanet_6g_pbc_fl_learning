#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"

#include "ns3/vanet-security-module.h"

#include <algorithm>
#include <fstream>
#include <regex>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VanetSecuritySumo");

namespace {

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
  *stream << time << "," << VanetStats::GetInfectedRatio() << ","
          << VanetStats::GetMaxPropagationDistance() << ","
          << VanetStats::GetVerificationFailures() << ","
          << v2vMs << "," << v2iUpMs << "," << v2iDownMs << "," << v2iRttMs
          << "," << regMs << "," << kgcMs << "," << taMs
          << "\n";
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
  double commRange = 300.0;
  uint32_t rsuCount = 2;
  std::string outCsv = "vanet-security-metrics-wifi.csv";

  CommandLine cmd;
  cmd.AddValue("trace", "Path to SUMO ns-2 mobility trace", tracePath);
  cmd.AddValue("simTime", "Simulation time (s)", simTime);
  cmd.AddValue("msgInterval", "Source message interval (s)", msgInterval);
  cmd.AddValue("verifySignatures", "Enable ECDSA verification", verifySignatures);
  cmd.AddValue("commRange", "Communication range (m)", commRange);
  cmd.AddValue("rsuCount", "Number of RSUs", rsuCount);
  cmd.AddValue("outCsv", "Output CSV path", outCsv);
  cmd.Parse(argc, argv);

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

  // Mobility for vehicles from SUMO trace
  Ns2MobilityHelper ns2(tracePath);
  ns2.Install();

  // RSU fixed positions
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
    rsuPositions->Add(Vector(minX + span * 0.5, baseY, 0.0));
  }
  else
  {
    for (uint32_t i = 0; i < rsuCount; ++i)
    {
      double frac = static_cast<double>(i) / static_cast<double>(rsuCount - 1);
      rsuPositions->Add(Vector(minX + span * frac, baseY, 0.0));
    }
  }
  rsuMobility.SetPositionAllocator(rsuPositions);
  rsuMobility.Install(rsuNodes);

  // P2P links: BS-TA and BS-KGC
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer bsTaDevices = p2p.Install(bsNode.Get(0), taNode.Get(0));
  NetDeviceContainer bsKgcDevices = p2p.Install(bsNode.Get(0), kgcNode.Get(0));

  Ipv4AddressHelper p2pAddr;
  p2pAddr.SetBase("10.3.0.0", "255.255.255.0");
  Ipv4InterfaceContainer bsTaIfs = p2pAddr.Assign(bsTaDevices);
  p2pAddr.SetBase("10.4.0.0", "255.255.255.0");
  Ipv4InterfaceContainer bsKgcIfs = p2pAddr.Assign(bsKgcDevices);

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

  // 802.11p WiFi for RSUs and vehicles
  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  channel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange", DoubleValue(commRange));
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211p);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode",
                               StringValue("OfdmRate6MbpsBW10MHz"),
                               "ControlMode",
                               StringValue("OfdmRate6MbpsBW10MHz"));

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NodeContainer wifiNodes;
  wifiNodes.Add(rsuNodes);
  wifiNodes.Add(vehicleNodes);

  NetDeviceContainer wifiDevices = wifi.Install(phy, mac, wifiNodes);

  Ipv4AddressHelper wifiAddr;
  wifiAddr.SetBase("10.1.0.0", "255.255.0.0");
  Ipv4InterfaceContainer wifiIfs = wifiAddr.Assign(wifiDevices);

  // All traffic is within directly connected subnets; no global routing needed.

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
  taApp->SetAttribute("EnablePbc", BooleanValue(true));
  taApp->SetAttribute("PairingParams", StringValue(pbcParams));
  taNode.Get(0)->AddApplication(taApp);
  taApp->SetStartTime(Seconds(0.1));

  // Install KGC app
  Ptr<KgcApp> kgcApp = CreateObject<KgcApp>();
  kgcApp->SetAttribute("EnablePbc", BooleanValue(true));
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

  // Vehicle apps
  Ipv4Address rsuWifiAddress = wifiIfs.GetAddress(0); // first RSU
  for (uint32_t i = 0; i < vehicleCount; ++i)
  {
    Ptr<VehicleApp> vehicleApp = CreateObject<VehicleApp>();
    vehicleApp->SetAttribute("RsuAddress", Ipv4AddressValue(rsuWifiAddress));
    vehicleApp->SetAttribute("MessageInterval", TimeValue(Seconds(msgInterval)));
    vehicleApp->SetAttribute("VerifySignatures", BooleanValue(verifySignatures));
    vehicleApp->SetAttribute("EnablePbc", BooleanValue(true));
    vehicleApp->SetAttribute("PairingParams", StringValue(pbcParams));
    vehicleApp->SetAttribute("TaPublicKeyPem", StringValue(taKeys.publicPem));
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
