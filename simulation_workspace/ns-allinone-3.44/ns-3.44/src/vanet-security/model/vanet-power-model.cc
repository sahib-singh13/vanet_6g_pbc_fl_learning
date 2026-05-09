#include "vanet-power-model.h"

#include "ns3/log.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <map>
#include <utility>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("VanetPowerModel");

namespace {

struct StageStats
{
  uint64_t count{0};
  double totalLatencySeconds{0.0};
  double totalEnergyJ{0.0};
};

VanetPowerModel::Config g_config;
std::map<std::pair<std::string, std::string>, StageStats> g_stageStats;
double g_securityEnergyJ = 0.0;
double g_communicationEnergyJ = 0.0;

} // namespace

VanetPowerModel::ScopedTimer::ScopedTimer(std::string stage, std::string role)
    : m_stage(std::move(stage)),
      m_role(std::move(role)),
      m_start(std::chrono::steady_clock::now())
{
}

VanetPowerModel::ScopedTimer::~ScopedTimer()
{
  const auto stop = std::chrono::steady_clock::now();
  const std::chrono::duration<double> elapsed = stop - m_start;
  VanetPowerModel::RecordSecurityStage(m_stage, m_role, elapsed.count());
}

void
VanetPowerModel::Configure(const Config& config)
{
  g_config = config;
  if (g_config.effectiveRateMbps <= 0.0)
  {
    NS_LOG_WARN("effectiveRateMbps must be positive; using 1 Mbps fallback");
    g_config.effectiveRateMbps = 1.0;
  }
}

void
VanetPowerModel::Reset()
{
  g_stageStats.clear();
  g_securityEnergyJ = 0.0;
  g_communicationEnergyJ = 0.0;
}

void
VanetPowerModel::RecordSecurityStage(const std::string& stage,
                                     const std::string& role,
                                     double latencySeconds)
{
  if (latencySeconds < 0.0)
  {
    return;
  }
  const double energyJ = latencySeconds * CpuPowerForRole(role);
  auto& stats = g_stageStats[{stage, role}];
  ++stats.count;
  stats.totalLatencySeconds += latencySeconds;
  stats.totalEnergyJ += energyJ;
  g_securityEnergyJ += energyJ;
}

void
VanetPowerModel::RecordCommunication(const std::string& category,
                                     const std::string& txRole,
                                     const std::string& rxRole,
                                     uint64_t bytes)
{
  if (bytes == 0)
  {
    return;
  }
  const double rateBps = std::max(1.0, g_config.effectiveRateMbps * 1e6);
  const double airtimeSeconds = (static_cast<double>(bytes) * 8.0) / rateBps;
  const double txEnergyJ = TxPowerForRole(txRole) * airtimeSeconds;
  const double rxEnergyJ = RxPowerForRole(rxRole) * airtimeSeconds;

  auto& txStats = g_stageStats[{"communication_tx", txRole + ":" + category}];
  ++txStats.count;
  txStats.totalLatencySeconds += airtimeSeconds;
  txStats.totalEnergyJ += txEnergyJ;

  auto& rxStats = g_stageStats[{"communication_rx", rxRole + ":" + category}];
  ++rxStats.count;
  rxStats.totalLatencySeconds += airtimeSeconds;
  rxStats.totalEnergyJ += rxEnergyJ;

  g_communicationEnergyJ += txEnergyJ + rxEnergyJ;
}

double
VanetPowerModel::GetSecurityEnergyJ()
{
  return g_securityEnergyJ;
}

double
VanetPowerModel::GetCommunicationEnergyJ()
{
  return g_communicationEnergyJ;
}

double
VanetPowerModel::GetTotalEnergyJ()
{
  return g_securityEnergyJ + g_communicationEnergyJ;
}

double
VanetPowerModel::GetAvgSecurityPowerW(double elapsedSeconds)
{
  return elapsedSeconds > 0.0 ? g_securityEnergyJ / elapsedSeconds : 0.0;
}

double
VanetPowerModel::GetAvgCommunicationPowerW(double elapsedSeconds)
{
  return elapsedSeconds > 0.0 ? g_communicationEnergyJ / elapsedSeconds : 0.0;
}

double
VanetPowerModel::GetAvgTotalPowerW(double elapsedSeconds)
{
  return elapsedSeconds > 0.0 ? GetTotalEnergyJ() / elapsedSeconds : 0.0;
}

double
VanetPowerModel::GetAvgSecurityLatency(const std::string& stage)
{
  double totalLatencySeconds = 0.0;
  uint64_t totalCount = 0;
  for (const auto& item : g_stageStats)
  {
    if (item.first.first == stage)
    {
      totalLatencySeconds += item.second.totalLatencySeconds;
      totalCount += item.second.count;
    }
  }
  return totalCount > 0 ? totalLatencySeconds / static_cast<double>(totalCount) : 0.0;
}

void
VanetPowerModel::WriteStageSummaryCsv(const std::string& path,
                                      const std::string& networkLabel,
                                      const std::string& securityMode)
{
  if (path.empty())
  {
    return;
  }
  std::ofstream stream(path);
  if (!stream.is_open())
  {
    NS_LOG_WARN("Failed to open stage summary CSV: " << path);
    return;
  }

  stream << "network_label,security_mode,stage,role,count,avg_latency_ms,"
            "total_latency_ms,total_energy_j,avg_energy_mj_per_op\n";
  stream << std::fixed << std::setprecision(9);
  for (const auto& item : g_stageStats)
  {
    const auto& stage = item.first.first;
    const auto& role = item.first.second;
    const auto& stats = item.second;
    const double avgLatencyMs = stats.count > 0
                                    ? (stats.totalLatencySeconds * 1000.0) /
                                          static_cast<double>(stats.count)
                                    : 0.0;
    const double totalLatencyMs = stats.totalLatencySeconds * 1000.0;
    const double avgEnergyMj = stats.count > 0
                                   ? (stats.totalEnergyJ * 1000.0) /
                                         static_cast<double>(stats.count)
                                   : 0.0;
    stream << networkLabel << ',' << securityMode << ',' << stage << ',' << role << ','
           << stats.count << ',' << avgLatencyMs << ',' << totalLatencyMs << ','
           << stats.totalEnergyJ << ',' << avgEnergyMj << '\n';
  }
}

double
VanetPowerModel::DbmToW(double dbm)
{
  return std::pow(10.0, (dbm - 30.0) / 10.0);
}

double
VanetPowerModel::CpuPowerForRole(const std::string& role)
{
  return IsVehicleRole(role) ? g_config.vehicleCpuPowerW : g_config.infraCpuPowerW;
}

double
VanetPowerModel::TxPowerForRole(const std::string& role)
{
  return DbmToW(IsVehicleRole(role) ? g_config.vehicleTxPowerDbm : g_config.infraTxPowerDbm);
}

double
VanetPowerModel::RxPowerForRole(const std::string& role)
{
  return IsVehicleRole(role) ? g_config.vehicleRxPowerW : g_config.infraRxPowerW;
}

bool
VanetPowerModel::IsVehicleRole(const std::string& role)
{
  return role.find("vehicle") != std::string::npos;
}

} // namespace ns3
