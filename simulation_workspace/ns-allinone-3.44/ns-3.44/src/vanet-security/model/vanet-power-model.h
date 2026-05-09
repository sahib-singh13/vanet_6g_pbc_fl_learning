#ifndef VANET_POWER_MODEL_H
#define VANET_POWER_MODEL_H

#include <chrono>
#include <cstdint>
#include <string>

namespace ns3 {

class VanetPowerModel
{
public:
  struct Config
  {
    double vehicleCpuPowerW{2.5};
    double infraCpuPowerW{15.0};
    double vehicleRxPowerW{0.8};
    double infraRxPowerW{5.0};
    double vehicleTxPowerDbm{23.0};
    double infraTxPowerDbm{30.0};
    double effectiveRateMbps{100.0};
  };

  class ScopedTimer
  {
  public:
    ScopedTimer(std::string stage, std::string role);
    ~ScopedTimer();

    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;

  private:
    std::string m_stage;
    std::string m_role;
    std::chrono::steady_clock::time_point m_start;
  };

  static void Configure(const Config& config);
  static void Reset();

  static void RecordSecurityStage(const std::string& stage,
                                  const std::string& role,
                                  double latencySeconds);
  static void RecordCommunication(const std::string& category,
                                  const std::string& txRole,
                                  const std::string& rxRole,
                                  uint64_t bytes);

  static double GetSecurityEnergyJ();
  static double GetCommunicationEnergyJ();
  static double GetTotalEnergyJ();
  static double GetAvgSecurityPowerW(double elapsedSeconds);
  static double GetAvgCommunicationPowerW(double elapsedSeconds);
  static double GetAvgTotalPowerW(double elapsedSeconds);
  static double GetAvgSecurityLatency(const std::string& stage);

  static void WriteStageSummaryCsv(const std::string& path,
                                   const std::string& networkLabel,
                                   const std::string& securityMode);

private:
  static double DbmToW(double dbm);
  static double CpuPowerForRole(const std::string& role);
  static double TxPowerForRole(const std::string& role);
  static double RxPowerForRole(const std::string& role);
  static bool IsVehicleRole(const std::string& role);
};

} // namespace ns3

#endif // VANET_POWER_MODEL_H
