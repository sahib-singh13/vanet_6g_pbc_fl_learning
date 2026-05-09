#ifndef VANET_STATS_H
#define VANET_STATS_H

#include "ns3/vector.h"

#include <cstdint>
#include <unordered_set>

namespace ns3 {

class VanetStats
{
public:
  static void Reset();
  static void SetTotalVehicles(uint32_t total);
  static void SetSourcePosition(const Vector& position);
  static bool HasSource();

  static void MarkInfected(uint32_t nodeId, const Vector& position);
  static void RecordVerificationFailure();
  static void RecordV2vDelay(double seconds);
  static void RecordV2iUplinkDelay(double seconds);
  static void RecordV2iDownlinkDelay(double seconds);
  static void RecordV2iRtt(double seconds);
  static void RecordRegistrationDelay(double seconds);
  static void RecordKgcRtt(double seconds);
  static void RecordTaRtt(double seconds);

  static uint32_t GetTotalVehicles();
  static uint32_t GetInfectedVehicles();
  static double GetInfectedRatio();
  static double GetMaxPropagationDistance();
  static uint64_t GetVerificationFailures();
  static double GetAvgV2vDelay();
  static double GetAvgV2iUplinkDelay();
  static double GetAvgV2iDownlinkDelay();
  static double GetAvgV2iRtt();
  static double GetAvgRegistrationDelay();
  static double GetAvgKgcRtt();
  static double GetAvgTaRtt();

private:
  static uint32_t s_totalVehicles;
  static uint32_t s_infectedVehicles;
  static double s_maxPropagationDistance;
  static uint64_t s_verificationFailures;
  static double s_v2vDelaySum;
  static uint64_t s_v2vDelayCount;
  static double s_v2iUplinkDelaySum;
  static uint64_t s_v2iUplinkDelayCount;
  static double s_v2iDownlinkDelaySum;
  static uint64_t s_v2iDownlinkDelayCount;
  static double s_v2iRttSum;
  static uint64_t s_v2iRttCount;
  static double s_registrationDelaySum;
  static uint64_t s_registrationDelayCount;
  static double s_kgcRttSum;
  static uint64_t s_kgcRttCount;
  static double s_taRttSum;
  static uint64_t s_taRttCount;
  static Vector s_sourcePosition;
  static bool s_sourceSet;
  static std::unordered_set<uint32_t> s_infectedIds;
};

} // namespace ns3

#endif // VANET_STATS_H
