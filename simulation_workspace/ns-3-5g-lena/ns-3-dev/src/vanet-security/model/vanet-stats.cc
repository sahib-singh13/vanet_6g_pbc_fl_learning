#include "vanet-stats.h"

#include "ns3/log.h"

#include <cmath>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("VanetStats");

uint32_t VanetStats::s_totalVehicles = 0;
uint32_t VanetStats::s_infectedVehicles = 0;
double VanetStats::s_maxPropagationDistance = 0.0;
uint64_t VanetStats::s_verificationFailures = 0;
double VanetStats::s_v2vDelaySum = 0.0;
uint64_t VanetStats::s_v2vDelayCount = 0;
double VanetStats::s_v2iUplinkDelaySum = 0.0;
uint64_t VanetStats::s_v2iUplinkDelayCount = 0;
double VanetStats::s_v2iDownlinkDelaySum = 0.0;
uint64_t VanetStats::s_v2iDownlinkDelayCount = 0;
double VanetStats::s_v2iRttSum = 0.0;
uint64_t VanetStats::s_v2iRttCount = 0;
Vector VanetStats::s_sourcePosition = Vector(0.0, 0.0, 0.0);
bool VanetStats::s_sourceSet = false;
std::unordered_set<uint32_t> VanetStats::s_infectedIds;

void
VanetStats::Reset()
{
  s_totalVehicles = 0;
  s_infectedVehicles = 0;
  s_maxPropagationDistance = 0.0;
  s_verificationFailures = 0;
  s_v2vDelaySum = 0.0;
  s_v2vDelayCount = 0;
  s_v2iUplinkDelaySum = 0.0;
  s_v2iUplinkDelayCount = 0;
  s_v2iDownlinkDelaySum = 0.0;
  s_v2iDownlinkDelayCount = 0;
  s_v2iRttSum = 0.0;
  s_v2iRttCount = 0;
  s_sourcePosition = Vector(0.0, 0.0, 0.0);
  s_sourceSet = false;
  s_infectedIds.clear();
}

void
VanetStats::SetTotalVehicles(uint32_t total)
{
  s_totalVehicles = total;
}

void
VanetStats::SetSourcePosition(const Vector& position)
{
  s_sourcePosition = position;
  s_sourceSet = true;
}

bool
VanetStats::HasSource()
{
  return s_sourceSet;
}

void
VanetStats::MarkInfected(uint32_t nodeId, const Vector& position)
{
  if (s_infectedIds.find(nodeId) != s_infectedIds.end())
  {
    return;
  }
  s_infectedIds.insert(nodeId);
  s_infectedVehicles = static_cast<uint32_t>(s_infectedIds.size());

  if (s_sourceSet)
  {
    double dist = std::abs(position.x - s_sourcePosition.x);
    if (dist > s_maxPropagationDistance)
    {
      s_maxPropagationDistance = dist;
    }
  }
}

void
VanetStats::RecordVerificationFailure()
{
  ++s_verificationFailures;
}

void
VanetStats::RecordV2vDelay(double seconds)
{
  if (seconds < 0.0)
  {
    return;
  }
  s_v2vDelaySum += seconds;
  ++s_v2vDelayCount;
}

void
VanetStats::RecordV2iUplinkDelay(double seconds)
{
  if (seconds < 0.0)
  {
    return;
  }
  s_v2iUplinkDelaySum += seconds;
  ++s_v2iUplinkDelayCount;
}

void
VanetStats::RecordV2iDownlinkDelay(double seconds)
{
  if (seconds < 0.0)
  {
    return;
  }
  s_v2iDownlinkDelaySum += seconds;
  ++s_v2iDownlinkDelayCount;
}

void
VanetStats::RecordV2iRtt(double seconds)
{
  if (seconds < 0.0)
  {
    return;
  }
  s_v2iRttSum += seconds;
  ++s_v2iRttCount;
}

uint32_t
VanetStats::GetTotalVehicles()
{
  return s_totalVehicles;
}

uint32_t
VanetStats::GetInfectedVehicles()
{
  return s_infectedVehicles;
}

double
VanetStats::GetInfectedRatio()
{
  if (s_totalVehicles == 0)
  {
    return 0.0;
  }
  return static_cast<double>(s_infectedVehicles) / static_cast<double>(s_totalVehicles);
}

double
VanetStats::GetMaxPropagationDistance()
{
  return s_maxPropagationDistance;
}

uint64_t
VanetStats::GetVerificationFailures()
{
  return s_verificationFailures;
}

double
VanetStats::GetAvgV2vDelay()
{
  if (s_v2vDelayCount == 0)
  {
    return 0.0;
  }
  return s_v2vDelaySum / static_cast<double>(s_v2vDelayCount);
}

double
VanetStats::GetAvgV2iUplinkDelay()
{
  if (s_v2iUplinkDelayCount == 0)
  {
    return 0.0;
  }
  return s_v2iUplinkDelaySum / static_cast<double>(s_v2iUplinkDelayCount);
}

double
VanetStats::GetAvgV2iDownlinkDelay()
{
  if (s_v2iDownlinkDelayCount == 0)
  {
    return 0.0;
  }
  return s_v2iDownlinkDelaySum / static_cast<double>(s_v2iDownlinkDelayCount);
}

double
VanetStats::GetAvgV2iRtt()
{
  if (s_v2iRttCount == 0)
  {
    return 0.0;
  }
  return s_v2iRttSum / static_cast<double>(s_v2iRttCount);
}

} // namespace ns3
