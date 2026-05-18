#ifndef FL_VANET_APPS_H
#define FL_VANET_APPS_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"

#include "vanet-message.h"

#ifdef VANET_SECURITY_USE_PBC
#include "pbc-crypto.h"
#endif

#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ns3 {

class FlVehicleApp : public Application
{
public:
  FlVehicleApp();
  ~FlVehicleApp() override;

  static TypeId GetTypeId();

  void SetGroupInfo(const std::vector<uint32_t>& vehicleIds,
                    const std::vector<uint32_t>& datasetSizes);
  void SetEccKeys(const std::string& publicKeyPem, const std::string& privateKeyPem);
  void SetPbcCredentials(const std::vector<uint8_t>& pid1,
                         const std::vector<uint8_t>& pid2,
                         uint64_t tiUs,
                         const std::vector<uint8_t>& partialKey,
                         const std::vector<uint8_t>& secretXi,
                         const std::vector<uint8_t>& publicQi);

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void HandleRead(Ptr<Socket> socket);
  void HandleModelPayload(const std::vector<uint8_t>& payload);
  std::vector<double> TrainLocalModel(uint32_t round, const std::vector<double>& globalModel);
  std::vector<double> BuildMask(uint32_t round, uint32_t dim) const;
  void SendUpdate(uint32_t round, const std::vector<double>& update);

  Ptr<Socket> m_socket;
  uint16_t m_listenPort{9402};
  Ipv4Address m_rsuAddress{"10.2.0.2"};
  uint16_t m_rsuPort{9401};

  uint32_t m_vehicleId{0};
  uint32_t m_datasetSize{1000};
  uint32_t m_modelDim{64};
  uint32_t m_localEpochs{1};
  double m_learningRate{0.01};
  bool m_enablePbc{false};
  bool m_enableMasking{true};
  std::string m_securityMode{"pbc"};
  std::string m_pairingParams;
  std::string m_statePrefix{"fl-round"};
  uint64_t m_pidValidityUs{300000000};

  std::vector<uint32_t> m_groupVehicleIds;
  std::vector<uint32_t> m_groupDatasetSizes;
  std::string m_publicKeyPem;
  std::string m_privateKeyPem;

  std::vector<uint8_t> m_pid1;
  std::vector<uint8_t> m_pid2;
  uint64_t m_pidTiUs{0};
  std::vector<uint8_t> m_partialKey;
  std::vector<uint8_t> m_secretXi;
  std::vector<uint8_t> m_publicQi;

#ifdef VANET_SECURITY_USE_PBC
  PbcCrypto m_pbc;
#endif
};

class FlRsuAggregatorApp : public Application
{
public:
  FlRsuAggregatorApp();
  ~FlRsuAggregatorApp() override;

  static TypeId GetTypeId();

  void SetVehicleAddresses(const std::vector<Ipv4Address>& addresses);
  void SetPpubBytes(const std::vector<uint8_t>& ppubBytes);

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  struct UpdateEntry
  {
    uint32_t vehicleId{0};
    uint32_t datasetSize{0};
    std::vector<double> update;
    std::vector<uint8_t> stateBytes;
    std::vector<uint8_t> pidBytes;
    std::vector<uint8_t> qiBytes;
    std::vector<uint8_t> wiBytes;
    std::vector<uint8_t> psiBytes;
    std::vector<uint8_t> messageBytes;
  };

  struct RoundState
  {
    uint32_t round{0};
    std::vector<double> globalModel;
    std::vector<UpdateEntry> updates;
    std::unordered_set<uint32_t> seenVehicles;
    uint32_t rejected{0};
  };

  void HandleRead(Ptr<Socket> socket);
  void HandleModelDownload(const VanetMessageHeader& header, const std::vector<uint8_t>& payload);
  void HandleVehicleUpdate(Ptr<Packet> packet, const Address& from);
  void TryFlushRound(uint32_t round);
  void SendAggregate(uint32_t round, const std::vector<double>& aggregate, uint32_t verified, uint32_t rejected, uint32_t totalDataset);

  Ptr<Socket> m_socket;
  uint16_t m_listenPort{9401};
  Ipv4Address m_bsAddress{"10.2.0.1"};
  uint16_t m_bsPort{9400};
  uint16_t m_vehiclePort{9402};

  uint32_t m_rsuId{0};
  uint32_t m_expectedUpdates{0};
  uint32_t m_modelDim{64};
  bool m_enablePbc{false};
  std::string m_securityMode{"pbc"};
  std::string m_pairingParams;
  uint64_t m_pidValidityUs{300000000};
  std::vector<Ipv4Address> m_vehicleAddresses;
  std::vector<uint8_t> m_ppubBytes;
  std::unordered_map<uint32_t, RoundState> m_rounds;

#ifdef VANET_SECURITY_USE_PBC
  PbcCrypto m_pbc;
#endif
};

class FlBsAggregatorApp : public Application
{
public:
  FlBsAggregatorApp();
  ~FlBsAggregatorApp() override;

  static TypeId GetTypeId();

  void SetRsuAddresses(const std::vector<Ipv4Address>& addresses);

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  struct RsuAggregate
  {
    uint32_t rsuId{0};
    uint32_t verified{0};
    uint32_t rejected{0};
    uint32_t datasetSize{0};
    std::vector<double> weights;
  };

  void StartRound();
  void HandleRead(Ptr<Socket> socket);
  void CompleteRound(uint32_t round);
  void WriteCsvHeader();
  void WriteCsvRow(uint32_t round, uint32_t verified, uint32_t rejected, uint32_t totalDataset);

  Ptr<Socket> m_socket;
  uint16_t m_listenPort{9400};
  uint16_t m_rsuPort{9401};
  std::vector<Ipv4Address> m_rsuAddresses;

  uint32_t m_rounds{20};
  uint32_t m_currentRound{0};
  uint32_t m_modelDim{64};
  uint32_t m_selectedVehicles{0};
  Time m_roundInterval{Seconds(1.0)};
  Time m_initialDelay{Seconds(3.0)};
  std::string m_flCsvPath{"results/fl/fl_metrics.csv"};
  std::string m_networkLabel{"5g_lte"};
  std::string m_securityMode{"pbc"};
  std::vector<double> m_globalModel;
  std::unordered_map<uint32_t, std::vector<RsuAggregate>> m_roundAggregates;
  std::unordered_map<uint32_t, std::unordered_set<uint32_t>> m_seenRsuAggregates;
  std::ofstream m_csv;
};

} // namespace ns3

#endif // FL_VANET_APPS_H
