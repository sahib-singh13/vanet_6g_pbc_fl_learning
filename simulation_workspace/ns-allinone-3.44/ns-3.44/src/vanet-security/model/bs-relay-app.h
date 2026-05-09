#ifndef BS_RELAY_APP_H
#define BS_RELAY_APP_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ipv4-address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"

#ifdef VANET_SECURITY_USE_PBC
#include "pbc-crypto.h"
#endif

#include <string>
#include <unordered_map>
#include <vector>

namespace ns3 {

class BsRelayApp : public Application
{
public:
  BsRelayApp();
  ~BsRelayApp() override;

  static TypeId GetTypeId();

  void SetUeAddresses(const std::vector<Ipv4Address>& addresses);
  void SetPpubBytes(const std::vector<uint8_t>& ppubBytes);

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  struct BatchEntry
  {
    Ptr<Packet> packet;
    Ipv4Address srcAddr;
    std::vector<uint8_t> stateBytes;
    std::vector<uint8_t> pidBytes;
    std::vector<uint8_t> qiBytes;
    std::vector<uint8_t> wiBytes;
    std::vector<uint8_t> psiBytes;
    std::vector<uint8_t> messageBytes;
  };

  struct BatchState
  {
    std::vector<BatchEntry> entries;
    EventId flushEvent;
  };

  void HandleRead(Ptr<Socket> socket);
  void ForwardPacket(Ptr<Packet> packet, Ipv4Address srcAddr);
  void FlushBatch(const std::string& batchKey);

  Ptr<Socket> m_socket;
  uint16_t m_port{9200};
  std::vector<Ipv4Address> m_ueAddresses;
  bool m_enablePbc{false};
  std::string m_pairingParams;
  uint64_t m_aggregationWindowMs{50};
  uint32_t m_maxBatchSize{32};
  uint64_t m_pidValidityUs{30000000};
  std::vector<uint8_t> m_ppubBytes;
  std::unordered_map<std::string, BatchState> m_batches;

#ifdef VANET_SECURITY_USE_PBC
  PbcCrypto m_pbc;
#endif
};

} // namespace ns3

#endif // BS_RELAY_APP_H
