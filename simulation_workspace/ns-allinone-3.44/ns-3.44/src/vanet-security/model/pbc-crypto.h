#ifndef PBC_CRYPTO_H
#define PBC_CRYPTO_H

#ifdef VANET_SECURITY_USE_PBC
#include <pbc/pbc.h>
#endif

#include <string>
#include <cstdint>
#include <vector>

namespace ns3 {

class PbcCrypto
{
public:
  PbcCrypto();
  ~PbcCrypto();

  // Initialize PBC with pairing parameters. Returns false if not available.
  bool Init(const std::string &pairingParams);

  // Setup methods for KGC/TA. Return false if PBC is unavailable.
  bool SetupKgc();
  bool SetupTa();
  bool SetPpubBytes(const std::vector<uint8_t> &ppubBytes);

  // Generate PID1 = d * P and return PID1 bytes plus d bytes.
  bool GeneratePid1(std::vector<uint8_t> &pid1Bytes, std::vector<uint8_t> &diBytes);
  bool GenerateVerificationKey(std::vector<uint8_t> &xiBytes, std::vector<uint8_t> &qiBytes);

  // Compute PID2 for a given nodeId using TA secret t and PID1.
  bool ComputePid2(uint32_t nodeId,
                   const std::vector<uint8_t> &pid1Bytes,
                   std::vector<uint8_t> &pid2Bytes);

  // Compute partial private key S_i for KGC using PID and Ppub.
  bool ComputePartialKey(const std::vector<uint8_t> &pid1Bytes,
                         const std::vector<uint8_t> &pid2Bytes,
                         uint64_t tiUs,
                         std::vector<uint8_t> &siBytes);
  bool EncodePid(const std::vector<uint8_t> &pid1Bytes,
                 const std::vector<uint8_t> &pid2Bytes,
                 uint64_t tiUs,
                 std::vector<uint8_t> &pidBytes);
  bool ComputePi(const std::vector<uint8_t> &pidBytes, std::vector<uint8_t> &piBytes);
  bool ComputeX(const std::vector<uint8_t> &thetaBytes, std::vector<uint8_t> &xBytes);
  bool ComputeRi(const std::vector<uint8_t> &thetaBytes,
                 const std::vector<uint8_t> &messageBytes,
                 const std::vector<uint8_t> &pidBytes,
                 const std::vector<uint8_t> &qiBytes,
                 const std::vector<uint8_t> &wiBytes,
                 std::vector<uint8_t> &riBytes);
  bool SignMessage(const std::vector<uint8_t> &siBytes,
                   const std::vector<uint8_t> &xiBytes,
                   const std::vector<uint8_t> &pidBytes,
                   const std::vector<uint8_t> &thetaBytes,
                   const std::vector<uint8_t> &messageBytes,
                   std::vector<uint8_t> &wiBytes,
                   std::vector<uint8_t> &psiBytes);
  bool AggregatePsi(const std::vector<std::vector<uint8_t>> &psiList,
                    std::vector<uint8_t> &aggregatePsiBytes);
  bool VerifyAggregate(const std::vector<std::vector<uint8_t>> &pidList,
                       const std::vector<std::vector<uint8_t>> &qiList,
                       const std::vector<std::vector<uint8_t>> &wiList,
                       const std::vector<std::vector<uint8_t>> &messageList,
                       const std::vector<uint8_t> &thetaBytes,
                       const std::vector<uint8_t> &aggregatePsiBytes);

  // Stub signing API. Returns false when PBC is not enabled.
  bool Sign(const std::vector<uint8_t> &message, std::vector<uint8_t> &signature);

  // Stub verification API. Returns false when PBC is not enabled.
  bool Verify(const std::vector<uint8_t> &message, const std::vector<uint8_t> &signature);

  // Export public parameters as bytes (empty if not available).
  std::vector<uint8_t> GetGeneratorBytes();
  std::vector<uint8_t> GetPpubBytes();
  std::vector<uint8_t> GetTpubBytes();
  size_t GetG1BytesLength() const;

  // Hash helpers (Type A uses G1 for both groups).
  bool HashToG1(const std::vector<uint8_t> &data, std::vector<uint8_t> &out);
  bool HashToG2(const std::vector<uint8_t> &data, std::vector<uint8_t> &out);

private:
#ifdef VANET_SECURITY_USE_PBC
  bool EncodeElement(const element_t &element, std::vector<uint8_t> &out);
  bool DecodeG1(const std::vector<uint8_t> &bytes, element_t &element);
  bool DecodeZr(const std::vector<uint8_t> &bytes, element_t &element);
  bool PairElements(const element_t &lhs, const element_t &rhs, element_t &result);
  bool m_initialized{false};
  bool m_hasP{false};
  bool m_hasS{false};
  bool m_hasT{false};
  bool m_hasPpub{false};
  bool m_hasTpub{false};
  pairing_t m_pairing;
  element_t m_P;
  element_t m_s;
  element_t m_t;
  element_t m_Ppub;
  element_t m_Tpub;
#endif
};

} // namespace ns3

#endif // PBC_CRYPTO_H
