#include "pbc-crypto.h"

#include "ecc-crypto.h"
#include "vanet-power-model.h"
#include "vanet-message.h"

namespace ns3 {

PbcCrypto::PbcCrypto() = default;

PbcCrypto::~PbcCrypto()
{
#ifdef VANET_SECURITY_USE_PBC
  if (m_hasS)
  {
    element_clear(m_s);
  }
  if (m_hasT)
  {
    element_clear(m_t);
  }
  if (m_hasPpub)
  {
    element_clear(m_Ppub);
  }
  if (m_hasTpub)
  {
    element_clear(m_Tpub);
  }
  if (m_hasP)
  {
    element_clear(m_P);
  }
  if (m_initialized)
  {
    pairing_clear(m_pairing);
  }
#endif
}

bool
PbcCrypto::Init(const std::string& pairingParams)
{
#ifdef VANET_SECURITY_USE_PBC
  if (m_initialized)
  {
    return true;
  }
  if (pairingParams.empty())
  {
    return false;
  }

  pairing_init_set_buf(m_pairing, pairingParams.data(), pairingParams.size());
  m_initialized = true;

  element_init_G1(m_P, m_pairing);
  const char kGeneratorSeed[] = "VANET_PBC_GENERATOR_SEED_V1";
  element_from_hash(m_P,
                    const_cast<void*>(static_cast<const void*>(kGeneratorSeed)),
                    static_cast<int>(sizeof(kGeneratorSeed) - 1));
  m_hasP = true;
  return true;
#else
  (void)pairingParams;
  return false;
#endif
}

bool
PbcCrypto::SetupKgc()
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP)
  {
    return false;
  }
  if (m_hasS && m_hasPpub)
  {
    return true;
  }

  if (!m_hasS)
  {
    element_init_Zr(m_s, m_pairing);
    element_random(m_s);
    m_hasS = true;
  }

  if (!m_hasPpub)
  {
    element_init_G1(m_Ppub, m_pairing);
    m_hasPpub = true;
  }
  element_mul_zn(m_Ppub, m_P, m_s);
  return true;
#else
  return false;
#endif
}

bool
PbcCrypto::SetupTa()
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP)
  {
    return false;
  }
  if (m_hasT && m_hasTpub)
  {
    return true;
  }

  if (!m_hasT)
  {
    element_init_Zr(m_t, m_pairing);
    element_random(m_t);
    m_hasT = true;
  }

  if (!m_hasTpub)
  {
    element_init_G1(m_Tpub, m_pairing);
    m_hasTpub = true;
  }
  element_mul_zn(m_Tpub, m_P, m_t);
  return true;
#else
  return false;
#endif
}

bool
PbcCrypto::SetPpubBytes(const std::vector<uint8_t>& ppubBytes)
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP || ppubBytes.empty())
  {
    return false;
  }

  if (!m_hasPpub)
  {
    element_init_G1(m_Ppub, m_pairing);
    m_hasPpub = true;
  }
  element_from_bytes(
      m_Ppub,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(ppubBytes.data())));
  return true;
#else
  (void)ppubBytes;
  return false;
#endif
}

bool
PbcCrypto::GeneratePid1(std::vector<uint8_t>& pid1Bytes, std::vector<uint8_t>& diBytes)
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP)
  {
    return false;
  }

  element_t di;
  element_t pid1;
  element_init_Zr(di, m_pairing);
  element_init_G1(pid1, m_pairing);
  element_random(di);
  element_mul_zn(pid1, m_P, di);

  bool ok = EncodeElement(pid1, pid1Bytes) && EncodeElement(di, diBytes);
  element_clear(pid1);
  element_clear(di);
  return ok;
#else
  pid1Bytes.clear();
  diBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::GenerateVerificationKey(std::vector<uint8_t>& xiBytes, std::vector<uint8_t>& qiBytes)
{
  VanetPowerModel::ScopedTimer timer("pbc_full_key", "vehicle");
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP)
  {
    return false;
  }

  element_t xi;
  element_t qi;
  element_init_Zr(xi, m_pairing);
  element_init_G1(qi, m_pairing);
  element_random(xi);
  element_mul_zn(qi, m_P, xi);

  bool ok = EncodeElement(xi, xiBytes) && EncodeElement(qi, qiBytes);
  element_clear(qi);
  element_clear(xi);
  return ok;
#else
  xiBytes.clear();
  qiBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::ComputePid2(uint32_t nodeId,
                       const std::vector<uint8_t>& pid1Bytes,
                       std::vector<uint8_t>& pid2Bytes)
{
  VanetPowerModel::ScopedTimer timer("pbc_pid2", "ta");
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasT || !m_hasTpub || pid1Bytes.empty())
  {
    return false;
  }
  if (pid1Bytes.size() != GetG1BytesLength())
  {
    return false;
  }

  element_t pid1;
  element_t q;
  element_init_G1(pid1, m_pairing);
  element_init_G1(q, m_pairing);
  element_from_bytes(
      pid1,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(pid1Bytes.data())));
  element_mul_zn(q, pid1, m_t);

  std::vector<uint8_t> qBytes;
  std::vector<uint8_t> tpubBytes;
  bool ok = EncodeElement(q, qBytes) && EncodeElement(m_Tpub, tpubBytes);

  element_clear(q);
  element_clear(pid1);
  if (!ok)
  {
    return false;
  }

  std::vector<uint8_t> hashInput;
  hashInput.reserve(qBytes.size() + tpubBytes.size());
  hashInput.insert(hashInput.end(), qBytes.begin(), qBytes.end());
  hashInput.insert(hashInput.end(), tpubBytes.begin(), tpubBytes.end());

  std::vector<uint8_t> h0 = EccCrypto::Sha256(hashInput.data(), hashInput.size());
  if (h0.size() < 4)
  {
    return false;
  }

  const uint8_t idBytes[4] = {static_cast<uint8_t>((nodeId >> 24) & 0xFF),
                              static_cast<uint8_t>((nodeId >> 16) & 0xFF),
                              static_cast<uint8_t>((nodeId >> 8) & 0xFF),
                              static_cast<uint8_t>(nodeId & 0xFF)};
  pid2Bytes.resize(4);
  for (size_t i = 0; i < 4; ++i)
  {
    pid2Bytes[i] = static_cast<uint8_t>(idBytes[i] ^ h0[i]);
  }
  return true;
#else
  (void)nodeId;
  (void)pid1Bytes;
  pid2Bytes.clear();
  return false;
#endif
}

bool
PbcCrypto::ComputePartialKey(const std::vector<uint8_t>& pid1Bytes,
                             const std::vector<uint8_t>& pid2Bytes,
                             uint64_t tiUs,
                             std::vector<uint8_t>& siBytes)
{
  VanetPowerModel::ScopedTimer timer("pbc_partial_key", "kgc");
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasS || !m_hasPpub || pid1Bytes.empty() || pid2Bytes.empty())
  {
    return false;
  }

  std::vector<uint8_t> pidBytes;
  if (!EncodePid(pid1Bytes, pid2Bytes, tiUs, pidBytes))
  {
    return false;
  }

  std::vector<uint8_t> piBytes;
  if (!ComputePi(pidBytes, piBytes))
  {
    return false;
  }

  element_t pi;
  element_t si;
  element_init_G1(pi, m_pairing);
  element_init_G1(si, m_pairing);
  element_from_bytes(
      pi,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(piBytes.data())));
  element_mul_zn(si, pi, m_s);

  bool ok = EncodeElement(si, siBytes);
  element_clear(si);
  element_clear(pi);
  return ok;
#else
  (void)pid1Bytes;
  (void)pid2Bytes;
  (void)tiUs;
  siBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::EncodePid(const std::vector<uint8_t>& pid1Bytes,
                     const std::vector<uint8_t>& pid2Bytes,
                     uint64_t tiUs,
                     std::vector<uint8_t>& pidBytes)
{
  if (pid1Bytes.empty() || pid2Bytes.size() != 4)
  {
    pidBytes.clear();
    return false;
  }

  pidBytes.clear();
  WriteUint16(pidBytes, static_cast<uint16_t>(pid1Bytes.size()));
  WriteBytes(pidBytes, pid1Bytes);
  WriteUint16(pidBytes, static_cast<uint16_t>(pid2Bytes.size()));
  WriteBytes(pidBytes, pid2Bytes);
  WriteUint64(pidBytes, tiUs);
  return true;
}

bool
PbcCrypto::ComputePi(const std::vector<uint8_t>& pidBytes, std::vector<uint8_t>& piBytes)
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasPpub || pidBytes.empty())
  {
    return false;
  }

  std::vector<uint8_t> ppubBytes = GetPpubBytes();
  if (ppubBytes.empty())
  {
    return false;
  }

  std::vector<uint8_t> input;
  input.reserve(pidBytes.size() + ppubBytes.size());
  input.insert(input.end(), pidBytes.begin(), pidBytes.end());
  input.insert(input.end(), ppubBytes.begin(), ppubBytes.end());
  return HashToG1(input, piBytes);
#else
  (void)pidBytes;
  piBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::ComputeX(const std::vector<uint8_t>& thetaBytes, std::vector<uint8_t>& xBytes)
{
  return HashToG1(thetaBytes, xBytes);
}

bool
PbcCrypto::ComputeRi(const std::vector<uint8_t>& thetaBytes,
                     const std::vector<uint8_t>& messageBytes,
                     const std::vector<uint8_t>& pidBytes,
                     const std::vector<uint8_t>& qiBytes,
                     const std::vector<uint8_t>& wiBytes,
                     std::vector<uint8_t>& riBytes)
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || thetaBytes.empty() || pidBytes.empty() || qiBytes.empty() || wiBytes.empty())
  {
    return false;
  }

  std::vector<uint8_t> input;
  input.reserve(thetaBytes.size() + messageBytes.size() + pidBytes.size() + qiBytes.size() +
                wiBytes.size());
  input.insert(input.end(), thetaBytes.begin(), thetaBytes.end());
  input.insert(input.end(), messageBytes.begin(), messageBytes.end());
  input.insert(input.end(), pidBytes.begin(), pidBytes.end());
  input.insert(input.end(), qiBytes.begin(), qiBytes.end());
  input.insert(input.end(), wiBytes.begin(), wiBytes.end());
  return HashToG1(input, riBytes);
#else
  (void)thetaBytes;
  (void)messageBytes;
  (void)pidBytes;
  (void)qiBytes;
  (void)wiBytes;
  riBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::SignMessage(const std::vector<uint8_t>& siBytes,
                       const std::vector<uint8_t>& xiBytes,
                       const std::vector<uint8_t>& pidBytes,
                       const std::vector<uint8_t>& thetaBytes,
                       const std::vector<uint8_t>& messageBytes,
                       std::vector<uint8_t>& wiBytes,
                       std::vector<uint8_t>& psiBytes)
{
  VanetPowerModel::ScopedTimer timer("pbc_sign", "vehicle");
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP || siBytes.empty() || xiBytes.empty() || pidBytes.empty() ||
      thetaBytes.empty())
  {
    return false;
  }

  element_t si;
  element_t xi;
  element_t qi;
  element_t wi;
  element_t wiPoint;
  element_t x;
  element_t ri;
  element_t xiX;
  element_t wiRi;
  element_t psi;

  element_init_G1(si, m_pairing);
  element_init_Zr(xi, m_pairing);
  element_init_G1(qi, m_pairing);
  element_init_Zr(wi, m_pairing);
  element_init_G1(wiPoint, m_pairing);
  element_init_G1(x, m_pairing);
  element_init_G1(ri, m_pairing);
  element_init_G1(xiX, m_pairing);
  element_init_G1(wiRi, m_pairing);
  element_init_G1(psi, m_pairing);

  element_from_bytes(
      si,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(siBytes.data())));
  element_from_bytes(
      xi,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(xiBytes.data())));
  element_mul_zn(qi, m_P, xi);

  std::vector<uint8_t> qiBytes;
  if (!EncodeElement(qi, qiBytes))
  {
    element_clear(psi);
    element_clear(wiRi);
    element_clear(xiX);
    element_clear(ri);
    element_clear(x);
    element_clear(wiPoint);
    element_clear(wi);
    element_clear(qi);
    element_clear(xi);
    element_clear(si);
    return false;
  }

  element_random(wi);
  element_mul_zn(wiPoint, m_P, wi);
  if (!EncodeElement(wiPoint, wiBytes))
  {
    element_clear(psi);
    element_clear(wiRi);
    element_clear(xiX);
    element_clear(ri);
    element_clear(x);
    element_clear(wiPoint);
    element_clear(wi);
    element_clear(qi);
    element_clear(xi);
    element_clear(si);
    return false;
  }

  std::vector<uint8_t> xBytes;
  std::vector<uint8_t> riBytes;
  bool ok = ComputeX(thetaBytes, xBytes) &&
            ComputeRi(thetaBytes, messageBytes, pidBytes, qiBytes, wiBytes, riBytes);
  if (ok)
  {
    element_from_bytes(
        x, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(xBytes.data())));
    element_from_bytes(
        ri, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(riBytes.data())));
    element_mul_zn(xiX, x, xi);
    element_mul_zn(wiRi, ri, wi);
    element_set(psi, si);
    element_add(psi, psi, xiX);
    element_add(psi, psi, wiRi);
    ok = EncodeElement(psi, psiBytes);
  }

  element_clear(psi);
  element_clear(wiRi);
  element_clear(xiX);
  element_clear(ri);
  element_clear(x);
  element_clear(wiPoint);
  element_clear(wi);
  element_clear(qi);
  element_clear(xi);
  element_clear(si);
  return ok;
#else
  (void)siBytes;
  (void)xiBytes;
  (void)pidBytes;
  (void)thetaBytes;
  (void)messageBytes;
  wiBytes.clear();
  psiBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::AggregatePsi(const std::vector<std::vector<uint8_t>>& psiList,
                        std::vector<uint8_t>& aggregatePsiBytes)
{
  VanetPowerModel::ScopedTimer timer("pbc_aggregate", "bs_relay");
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP || psiList.empty())
  {
    return false;
  }

  element_t sum;
  element_init_G1(sum, m_pairing);
  element_set0(sum);

  bool ok = true;
  for (const auto& psiBytes : psiList)
  {
    if (psiBytes.size() != GetG1BytesLength())
    {
      ok = false;
      break;
    }

    element_t psi;
    element_init_G1(psi, m_pairing);
    element_from_bytes(
        psi,
        const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(psiBytes.data())));
    element_add(sum, sum, psi);
    element_clear(psi);
  }

  if (ok)
  {
    ok = EncodeElement(sum, aggregatePsiBytes);
  }
  element_clear(sum);
  return ok;
#else
  (void)psiList;
  aggregatePsiBytes.clear();
  return false;
#endif
}

bool
PbcCrypto::VerifyAggregate(const std::vector<std::vector<uint8_t>>& pidList,
                           const std::vector<std::vector<uint8_t>>& qiList,
                           const std::vector<std::vector<uint8_t>>& wiList,
                           const std::vector<std::vector<uint8_t>>& messageList,
                           const std::vector<uint8_t>& thetaBytes,
                           const std::vector<uint8_t>& aggregatePsiBytes)
{
  VanetPowerModel::ScopedTimer timer("pbc_verify_aggregate", "bs_relay");
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || !m_hasP || !m_hasPpub || pidList.empty() || thetaBytes.empty() ||
      aggregatePsiBytes.empty())
  {
    return false;
  }
  if (pidList.size() != qiList.size() || pidList.size() != wiList.size() ||
      pidList.size() != messageList.size())
  {
    return false;
  }
  if (aggregatePsiBytes.size() != GetG1BytesLength())
  {
    return false;
  }

  std::vector<uint8_t> xBytes;
  if (!ComputeX(thetaBytes, xBytes))
  {
    return false;
  }

  element_t aggregatePsi;
  element_t x;
  element_t sumPi;
  element_t sumQi;
  element_t left;
  element_t right;
  element_t pairPpubPi;
  element_t pairXQi;
  element_t pairRiWi;
  element_t productRiWi;

  element_init_G1(aggregatePsi, m_pairing);
  element_init_G1(x, m_pairing);
  element_init_G1(sumPi, m_pairing);
  element_init_G1(sumQi, m_pairing);
  element_init_GT(left, m_pairing);
  element_init_GT(right, m_pairing);
  element_init_GT(pairPpubPi, m_pairing);
  element_init_GT(pairXQi, m_pairing);
  element_init_GT(pairRiWi, m_pairing);
  element_init_GT(productRiWi, m_pairing);

  element_set0(sumPi);
  element_set0(sumQi);
  element_set1(productRiWi);
  element_from_bytes(aggregatePsi,
                     const_cast<unsigned char*>(
                         reinterpret_cast<const unsigned char*>(aggregatePsiBytes.data())));
  element_from_bytes(
      x, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(xBytes.data())));

  bool ok = true;
  for (size_t i = 0; i < pidList.size() && ok; ++i)
  {
    if (qiList[i].size() != GetG1BytesLength() || wiList[i].size() != GetG1BytesLength())
    {
      ok = false;
      break;
    }

    std::vector<uint8_t> piBytes;
    std::vector<uint8_t> riBytes;
    ok = ComputePi(pidList[i], piBytes) &&
         ComputeRi(thetaBytes, messageList[i], pidList[i], qiList[i], wiList[i], riBytes);
    if (!ok)
    {
      break;
    }

    element_t pi;
    element_t qi;
    element_t wi;
    element_t ri;
    element_init_G1(pi, m_pairing);
    element_init_G1(qi, m_pairing);
    element_init_G1(wi, m_pairing);
    element_init_G1(ri, m_pairing);

    element_from_bytes(
        pi, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(piBytes.data())));
    element_from_bytes(
        qi, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(qiList[i].data())));
    element_from_bytes(
        wi, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(wiList[i].data())));
    element_from_bytes(
        ri, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(riBytes.data())));

    element_add(sumPi, sumPi, pi);
    element_add(sumQi, sumQi, qi);
    pairing_apply(pairRiWi, ri, wi, m_pairing);
    element_mul(productRiWi, productRiWi, pairRiWi);

    element_clear(ri);
    element_clear(wi);
    element_clear(qi);
    element_clear(pi);
  }

  if (ok)
  {
    pairing_apply(left, aggregatePsi, m_P, m_pairing);
    pairing_apply(pairPpubPi, m_Ppub, sumPi, m_pairing);
    pairing_apply(pairXQi, x, sumQi, m_pairing);
    element_set(right, pairPpubPi);
    element_mul(right, right, pairXQi);
    element_mul(right, right, productRiWi);
    ok = (element_cmp(left, right) == 0);
  }

  element_clear(productRiWi);
  element_clear(pairRiWi);
  element_clear(pairXQi);
  element_clear(pairPpubPi);
  element_clear(right);
  element_clear(left);
  element_clear(sumQi);
  element_clear(sumPi);
  element_clear(x);
  element_clear(aggregatePsi);
  return ok;
#else
  (void)pidList;
  (void)qiList;
  (void)wiList;
  (void)messageList;
  (void)thetaBytes;
  (void)aggregatePsiBytes;
  return false;
#endif
}

#ifdef Sign
#undef Sign
#endif
#ifdef Verify
#undef Verify
#endif

bool PbcCrypto::Sign(const std::vector<uint8_t>& message, std::vector<uint8_t>& signature)
{
  (void)message;
  signature.clear();
#ifdef VANET_SECURITY_USE_PBC
  return true;
#else
  return false;
#endif
}

bool PbcCrypto::Verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature)
{
  (void)message;
  (void)signature;
#ifdef VANET_SECURITY_USE_PBC
  return true;
#else
  return false;
#endif
}

std::vector<uint8_t>
PbcCrypto::GetGeneratorBytes()
{
#ifdef VANET_SECURITY_USE_PBC
  std::vector<uint8_t> out;
  if (!m_hasP || !EncodeElement(m_P, out))
  {
    return {};
  }
  return out;
#else
  return {};
#endif
}

std::vector<uint8_t>
PbcCrypto::GetPpubBytes()
{
#ifdef VANET_SECURITY_USE_PBC
  std::vector<uint8_t> out;
  if (!m_hasPpub || !EncodeElement(m_Ppub, out))
  {
    return {};
  }
  return out;
#else
  return {};
#endif
}

std::vector<uint8_t>
PbcCrypto::GetTpubBytes()
{
#ifdef VANET_SECURITY_USE_PBC
  std::vector<uint8_t> out;
  if (!m_hasTpub || !EncodeElement(m_Tpub, out))
  {
    return {};
  }
  return out;
#else
  return {};
#endif
}

size_t
PbcCrypto::GetG1BytesLength() const
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_hasP)
  {
    return 0;
  }
  return element_length_in_bytes(const_cast<element_s*>(m_P));
#else
  return 0;
#endif
}

bool
PbcCrypto::HashToG1(const std::vector<uint8_t>& data, std::vector<uint8_t>& out)
{
#ifdef VANET_SECURITY_USE_PBC
  if (!m_initialized || data.empty())
  {
    return false;
  }
  element_t tmp;
  element_init_G1(tmp, m_pairing);
  element_from_hash(
      tmp, const_cast<void*>(static_cast<const void*>(data.data())), static_cast<int>(data.size()));
  bool ok = EncodeElement(tmp, out);
  element_clear(tmp);
  return ok;
#else
  (void)data;
  out.clear();
  return false;
#endif
}

bool
PbcCrypto::HashToG2(const std::vector<uint8_t>& data, std::vector<uint8_t>& out)
{
#ifdef VANET_SECURITY_USE_PBC
  return HashToG1(data, out);
#else
  (void)data;
  out.clear();
  return false;
#endif
}

#ifdef VANET_SECURITY_USE_PBC
bool
PbcCrypto::EncodeElement(const element_t& element, std::vector<uint8_t>& out)
{
  size_t len = element_length_in_bytes(const_cast<element_s*>(element));
  out.resize(len);
  element_to_bytes(out.data(), const_cast<element_s*>(element));
  return true;
}

bool
PbcCrypto::DecodeG1(const std::vector<uint8_t>& bytes, element_t& element)
{
  if (!m_initialized || !m_hasP || bytes.size() != GetG1BytesLength())
  {
    return false;
  }
  element_init_G1(element, m_pairing);
  element_from_bytes(
      element,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(bytes.data())));
  return true;
}

bool
PbcCrypto::DecodeZr(const std::vector<uint8_t>& bytes, element_t& element)
{
  if (!m_initialized || bytes.empty())
  {
    return false;
  }
  element_init_Zr(element, m_pairing);
  element_from_bytes(
      element,
      const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(bytes.data())));
  return true;
}

bool
PbcCrypto::PairElements(const element_t& lhs, const element_t& rhs, element_t& result)
{
  if (!m_initialized)
  {
    return false;
  }
  element_init_GT(result, m_pairing);
  pairing_apply(result,
                const_cast<element_s*>(lhs),
                const_cast<element_s*>(rhs),
                m_pairing);
  return true;
}
#endif

} // namespace ns3
