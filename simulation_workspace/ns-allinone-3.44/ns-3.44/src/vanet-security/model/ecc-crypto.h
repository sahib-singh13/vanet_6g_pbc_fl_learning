#ifndef ECC_CRYPTO_H
#define ECC_CRYPTO_H

#include <cstdint>
#include <string>
#include <vector>

namespace ns3 {

class EccCrypto
{
public:
  struct KeyPair
  {
    std::string publicPem;
    std::string privatePem;
  };

  static KeyPair GenerateKeyPair();
  static std::vector<uint8_t> Sign(const std::string& privatePem, const uint8_t* data, size_t len);
  static bool Verify(const std::string& publicPem,
                     const uint8_t* data,
                     size_t len,
                     const std::vector<uint8_t>& signature);
  static std::vector<uint8_t> Sha256(const uint8_t* data, size_t len);
};

} // namespace ns3

#endif // ECC_CRYPTO_H
