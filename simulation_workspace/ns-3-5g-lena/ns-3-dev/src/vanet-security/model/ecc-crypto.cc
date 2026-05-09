#include "ecc-crypto.h"

#include "ns3/log.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("EccCrypto");

namespace {

std::string
BioToString(BIO* bio)
{
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  if (len <= 0 || data == nullptr)
  {
    return std::string();
  }
  return std::string(data, static_cast<size_t>(len));
}

EVP_PKEY*
LoadPrivateKey(const std::string& pem)
{
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio)
  {
    return nullptr;
  }
  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return pkey;
}

EVP_PKEY*
LoadPublicKey(const std::string& pem)
{
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio)
  {
    return nullptr;
  }
  EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return pkey;
}

} // namespace

EccCrypto::KeyPair
EccCrypto::GenerateKeyPair()
{
  KeyPair keys;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (!ctx)
  {
    NS_LOG_ERROR("Failed to create EVP_PKEY_CTX");
    return keys;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    NS_LOG_ERROR("Failed to init keygen");
    return keys;
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    NS_LOG_ERROR("Failed to set curve");
    return keys;
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    NS_LOG_ERROR("Failed to generate keypair");
    return keys;
  }

  BIO* privBio = BIO_new(BIO_s_mem());
  BIO* pubBio = BIO_new(BIO_s_mem());
  if (!privBio || !pubBio)
  {
    if (privBio)
    {
      BIO_free(privBio);
    }
    if (pubBio)
    {
      BIO_free(pubBio);
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    NS_LOG_ERROR("Failed to allocate BIO");
    return keys;
  }

  if (PEM_write_bio_PrivateKey(privBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0)
  {
    NS_LOG_ERROR("Failed to write private key");
  }
  if (PEM_write_bio_PUBKEY(pubBio, pkey) <= 0)
  {
    NS_LOG_ERROR("Failed to write public key");
  }

  keys.privatePem = BioToString(privBio);
  keys.publicPem = BioToString(pubBio);

  BIO_free(privBio);
  BIO_free(pubBio);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);

  return keys;
}

std::vector<uint8_t>
EccCrypto::Sign(const std::string& privatePem, const uint8_t* data, size_t len)
{
  std::vector<uint8_t> signature;
  EVP_PKEY* pkey = LoadPrivateKey(privatePem);
  if (!pkey)
  {
    NS_LOG_ERROR("Failed to load private key");
    return signature;
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx)
  {
    EVP_PKEY_free(pkey);
    return signature;
  }

  if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
  {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return signature;
  }

  if (EVP_DigestSignUpdate(mdctx, data, len) <= 0)
  {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return signature;
  }

  size_t sigLen = 0;
  if (EVP_DigestSignFinal(mdctx, nullptr, &sigLen) <= 0)
  {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return signature;
  }

  signature.resize(sigLen);
  if (EVP_DigestSignFinal(mdctx, signature.data(), &sigLen) <= 0)
  {
    signature.clear();
  }
  signature.resize(sigLen);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return signature;
}

bool
EccCrypto::Verify(const std::string& publicPem,
                  const uint8_t* data,
                  size_t len,
                  const std::vector<uint8_t>& signature)
{
  EVP_PKEY* pkey = LoadPublicKey(publicPem);
  if (!pkey)
  {
    NS_LOG_ERROR("Failed to load public key");
    return false;
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx)
  {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) > 0)
  {
    if (EVP_DigestVerifyUpdate(mdctx, data, len) > 0)
    {
      int rc = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
      ok = (rc == 1);
    }
  }

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ok;
}

std::vector<uint8_t>
EccCrypto::Sha256(const uint8_t* data, size_t len)
{
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256(data, len, hash.data());
  return hash;
}

} // namespace ns3
