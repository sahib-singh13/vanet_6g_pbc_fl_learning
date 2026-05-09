#ifndef VANET_MESSAGE_H
#define VANET_MESSAGE_H

#include "ns3/header.h"
#include "ns3/nstime.h"
#include "ns3/simple-ref-count.h"

#include <cstdint>
#include <vector>

namespace ns3 {

enum class VanetMessageType : uint8_t
{
  REGISTER_REQ = 1,
  REGISTER_RESP = 2,
  KEY_REQ = 3,
  KEY_RESP = 4,
  CERT_REQ = 5,
  CERT_RESP = 6,
  V2V_DATA = 7,
  V2V_PBC_DATA = 8,
  V2I_PING = 9,
  V2I_PONG = 10,
  FL_ROUND_START = 11,
  FL_MODEL_DOWNLOAD = 12,
  FL_UPDATE_UPLOAD = 13,
  FL_RSU_AGGREGATE = 14,
  FL_GLOBAL_MODEL = 15,
  FL_ROUND_DONE = 16
};

class VanetMessageHeader : public Header
{
public:
  VanetMessageHeader();

  void SetType(VanetMessageType type);
  void SetSenderId(uint32_t senderId);
  void SetTargetId(uint32_t targetId);
  void SetMessageId(uint32_t messageId);
  void SetTimestampUs(uint64_t tsUs);
  void SetPayloadSize(uint32_t payloadSize);

  VanetMessageType GetType() const;
  uint32_t GetSenderId() const;
  uint32_t GetTargetId() const;
  uint32_t GetMessageId() const;
  uint64_t GetTimestampUs() const;
  uint32_t GetPayloadSize() const;

  static TypeId GetTypeId();
  TypeId GetInstanceTypeId() const override;
  void Serialize(Buffer::Iterator start) const override;
  uint32_t Deserialize(Buffer::Iterator start) override;
  uint32_t GetSerializedSize() const override;
  void Print(std::ostream& os) const override;

private:
  VanetMessageType m_type{VanetMessageType::V2V_DATA};
  uint32_t m_senderId{0};
  uint32_t m_targetId{0};
  uint32_t m_messageId{0};
  uint64_t m_timestampUs{0};
  uint32_t m_payloadSize{0};
};

class VanetAuthHeader : public Header
{
public:
  VanetAuthHeader();

  void SetPublicKey(const std::vector<uint8_t>& pubKey);
  void SetCertificate(const std::vector<uint8_t>& cert);
  void SetSignature(const std::vector<uint8_t>& signature);

  const std::vector<uint8_t>& GetPublicKey() const;
  const std::vector<uint8_t>& GetCertificate() const;
  const std::vector<uint8_t>& GetSignature() const;

  static TypeId GetTypeId();
  TypeId GetInstanceTypeId() const override;
  void Serialize(Buffer::Iterator start) const override;
  uint32_t Deserialize(Buffer::Iterator start) override;
  uint32_t GetSerializedSize() const override;
  void Print(std::ostream& os) const override;

private:
  std::vector<uint8_t> m_publicKey;
  std::vector<uint8_t> m_certificate;
  std::vector<uint8_t> m_signature;
};

class VanetPbcAuthHeader : public Header
{
public:
  VanetPbcAuthHeader();

  void SetState(const std::vector<uint8_t>& state);
  void SetPid1(const std::vector<uint8_t>& pid1);
  void SetPid2(const std::vector<uint8_t>& pid2);
  void SetTimestampUs(uint64_t tiUs);
  void SetQi(const std::vector<uint8_t>& qi);
  void SetWi(const std::vector<uint8_t>& wi);
  void SetPsi(const std::vector<uint8_t>& psi);

  const std::vector<uint8_t>& GetState() const;
  const std::vector<uint8_t>& GetPid1() const;
  const std::vector<uint8_t>& GetPid2() const;
  uint64_t GetTimestampUs() const;
  const std::vector<uint8_t>& GetQi() const;
  const std::vector<uint8_t>& GetWi() const;
  const std::vector<uint8_t>& GetPsi() const;

  static TypeId GetTypeId();
  TypeId GetInstanceTypeId() const override;
  void Serialize(Buffer::Iterator start) const override;
  uint32_t Deserialize(Buffer::Iterator start) override;
  uint32_t GetSerializedSize() const override;
  void Print(std::ostream& os) const override;

private:
  std::vector<uint8_t> m_state;
  std::vector<uint8_t> m_pid1;
  std::vector<uint8_t> m_pid2;
  uint64_t m_tiUs{0};
  std::vector<uint8_t> m_qi;
  std::vector<uint8_t> m_wi;
  std::vector<uint8_t> m_psi;
};

// Helper functions to pack/unpack primitive types into byte vectors.
void WriteUint32(std::vector<uint8_t>& buffer, uint32_t value);
bool ReadUint32(const std::vector<uint8_t>& buffer, size_t& offset, uint32_t& value);
void WriteUint16(std::vector<uint8_t>& buffer, uint16_t value);
bool ReadUint16(const std::vector<uint8_t>& buffer, size_t& offset, uint16_t& value);
void WriteUint64(std::vector<uint8_t>& buffer, uint64_t value);
bool ReadUint64(const std::vector<uint8_t>& buffer, size_t& offset, uint64_t& value);
void WriteBytes(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& data);
bool ReadBytes(const std::vector<uint8_t>& buffer, size_t& offset, uint16_t length, std::vector<uint8_t>& out);
// TCP stream helper: extract one framed VanetMessage (header + payload) if available.
bool TryExtractMessage(std::vector<uint8_t>& buffer,
                       VanetMessageHeader& header,
                       std::vector<uint8_t>& payload);

} // namespace ns3

#endif // VANET_MESSAGE_H
