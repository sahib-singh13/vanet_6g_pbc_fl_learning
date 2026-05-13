#include "vanet-message.h"

#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("VanetMessage");

namespace {

bool
ReadNtohU16Safe(Buffer::Iterator& start, uint16_t& value)
{
  if (start.GetRemainingSize() < 2)
  {
    return false;
  }
  value = start.ReadNtohU16();
  return true;
}

bool
ReadNtohU64Safe(Buffer::Iterator& start, uint64_t& value)
{
  if (start.GetRemainingSize() < 8)
  {
    return false;
  }
  value = start.ReadNtohU64();
  return true;
}

bool
ReadVectorSafe(Buffer::Iterator& start, uint16_t length, std::vector<uint8_t>& value)
{
  if (start.GetRemainingSize() < length)
  {
    return false;
  }
  value.resize(length);
  for (uint16_t i = 0; i < length; ++i)
  {
    value[i] = start.ReadU8();
  }
  return true;
}

} // namespace

VanetMessageHeader::VanetMessageHeader() = default;

TypeId
VanetMessageHeader::GetTypeId()
{
  static TypeId tid = TypeId("ns3::VanetMessageHeader")
                          .SetParent<Header>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<VanetMessageHeader>();
  return tid;
}

TypeId
VanetMessageHeader::GetInstanceTypeId() const
{
  return GetTypeId();
}

void
VanetMessageHeader::SetType(VanetMessageType type)
{
  m_type = type;
}

void
VanetMessageHeader::SetSenderId(uint32_t senderId)
{
  m_senderId = senderId;
}

void
VanetMessageHeader::SetTargetId(uint32_t targetId)
{
  m_targetId = targetId;
}

void
VanetMessageHeader::SetMessageId(uint32_t messageId)
{
  m_messageId = messageId;
}

void
VanetMessageHeader::SetTimestampUs(uint64_t tsUs)
{
  m_timestampUs = tsUs;
}

void
VanetMessageHeader::SetPayloadSize(uint32_t payloadSize)
{
  m_payloadSize = payloadSize;
}

VanetMessageType
VanetMessageHeader::GetType() const
{
  return m_type;
}

uint32_t
VanetMessageHeader::GetSenderId() const
{
  return m_senderId;
}

uint32_t
VanetMessageHeader::GetTargetId() const
{
  return m_targetId;
}

uint32_t
VanetMessageHeader::GetMessageId() const
{
  return m_messageId;
}

uint64_t
VanetMessageHeader::GetTimestampUs() const
{
  return m_timestampUs;
}

uint32_t
VanetMessageHeader::GetPayloadSize() const
{
  return m_payloadSize;
}

uint32_t
VanetMessageHeader::GetSerializedSize() const
{
  return 1 + 4 + 4 + 4 + 8 + 4;
}

void
VanetMessageHeader::Serialize(Buffer::Iterator start) const
{
  start.WriteU8(static_cast<uint8_t>(m_type));
  start.WriteHtonU32(m_senderId);
  start.WriteHtonU32(m_targetId);
  start.WriteHtonU32(m_messageId);
  start.WriteHtonU64(m_timestampUs);
  start.WriteHtonU32(m_payloadSize);
}

uint32_t
VanetMessageHeader::Deserialize(Buffer::Iterator start)
{
  if (start.GetRemainingSize() < GetSerializedSize())
  {
    m_type = VanetMessageType::V2V_DATA;
    m_senderId = 0;
    m_targetId = 0;
    m_messageId = 0;
    m_timestampUs = 0;
    m_payloadSize = 0;
    return 0;
  }

  m_type = static_cast<VanetMessageType>(start.ReadU8());
  m_senderId = start.ReadNtohU32();
  m_targetId = start.ReadNtohU32();
  m_messageId = start.ReadNtohU32();
  m_timestampUs = start.ReadNtohU64();
  m_payloadSize = start.ReadNtohU32();
  return GetSerializedSize();
}

void
VanetMessageHeader::Print(std::ostream& os) const
{
  os << "type=" << static_cast<uint32_t>(m_type) << " sender=" << m_senderId
     << " target=" << m_targetId << " msgId=" << m_messageId
     << " tsUs=" << m_timestampUs << " payload=" << m_payloadSize;
}

VanetAuthHeader::VanetAuthHeader() = default;

TypeId
VanetAuthHeader::GetTypeId()
{
  static TypeId tid = TypeId("ns3::VanetAuthHeader")
                          .SetParent<Header>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<VanetAuthHeader>();
  return tid;
}

TypeId
VanetAuthHeader::GetInstanceTypeId() const
{
  return GetTypeId();
}

void
VanetAuthHeader::SetPublicKey(const std::vector<uint8_t>& pubKey)
{
  m_publicKey = pubKey;
}

void
VanetAuthHeader::SetCertificate(const std::vector<uint8_t>& cert)
{
  m_certificate = cert;
}

void
VanetAuthHeader::SetSignature(const std::vector<uint8_t>& signature)
{
  m_signature = signature;
}

const std::vector<uint8_t>&
VanetAuthHeader::GetPublicKey() const
{
  return m_publicKey;
}

const std::vector<uint8_t>&
VanetAuthHeader::GetCertificate() const
{
  return m_certificate;
}

const std::vector<uint8_t>&
VanetAuthHeader::GetSignature() const
{
  return m_signature;
}

uint32_t
VanetAuthHeader::GetSerializedSize() const
{
  return 2 + 2 + 2 + m_publicKey.size() + m_certificate.size() + m_signature.size();
}

void
VanetAuthHeader::Serialize(Buffer::Iterator start) const
{
  start.WriteHtonU16(static_cast<uint16_t>(m_publicKey.size()));
  start.WriteHtonU16(static_cast<uint16_t>(m_certificate.size()));
  start.WriteHtonU16(static_cast<uint16_t>(m_signature.size()));

  for (uint8_t byte : m_publicKey)
  {
    start.WriteU8(byte);
  }
  for (uint8_t byte : m_certificate)
  {
    start.WriteU8(byte);
  }
  for (uint8_t byte : m_signature)
  {
    start.WriteU8(byte);
  }
}

uint32_t
VanetAuthHeader::Deserialize(Buffer::Iterator start)
{
  auto fail = [this]() -> uint32_t {
    m_publicKey.clear();
    m_certificate.clear();
    m_signature.clear();
    return 0;
  };

  uint16_t pubLen = 0;
  uint16_t certLen = 0;
  uint16_t sigLen = 0;
  if (!ReadNtohU16Safe(start, pubLen) || !ReadNtohU16Safe(start, certLen) ||
      !ReadNtohU16Safe(start, sigLen))
  {
    return fail();
  }

  if (!ReadVectorSafe(start, pubLen, m_publicKey) ||
      !ReadVectorSafe(start, certLen, m_certificate) ||
      !ReadVectorSafe(start, sigLen, m_signature))
  {
    return fail();
  }

  return GetSerializedSize();
}

void
VanetAuthHeader::Print(std::ostream& os) const
{
  os << "pubLen=" << m_publicKey.size() << " certLen=" << m_certificate.size()
     << " sigLen=" << m_signature.size();
}

VanetPbcAuthHeader::VanetPbcAuthHeader() = default;

TypeId
VanetPbcAuthHeader::GetTypeId()
{
  static TypeId tid = TypeId("ns3::VanetPbcAuthHeader")
                          .SetParent<Header>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<VanetPbcAuthHeader>();
  return tid;
}

TypeId
VanetPbcAuthHeader::GetInstanceTypeId() const
{
  return GetTypeId();
}

void
VanetPbcAuthHeader::SetState(const std::vector<uint8_t>& state)
{
  m_state = state;
}

void
VanetPbcAuthHeader::SetPid1(const std::vector<uint8_t>& pid1)
{
  m_pid1 = pid1;
}

void
VanetPbcAuthHeader::SetPid2(const std::vector<uint8_t>& pid2)
{
  m_pid2 = pid2;
}

void
VanetPbcAuthHeader::SetTimestampUs(uint64_t tiUs)
{
  m_tiUs = tiUs;
}

void
VanetPbcAuthHeader::SetQi(const std::vector<uint8_t>& qi)
{
  m_qi = qi;
}

void
VanetPbcAuthHeader::SetWi(const std::vector<uint8_t>& wi)
{
  m_wi = wi;
}

void
VanetPbcAuthHeader::SetPsi(const std::vector<uint8_t>& psi)
{
  m_psi = psi;
}

const std::vector<uint8_t>&
VanetPbcAuthHeader::GetState() const
{
  return m_state;
}

const std::vector<uint8_t>&
VanetPbcAuthHeader::GetPid1() const
{
  return m_pid1;
}

const std::vector<uint8_t>&
VanetPbcAuthHeader::GetPid2() const
{
  return m_pid2;
}

uint64_t
VanetPbcAuthHeader::GetTimestampUs() const
{
  return m_tiUs;
}

const std::vector<uint8_t>&
VanetPbcAuthHeader::GetQi() const
{
  return m_qi;
}

const std::vector<uint8_t>&
VanetPbcAuthHeader::GetWi() const
{
  return m_wi;
}

const std::vector<uint8_t>&
VanetPbcAuthHeader::GetPsi() const
{
  return m_psi;
}

uint32_t
VanetPbcAuthHeader::GetSerializedSize() const
{
  return 2 + m_state.size() + 2 + m_pid1.size() + 2 + m_pid2.size() + 8 + 2 + m_qi.size() + 2 +
         m_wi.size() + 2 + m_psi.size();
}

void
VanetPbcAuthHeader::Serialize(Buffer::Iterator start) const
{
  start.WriteHtonU16(static_cast<uint16_t>(m_state.size()));
  for (uint8_t byte : m_state)
  {
    start.WriteU8(byte);
  }
  start.WriteHtonU16(static_cast<uint16_t>(m_pid1.size()));
  for (uint8_t byte : m_pid1)
  {
    start.WriteU8(byte);
  }
  start.WriteHtonU16(static_cast<uint16_t>(m_pid2.size()));
  for (uint8_t byte : m_pid2)
  {
    start.WriteU8(byte);
  }
  start.WriteHtonU64(m_tiUs);
  start.WriteHtonU16(static_cast<uint16_t>(m_qi.size()));
  for (uint8_t byte : m_qi)
  {
    start.WriteU8(byte);
  }
  start.WriteHtonU16(static_cast<uint16_t>(m_wi.size()));
  for (uint8_t byte : m_wi)
  {
    start.WriteU8(byte);
  }
  start.WriteHtonU16(static_cast<uint16_t>(m_psi.size()));
  for (uint8_t byte : m_psi)
  {
    start.WriteU8(byte);
  }
}

uint32_t
VanetPbcAuthHeader::Deserialize(Buffer::Iterator start)
{
  auto fail = [this]() -> uint32_t {
    m_state.clear();
    m_pid1.clear();
    m_pid2.clear();
    m_tiUs = 0;
    m_qi.clear();
    m_wi.clear();
    m_psi.clear();
    return 0;
  };

  uint16_t stateLen = 0;
  if (!ReadNtohU16Safe(start, stateLen) || !ReadVectorSafe(start, stateLen, m_state))
  {
    return fail();
  }

  uint16_t pid1Len = 0;
  if (!ReadNtohU16Safe(start, pid1Len) || !ReadVectorSafe(start, pid1Len, m_pid1))
  {
    return fail();
  }

  uint16_t pid2Len = 0;
  if (!ReadNtohU16Safe(start, pid2Len) || !ReadVectorSafe(start, pid2Len, m_pid2))
  {
    return fail();
  }

  if (!ReadNtohU64Safe(start, m_tiUs))
  {
    return fail();
  }

  uint16_t qiLen = 0;
  if (!ReadNtohU16Safe(start, qiLen) || !ReadVectorSafe(start, qiLen, m_qi))
  {
    return fail();
  }

  uint16_t wiLen = 0;
  if (!ReadNtohU16Safe(start, wiLen) || !ReadVectorSafe(start, wiLen, m_wi))
  {
    return fail();
  }

  uint16_t psiLen = 0;
  if (!ReadNtohU16Safe(start, psiLen) || !ReadVectorSafe(start, psiLen, m_psi))
  {
    return fail();
  }
  return GetSerializedSize();
}

void
VanetPbcAuthHeader::Print(std::ostream& os) const
{
  os << "stateLen=" << m_state.size() << " pid1Len=" << m_pid1.size()
     << " pid2Len=" << m_pid2.size() << " tiUs=" << m_tiUs << " qiLen=" << m_qi.size()
     << " wiLen=" << m_wi.size() << " psiLen=" << m_psi.size();
}

void
WriteUint32(std::vector<uint8_t>& buffer, uint32_t value)
{
  buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

bool
ReadUint32(const std::vector<uint8_t>& buffer, size_t& offset, uint32_t& value)
{
  if (offset + 4 > buffer.size())
  {
    return false;
  }
  value = (static_cast<uint32_t>(buffer[offset]) << 24) |
          (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
          (static_cast<uint32_t>(buffer[offset + 2]) << 8) |
          static_cast<uint32_t>(buffer[offset + 3]);
  offset += 4;
  return true;
}

void
WriteUint16(std::vector<uint8_t>& buffer, uint16_t value)
{
  buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

bool
ReadUint16(const std::vector<uint8_t>& buffer, size_t& offset, uint16_t& value)
{
  if (offset + 2 > buffer.size())
  {
    return false;
  }
  value = static_cast<uint16_t>((buffer[offset] << 8) | buffer[offset + 1]);
  offset += 2;
  return true;
}

void
WriteUint64(std::vector<uint8_t>& buffer, uint64_t value)
{
  buffer.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

bool
ReadUint64(const std::vector<uint8_t>& buffer, size_t& offset, uint64_t& value)
{
  if (offset + 8 > buffer.size())
  {
    return false;
  }
  value = (static_cast<uint64_t>(buffer[offset]) << 56) |
          (static_cast<uint64_t>(buffer[offset + 1]) << 48) |
          (static_cast<uint64_t>(buffer[offset + 2]) << 40) |
          (static_cast<uint64_t>(buffer[offset + 3]) << 32) |
          (static_cast<uint64_t>(buffer[offset + 4]) << 24) |
          (static_cast<uint64_t>(buffer[offset + 5]) << 16) |
          (static_cast<uint64_t>(buffer[offset + 6]) << 8) |
          static_cast<uint64_t>(buffer[offset + 7]);
  offset += 8;
  return true;
}

void
WriteBytes(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& data)
{
  buffer.insert(buffer.end(), data.begin(), data.end());
}

bool
ReadBytes(const std::vector<uint8_t>& buffer, size_t& offset, uint16_t length, std::vector<uint8_t>& out)
{
  if (offset + length > buffer.size())
  {
    return false;
  }
  out.assign(buffer.begin() + static_cast<long>(offset),
             buffer.begin() + static_cast<long>(offset + length));
  offset += length;
  return true;
}

bool
TryExtractMessage(std::vector<uint8_t>& buffer,
                  VanetMessageHeader& header,
                  std::vector<uint8_t>& payload)
{
  constexpr size_t kHeaderSize = 1 + 4 + 4 + 4 + 8 + 4;
  if (buffer.size() < kHeaderSize)
  {
    return false;
  }

  size_t offset = 0;
  uint8_t type = buffer[offset++];
  uint32_t senderId = 0;
  uint32_t targetId = 0;
  uint32_t messageId = 0;
  uint64_t tsUs = 0;
  uint32_t payloadSize = 0;
  if (!ReadUint32(buffer, offset, senderId) ||
      !ReadUint32(buffer, offset, targetId) ||
      !ReadUint32(buffer, offset, messageId) ||
      !ReadUint64(buffer, offset, tsUs) ||
      !ReadUint32(buffer, offset, payloadSize))
  {
    return false;
  }

  if (buffer.size() < kHeaderSize + payloadSize)
  {
    return false;
  }

  header.SetType(static_cast<VanetMessageType>(type));
  header.SetSenderId(senderId);
  header.SetTargetId(targetId);
  header.SetMessageId(messageId);
  header.SetTimestampUs(tsUs);
  header.SetPayloadSize(payloadSize);

  payload.assign(buffer.begin() + kHeaderSize,
                 buffer.begin() + kHeaderSize + payloadSize);
  buffer.erase(buffer.begin(), buffer.begin() + kHeaderSize + payloadSize);
  return true;
}

} // namespace ns3
