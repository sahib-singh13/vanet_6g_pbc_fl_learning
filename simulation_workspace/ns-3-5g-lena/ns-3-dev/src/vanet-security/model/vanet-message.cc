#include "vanet-message.h"

#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("VanetMessage");

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
  uint16_t pubLen = start.ReadNtohU16();
  uint16_t certLen = start.ReadNtohU16();
  uint16_t sigLen = start.ReadNtohU16();

  m_publicKey.resize(pubLen);
  for (uint16_t i = 0; i < pubLen; ++i)
  {
    m_publicKey[i] = start.ReadU8();
  }
  m_certificate.resize(certLen);
  for (uint16_t i = 0; i < certLen; ++i)
  {
    m_certificate[i] = start.ReadU8();
  }
  m_signature.resize(sigLen);
  for (uint16_t i = 0; i < sigLen; ++i)
  {
    m_signature[i] = start.ReadU8();
  }

  return GetSerializedSize();
}

void
VanetAuthHeader::Print(std::ostream& os) const
{
  os << "pubLen=" << m_publicKey.size() << " certLen=" << m_certificate.size()
     << " sigLen=" << m_signature.size();
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

} // namespace ns3
