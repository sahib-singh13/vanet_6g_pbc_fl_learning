#include "bs-relay-app.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/udp-socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("BsRelayApp");

BsRelayApp::BsRelayApp() = default;
BsRelayApp::~BsRelayApp() = default;

TypeId
BsRelayApp::GetTypeId()
{
  static TypeId tid = TypeId("ns3::BsRelayApp")
                          .SetParent<Application>()
                          .SetGroupName("VanetSecurity")
                          .AddConstructor<BsRelayApp>()
                          .AddAttribute("ListenPort",
                                        "UDP port for V2V relay.",
                                        UintegerValue(9200),
                                        MakeUintegerAccessor(&BsRelayApp::m_port),
                                        MakeUintegerChecker<uint16_t>());
  return tid;
}

void
BsRelayApp::SetUeAddresses(const std::vector<Ipv4Address>& addresses)
{
  m_ueAddresses = addresses;
}

void
BsRelayApp::StartApplication()
{
  if (!m_socket)
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
    if (m_socket->Bind(local) != 0)
    {
      NS_LOG_ERROR("BS relay bind failed");
      return;
    }
    m_socket->SetRecvCallback(MakeCallback(&BsRelayApp::HandleRead, this));
  }
}

void
BsRelayApp::StopApplication()
{
  if (m_socket)
  {
    m_socket->Close();
    m_socket = nullptr;
  }
}

void
BsRelayApp::HandleRead(Ptr<Socket> socket)
{
  if (m_ueAddresses.empty())
  {
    socket->Recv();
    return;
  }

  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  while (packet && packet->GetSize() > 0)
  {
    Ipv4Address srcAddr;
    if (InetSocketAddress::IsMatchingType(from))
    {
      srcAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
    }

    for (const auto& dst : m_ueAddresses)
    {
      if (dst == srcAddr)
      {
        continue;
      }
      Ptr<Packet> copy = packet->Copy();
      socket->SendTo(copy, 0, InetSocketAddress(dst, m_port));
    }

    packet = socket->RecvFrom(from);
  }
}

} // namespace ns3
