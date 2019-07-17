#include "IPUtilsEx.h"
#include "PointerVector.h"

bool netflow::SIPConnectionInfo::Fill(pcpp::Packet* packet)
{
    using namespace pcpp;

    memset(this, 0, sizeof(*this));
    if (!packet->isPacketOfType(IPv4) && !packet->isPacketOfType(IPv6)) {
        // No IP layer detected
        return false;
    }

    if (!packet->isPacketOfType(ICMP) && 
        (packet->isPacketOfType(TCP) || packet->isPacketOfType(UDP)))
    {
        TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>();
        if (tcpLayer != NULL)
        {
            portSrc = ntohs(tcpLayer->getTcpHeader()->portSrc);
            portDst = ntohs(tcpLayer->getTcpHeader()->portDst);
        }
        else
        {
            UdpLayer* udpLayer = packet->getLayerOfType<UdpLayer>();
            if (udpLayer)
            {
                portSrc = ntohs(udpLayer->getUdpHeader()->portSrc);
                portDst = ntohs(udpLayer->getUdpHeader()->portDst);
            }
        }
    }

    IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();
    if (ipv4Layer != NULL)
    {
        ipv4.ipSrc = ipv4Layer->getIPv4Header()->ipSrc;
        ipv4.ipDst = ipv4Layer->getIPv4Header()->ipDst;
        protocol = ipv4Layer->getIPv4Header()->protocol;
        af_family = AF_INET;
    }
    else
    {
        IPv6Layer* ipv6Layer = packet->getLayerOfType<IPv6Layer>();
        memcpy(ipv6.ipSrc, ipv6Layer->getIPv6Header()->ipSrc, sizeof(ipv6.ipSrc));
        memcpy(ipv6.ipDst, ipv6Layer->getIPv6Header()->ipDst, sizeof(ipv6.ipDst));
        protocol = ipv6Layer->getIPv6Header()->nextHeader;
        af_family = AF_INET6;
    }
    return true;
}

bool netflow::SIPConnectionInfo::Equal(const SIPConnectionInfo& rhs) const
{
    auto& lhs = *this;
    return
        lhs.portDst == rhs.portDst &&
        lhs.portSrc == rhs.portSrc &&
        lhs.af_family == rhs.af_family &&
        lhs.protocol == rhs.protocol &&
        ((lhs.af_family == AF_INET && lhs.ipv4.ipSrc == rhs.ipv4.ipSrc && lhs.ipv4.ipDst == rhs.ipv4.ipDst) ||
        (lhs.af_family == AF_INET6 && !memcmp(lhs.ipv6.ipSrc, rhs.ipv6.ipSrc, 16) && !memcmp(lhs.ipv6.ipDst, rhs.ipv6.ipDst, 16)));
}

bool netflow::SIPConnectionInfo::EqualBack(const SIPConnectionInfo& rhs) const
{
    auto& lhs = *this;
    return
        lhs.portDst == rhs.portSrc &&
        lhs.portSrc == rhs.portDst &&
        lhs.af_family == rhs.af_family &&
        lhs.protocol == rhs.protocol &&
        ((lhs.af_family == AF_INET && lhs.ipv4.ipSrc == rhs.ipv4.ipDst && lhs.ipv4.ipDst == rhs.ipv4.ipSrc) ||
        (lhs.af_family == AF_INET6 && !memcmp(lhs.ipv6.ipSrc, rhs.ipv6.ipDst, 16) && !memcmp(lhs.ipv6.ipDst, rhs.ipv6.ipSrc, 16)));
}

bool netflow::SIPConnectionInfo::EqualAnySide(const SIPConnectionInfo& rhs) const
{
    return Equal(rhs) || EqualBack(rhs);
}

bool netflow::SIPConnectionInfo::operator==(const SIPConnectionInfo& rhs) const
{
    return Equal(rhs);
}

//uint32_t netflow::hash5Tuple(Packet* packet)
//{
//    using namespace pcpp;
//
//    if (!packet->isPacketOfType(IPv4) && !packet->isPacketOfType(IPv6))
//        return 0;
//
//    pcpp::ScalarBuffer<uint8_t> vec[5] = {};
//
//    uint16_t portSrc = 0;
//    uint16_t portDst = 0;
//    int srcPosition = 0;
//
//    if (!packet->isPacketOfType(ICMP) && ((packet->isPacketOfType(TCP)) || (!packet->isPacketOfType(UDP))))
//    {
//        TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>();
//        if (tcpLayer != NULL)
//        {
//            portSrc = tcpLayer->getTcpHeader()->portSrc;
//            portDst = tcpLayer->getTcpHeader()->portDst;
//        }
//        else
//        {
//            UdpLayer* udpLayer = packet->getLayerOfType<UdpLayer>();
//            portSrc = udpLayer->getUdpHeader()->portSrc;
//            portDst = udpLayer->getUdpHeader()->portDst;
//        }
//
//        if (portDst < portSrc)
//            srcPosition = 1;
//
//        vec[0 + srcPosition].buffer = (uint8_t*)&portSrc;
//        vec[0 + srcPosition].len = 2;
//        vec[1 - srcPosition].buffer = (uint8_t*)&portDst;
//        vec[1 - srcPosition].len = 2;
//    }
//
//    IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();
//    if (ipv4Layer != NULL)
//    {
//        if (portSrc == portDst && ipv4Layer->getIPv4Header()->ipDst < ipv4Layer->getIPv4Header()->ipSrc)
//            srcPosition = 1;
//
//        vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipSrc;
//        vec[2 + srcPosition].len = 4;
//        vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipDst;
//        vec[3 - srcPosition].len = 4;
//        vec[4].buffer = &(ipv4Layer->getIPv4Header()->protocol);
//        vec[4].len = 1;
//    }
//    else
//    {
//        IPv6Layer* ipv6Layer = packet->getLayerOfType<IPv6Layer>();
//        if (portSrc == portDst && (uint64_t)ipv6Layer->getIPv6Header()->ipDst < (uint64_t)ipv6Layer->getIPv6Header()->ipSrc)
//            srcPosition = 1;
//
//        vec[2 + srcPosition].buffer = ipv6Layer->getIPv6Header()->ipSrc;
//        vec[2 + srcPosition].len = 16;
//        vec[3 - srcPosition].buffer = ipv6Layer->getIPv6Header()->ipDst;
//        vec[3 - srcPosition].len = 16;
//        vec[4].buffer = &(ipv6Layer->getIPv6Header()->nextHeader);
//        vec[4].len = 1;
//    }
//
//    return pcpp::fnv_hash(vec, 5);
//}

uint32_t netflow::hash5Tuple(SIPConnectionInfo& connInfo)
{
    using namespace pcpp;

    pcpp::ScalarBuffer<uint8_t> vec[5] = {};
    int srcPosition = 0;

    {
        if (connInfo.portDst < connInfo.portSrc)
            srcPosition = 1;

        vec[0 + srcPosition].buffer = (uint8_t*)&connInfo.portSrc;
        vec[0 + srcPosition].len = sizeof(connInfo.portSrc);
        vec[1 - srcPosition].buffer = (uint8_t*)&connInfo.portDst;
        vec[1 - srcPosition].len = sizeof(connInfo.portDst);
    }

    switch (connInfo.af_family)
    {
    case AF_INET:
    {
        if (connInfo.portSrc == connInfo.portDst &&
            memcmp(&connInfo.ipv4.ipDst, &connInfo.ipv4.ipSrc, sizeof(connInfo.ipv4.ipSrc)) < 0) {
            srcPosition = 1;
        }
        vec[2 + srcPosition].buffer = (uint8_t*)&connInfo.ipv4.ipSrc;
        vec[2 + srcPosition].len = 4;
        vec[3 - srcPosition].buffer = (uint8_t*)&connInfo.ipv4.ipDst;
        vec[3 - srcPosition].len = 4;
        break;
    }
    case AF_INET6:
    {
        if (connInfo.portSrc == connInfo.portDst &&
            memcmp(&connInfo.ipv6.ipDst, &connInfo.ipv6.ipSrc, sizeof(connInfo.ipv6.ipSrc)) < 0) {
            srcPosition = 1;
        }
        vec[2 + srcPosition].buffer = (uint8_t*)&connInfo.ipv6.ipSrc;
        vec[2 + srcPosition].len = 16;
        vec[3 - srcPosition].buffer = (uint8_t*)&connInfo.ipv6.ipDst;
        vec[3 - srcPosition].len = 16;
        break;
    }
    } // switch
    vec[4].buffer = (uint8_t*)&connInfo.protocol;
    vec[4].len = sizeof(connInfo.protocol);

    return pcpp::fnv_hash(vec, 5);
}

uint32_t netflow::hash5Tuple(pcpp::Packet* packet)
{
    netflow::SIPConnectionInfo connInfo;

    if (!connInfo.Fill(packet)) {
        return 0;
    }

    return hash5Tuple(connInfo);
}
