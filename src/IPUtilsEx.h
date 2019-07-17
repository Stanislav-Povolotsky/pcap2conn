#ifndef __NETFLOW_IPUTILSEX__INCLUDED__
#define __NETFLOW_IPUTILSEX__INCLUDED__

#pragma warning(push)
#pragma warning(disable: 4800) // 'uint64_t': forcing value to bool 'true' or 'false'
#pragma warning(disable: 4200) // nonstandard extension used: zero-sized array in struct/union
#include "IpUtils.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PacketUtils.h"
#include "IpAddress.h"
#include "UdpLayer.h"
#include "Packet.h"
#pragma warning(pop)

#include <memory>
#if defined(WIN32) || defined(PCAPPP_MINGW_ENV) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

namespace netflow
{
    struct SIPConnectionInfo
    {
        uint8_t af_family = 0; // AF_INET, AF_INET6
        /** Defines the protocol used in the data portion of the IP datagram. Must be one of ::IPProtocolTypes */
        uint8_t protocol = 0;
        /** Source TCP port */
        uint16_t portSrc = 0;
        /** Destination TCP port */
        uint16_t portDst = 0;

        union
        {
            struct
            {
                /** IPv4 address of the sender of the packet */
                uint32_t ipSrc = 0;
                /** IPv4 address of the receiver of the packet */
                uint32_t ipDst = 0;
            } ipv4;
            struct
            {
                /** Source address */
                uint8_t ipSrc[16] = {};
                /** Destination address */
                uint8_t ipDst[16] = {};
            } ipv6;
        };

        SIPConnectionInfo() {};
        bool Fill(pcpp::Packet* packet);

        /**
         * Get the source IP address in the form of IPv4Address/IPv6Address
         * @return An IPv4Address/IPv6Address containing the source address
         */
        inline pcpp::IPv4Address getSrcIpV4Address() const { return pcpp::IPv4Address(af_family == AF_INET ? ipv4.ipSrc : 0); }
        inline pcpp::IPv6Address getSrcIpV6Address() const { return af_family == AF_INET6 ? pcpp::IPv6Address(const_cast<uint8_t*>(ipv6.ipSrc)) : pcpp::IPv6Address::Zero; }
        inline std::unique_ptr<pcpp::IPAddress> getSrcIpAddress() const { return std::unique_ptr<pcpp::IPAddress>(af_family == AF_INET6 ? pcpp::IPv6Address(const_cast<uint8_t*>(ipv6.ipSrc)).clone() : pcpp::IPv4Address(af_family == AF_INET ? ipv4.ipSrc : 0).clone()); }

        /**
         * Set the source IP address
         * @param[in] ipAddr The IP address to set
         */
        inline void setSrcIpAddress(const pcpp::IPv4Address& ipAddr) { if(af_family == AF_INET) ipv4.ipSrc = ipAddr.toInt(); }
        inline void setSrcIpAddress(const pcpp::IPv6Address& ipAddr) { if (af_family == AF_INET6) memcpy(ipv6.ipSrc, pcpp::IPv6Address(ipAddr).toIn6Addr(), sizeof(ipv6.ipSrc)); }

        /**
         * Get the destination IP address in the form of IPv4Address/IPv6Address
         * @return An IPv4Address/IPv6Address containing the destination address
         */
        inline pcpp::IPv4Address getDstIpV4Address() const { return pcpp::IPv4Address(af_family == AF_INET ? ipv4.ipDst : 0); }
        inline pcpp::IPv6Address getDstIpV6Address() const { return af_family == AF_INET6 ? pcpp::IPv6Address(const_cast<uint8_t*>(ipv6.ipDst)) : pcpp::IPv6Address::Zero; }
        inline std::unique_ptr<pcpp::IPAddress> getDstIpAddress() const { return std::unique_ptr<pcpp::IPAddress>(af_family == AF_INET6 ? pcpp::IPv6Address(const_cast<uint8_t*>(ipv6.ipDst)).clone() : pcpp::IPv4Address(af_family == AF_INET ? ipv4.ipDst : 0).clone()); }

        /**
         * Set the dest IP address
         * @param[in] ipAddr The IP address to set
         */
        inline void setDstIpAddress(const pcpp::IPv4Address& ipAddr) { if (af_family == AF_INET) ipv4.ipDst = ipAddr.toInt(); }
        inline void setDstIpAddress(const pcpp::IPv6Address& ipAddr) { if (af_family == AF_INET6) memcpy(ipv6.ipDst, pcpp::IPv6Address(ipAddr).toIn6Addr(), sizeof(ipv6.ipDst)); }

        bool operator== (const SIPConnectionInfo& rhs) const;
        bool Equal (const SIPConnectionInfo& rhs) const;
        bool EqualBack(const SIPConnectionInfo& rhs) const;
        bool EqualAnySide(const SIPConnectionInfo& rhs) const;
    };

    uint32_t hash5Tuple(SIPConnectionInfo& connInfo);
    uint32_t hash5Tuple(pcpp::Packet* packet);

}; // namespace netflow

#endif // __NETFLOW_IPUTILSEX__INCLUDED__
