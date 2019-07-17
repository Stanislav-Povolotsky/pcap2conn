#ifndef __NETFLOW_REASSEMBLER__INCLUDED__
#define __NETFLOW_REASSEMBLER__INCLUDED__

#pragma warning(push)
#pragma warning(disable: 4800) // 'uint64_t': forcing value to bool 'true' or 'false'
#pragma warning(disable: 4200) // nonstandard extension used: zero-sized array in struct/union
#include "TcpReassembly2.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "IPReassembly.h"
#include "IPAddress.h"
#pragma warning(pop)

#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "LRUList.h"
#ifdef _WIN32
#include <direct.h>
#endif


namespace netflow
{
    using pcpp::IPAddress;
    using pcpp::Packet;
    using pcpp::RawPacket;
    using pcpp::IPReassembly;
    using pcpp::ProtocolType;

    struct STimeInfo
    {
        timeval absolute_time;
        timeval relative_start_time;
        timeval relative_connection_time;
    };

    namespace time_utils
    {
        inline
        timeval time_diff(timeval start, timeval cur)
        {
            cur.tv_sec -= start.tv_sec;
            if (cur.tv_usec >= start.tv_sec) {
                cur.tv_usec -= start.tv_usec;
            }
            else {
                cur.tv_sec += 1;
                cur.tv_usec = cur.tv_usec + 1000000 - start.tv_usec;
            }
            return cur;
        }

        inline
        double time_double(timeval t)
        {
            return t.tv_sec + ((double)t.tv_usec / (double)1000000);
        }
    }; // time_utils

    class NetFlowStreamData
    {
    public:
        typedef std::function<void(uint8_t* pData, size_t nDataLen)> FnFree_t;

    public:
        /**
         * A c'tor for this class that basically zeros all members
         */
        NetFlowStreamData() : m_Data(nullptr), m_DataLen(0)
        {
        }

        /**
         * A c'tor for this class that get data from outside and set the internal members. Notice that when this class is destroyed it also frees the TCP data it stores
         * @param[in] tcpData A buffer containing the TCP data piece
         * @param[in] tcpDataLength The length of the buffer
         */
        NetFlowStreamData(uint8_t* pData, size_t nDataLength, FnFree_t fnFree = FnFree_t()) :
            m_Data(pData), m_DataLen(nDataLength), m_fnFree(fnFree)
        {
        }

        ~NetFlowStreamData()
        {
            clear();
        }

        void clear()
        {
            if (m_fnFree) {
                m_fnFree(m_Data, m_DataLen);
                m_fnFree = FnFree_t();
            }
            m_Data = nullptr;
            m_DataLen = 0;
        }

        /**
         * A getter for the data buffer
         * @return A pointer to the buffer
         */
        inline uint8_t* getData()
        {
            return m_Data;
        }

        /**
         * A getter for buffer length
         * @return Buffer length
         */
        inline size_t getDataLength()
        {
            return m_DataLen;
        }

        inline NetFlowStreamData& setData(uint8_t* pData, size_t nDataLen, FnFree_t fnFree = FnFree_t())
        {
            clear();
            m_Data = pData;
            m_DataLen = nDataLen;
            m_fnFree = fnFree;
        }

    private:
        uint8_t* m_Data;
        size_t m_DataLen;
        FnFree_t m_fnFree;
    };

    inline char* protocol_number_to_name(uint8_t protocol)
    {
        static char* s_protocols[256] = {
            "HOPOPT",              // IP protocol 0
            "ICMP",                // IP protocol 1
            "IGMP",                // IP protocol 2
            "GGP",                 // IP protocol 3
            "IPV4",                // IP protocol 4
            "ST",                  // IP protocol 5
            "TCP",                 // IP protocol 6
            "CBT",                 // IP protocol 7
            "EGP",                 // IP protocol 8
            "IGP",                 // IP protocol 9
            "BBN-RCC-MON",         // IP protocol 10
            "NVP-II",              // IP protocol 11
            "PUP",                 // IP protocol 12
            "ARGUS",               // IP protocol 13
            "EMCON",               // IP protocol 14
            "XNET",                // IP protocol 15
            "CHAOS",               // IP protocol 16
            "UDP",                 // IP protocol 17
            "MUX",                 // IP protocol 18
            "DCN-MEAS",            // IP protocol 19
            "HMP",                 // IP protocol 20
            "PRM",                 // IP protocol 21
            "XNS-IDP",             // IP protocol 22
            "TRUNK-1",             // IP protocol 23
            "TRUNK-2",             // IP protocol 24
            "LEAF-1",              // IP protocol 25
            "LEAF-2",              // IP protocol 26
            "RDP",                 // IP protocol 27
            "IRTP",                // IP protocol 28
            "ISO-TP4",             // IP protocol 29
            "NETBLT",              // IP protocol 30
            "MFE-NSP",             // IP protocol 31
            "MERIT-INP",           // IP protocol 32
            "DCCP",                // IP protocol 33
            "3PC",                 // IP protocol 34
            "IDPR",                // IP protocol 35
            "XTP",                 // IP protocol 36
            "DDP",                 // IP protocol 37
            "IDPR-CMTP",           // IP protocol 38
            "TP++",                // IP protocol 39
            "IL",                  // IP protocol 40
            "IPV6",                // IP protocol 41
            "SDRP",                // IP protocol 42
            "IPV6-ROUTE",          // IP protocol 43
            "IPV6-FRAG",           // IP protocol 44
            "IDRP",                // IP protocol 45
            "RSVP",                // IP protocol 46
            "GRE",                 // IP protocol 47
            "DSR",                 // IP protocol 48
            "BNA",                 // IP protocol 49
            "ESP",                 // IP protocol 50
            "AH",                  // IP protocol 51
            "I-NLSP",              // IP protocol 52
            "SWIPE",               // IP protocol 53
            "NARP",                // IP protocol 54
            "MOBILE",              // IP protocol 55
            "TLSP",                // IP protocol 56
            "SKIP",                // IP protocol 57
            "IPV6-ICMP",           // IP protocol 58
            "IPV6-NONXT",          // IP protocol 59
            "IPV6-OPTS",           // IP protocol 60
            "IP(61)",              // IP protocol 61
            "CFTP",                // IP protocol 62
            "IP(63)",              // IP protocol 63
            "SAT-EXPAK",           // IP protocol 64
            "KRYPTOLAN",           // IP protocol 65
            "RVD",                 // IP protocol 66
            "IPPC",                // IP protocol 67
            "IP(68)",              // IP protocol 68
            "SAT-MON",             // IP protocol 69
            "VISA",                // IP protocol 70
            "IPCV",                // IP protocol 71
            "CPNX",                // IP protocol 72
            "CPHB",                // IP protocol 73
            "WSN",                 // IP protocol 74
            "PVP",                 // IP protocol 75
            "BR-SAT-MON",          // IP protocol 76
            "SUN-ND",              // IP protocol 77
            "WB-MON",              // IP protocol 78
            "WB-EXPAK",            // IP protocol 79
            "ISO-IP",              // IP protocol 80
            "VMTP",                // IP protocol 81
            "SECURE-VMTP",         // IP protocol 82
            "VINES",               // IP protocol 83
            "TTP",                 // IP protocol 84
            "NSFNET-IGP",          // IP protocol 85
            "DGP",                 // IP protocol 86
            "TCF",                 // IP protocol 87
            "EIGRP",               // IP protocol 88
            "OSPFIGP",             // IP protocol 89
            "SPRITE-RPC",          // IP protocol 90
            "LARP",                // IP protocol 91
            "MTP",                 // IP protocol 92
            "AX.25",               // IP protocol 93
            "IPIP",                // IP protocol 94
            "MICP",                // IP protocol 95
            "SCC-SP",              // IP protocol 96
            "ETHERIP",             // IP protocol 97
            "ENCAP",               // IP protocol 98
            "IP(99)",              // IP protocol 99
            "GMTP",                // IP protocol 100
            "IFMP",                // IP protocol 101
            "PNNI",                // IP protocol 102
            "PIM",                 // IP protocol 103
            "ARIS",                // IP protocol 104
            "SCPS",                // IP protocol 105
            "QNX",                 // IP protocol 106
            "A/N",                 // IP protocol 107
            "IPCOMP",              // IP protocol 108
            "SNP",                 // IP protocol 109
            "COMPAQ-PEER",         // IP protocol 110
            "IPX-IN-IP",           // IP protocol 111
            "VRRP",                // IP protocol 112
            "PGM",                 // IP protocol 113
            "IP(114)",             // IP protocol 114
            "L2TP",                // IP protocol 115
            "DDX",                 // IP protocol 116
            "IATP",                // IP protocol 117
            "STP",                 // IP protocol 118
            "SRP",                 // IP protocol 119
            "UTI",                 // IP protocol 120
            "SMP",                 // IP protocol 121
            "SM",                  // IP protocol 122
            "PTP",                 // IP protocol 123
            "ISIS OVER IPV4",      // IP protocol 124
            "FIRE",                // IP protocol 125
            "CRTP",                // IP protocol 126
            "CRUDP",               // IP protocol 127
            "SSCOPMCE",            // IP protocol 128
            "IPLT",                // IP protocol 129
            "SPS",                 // IP protocol 130
            "PIPE",                // IP protocol 131
            "SCTP",                // IP protocol 132
            "FC",                  // IP protocol 133
            "RSVP-E2E-IGNORE",     // IP protocol 134
            "MOBILITY HEADER",     // IP protocol 135
            "UDPLITE",             // IP protocol 136
            "MPLS-IN-IP",          // IP protocol 137
            "MANET",               // IP protocol 138
            "HIP",                 // IP protocol 139
            "SHIM6",               // IP protocol 140
            "WESP",                // IP protocol 141
            "ROHC",                // IP protocol 142
            "IP(143)",             // IP protocol 143
            "IP(144)",             // IP protocol 144
            "IP(145)",             // IP protocol 145
            "IP(146)",             // IP protocol 146
            "IP(147)",             // IP protocol 147
            "IP(148)",             // IP protocol 148
            "IP(149)",             // IP protocol 149
            "IP(150)",             // IP protocol 150
            "IP(151)",             // IP protocol 151
            "IP(152)",             // IP protocol 152
            "IP(153)",             // IP protocol 153
            "IP(154)",             // IP protocol 154
            "IP(155)",             // IP protocol 155
            "IP(156)",             // IP protocol 156
            "IP(157)",             // IP protocol 157
            "IP(158)",             // IP protocol 158
            "IP(159)",             // IP protocol 159
            "IP(160)",             // IP protocol 160
            "IP(161)",             // IP protocol 161
            "IP(162)",             // IP protocol 162
            "IP(163)",             // IP protocol 163
            "IP(164)",             // IP protocol 164
            "IP(165)",             // IP protocol 165
            "IP(166)",             // IP protocol 166
            "IP(167)",             // IP protocol 167
            "IP(168)",             // IP protocol 168
            "IP(169)",             // IP protocol 169
            "IP(170)",             // IP protocol 170
            "IP(171)",             // IP protocol 171
            "IP(172)",             // IP protocol 172
            "IP(173)",             // IP protocol 173
            "IP(174)",             // IP protocol 174
            "IP(175)",             // IP protocol 175
            "IP(176)",             // IP protocol 176
            "IP(177)",             // IP protocol 177
            "IP(178)",             // IP protocol 178
            "IP(179)",             // IP protocol 179
            "IP(180)",             // IP protocol 180
            "IP(181)",             // IP protocol 181
            "IP(182)",             // IP protocol 182
            "IP(183)",             // IP protocol 183
            "IP(184)",             // IP protocol 184
            "IP(185)",             // IP protocol 185
            "IP(186)",             // IP protocol 186
            "IP(187)",             // IP protocol 187
            "IP(188)",             // IP protocol 188
            "IP(189)",             // IP protocol 189
            "IP(190)",             // IP protocol 190
            "IP(191)",             // IP protocol 191
            "IP(192)",             // IP protocol 192
            "IP(193)",             // IP protocol 193
            "IP(194)",             // IP protocol 194
            "IP(195)",             // IP protocol 195
            "IP(196)",             // IP protocol 196
            "IP(197)",             // IP protocol 197
            "IP(198)",             // IP protocol 198
            "IP(199)",             // IP protocol 199
            "IP(200)",             // IP protocol 200
            "IP(201)",             // IP protocol 201
            "IP(202)",             // IP protocol 202
            "IP(203)",             // IP protocol 203
            "IP(204)",             // IP protocol 204
            "IP(205)",             // IP protocol 205
            "IP(206)",             // IP protocol 206
            "IP(207)",             // IP protocol 207
            "IP(208)",             // IP protocol 208
            "IP(209)",             // IP protocol 209
            "IP(210)",             // IP protocol 210
            "IP(211)",             // IP protocol 211
            "IP(212)",             // IP protocol 212
            "IP(213)",             // IP protocol 213
            "IP(214)",             // IP protocol 214
            "IP(215)",             // IP protocol 215
            "IP(216)",             // IP protocol 216
            "IP(217)",             // IP protocol 217
            "IP(218)",             // IP protocol 218
            "IP(219)",             // IP protocol 219
            "IP(220)",             // IP protocol 220
            "IP(221)",             // IP protocol 221
            "IP(222)",             // IP protocol 222
            "IP(223)",             // IP protocol 223
            "IP(224)",             // IP protocol 224
            "IP(225)",             // IP protocol 225
            "IP(226)",             // IP protocol 226
            "IP(227)",             // IP protocol 227
            "IP(228)",             // IP protocol 228
            "IP(229)",             // IP protocol 229
            "IP(230)",             // IP protocol 230
            "IP(231)",             // IP protocol 231
            "IP(232)",             // IP protocol 232
            "IP(233)",             // IP protocol 233
            "IP(234)",             // IP protocol 234
            "IP(235)",             // IP protocol 235
            "IP(236)",             // IP protocol 236
            "IP(237)",             // IP protocol 237
            "IP(238)",             // IP protocol 238
            "IP(239)",             // IP protocol 239
            "IP(240)",             // IP protocol 240
            "IP(241)",             // IP protocol 241
            "IP(242)",             // IP protocol 242
            "IP(243)",             // IP protocol 243
            "IP(244)",             // IP protocol 244
            "IP(245)",             // IP protocol 245
            "IP(246)",             // IP protocol 246
            "IP(247)",             // IP protocol 247
            "IP(248)",             // IP protocol 248
            "IP(249)",             // IP protocol 249
            "IP(250)",             // IP protocol 250
            "IP(251)",             // IP protocol 251
            "IP(252)",             // IP protocol 252
            "IP(253)",             // IP protocol 253
            "IP(254)",             // IP protocol 254
            "IP(255)",             // IP protocol 255
        };
        return s_protocols[protocol];
    }

    struct NetFlowReassemblerStats
    {
        std::uint64_t nNumberOfProcessedConnections;
    };

    class NetFlowReassembler
    {
    public:
        typedef TcpReassembly2<SConnMgrCtxBase, NetFlowReassembler> TcpReassembly_t;

        typedef TcpReassembly_t::ConnectionEndReason ConnectionEndReason;

        /**
         * @typedef OnTcpMessageReady
         * A callback invoked when new data arrives on a connection
         * @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where 0 is the first side seen in the connection and 1 is the second side seen
         * @param[in] tcpData The TCP data itself + connection information
         * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly2 c'tor (or NULL if no cookie provided)
         */
        typedef void(*OnMessageReady)(int side, NetFlowStreamData& stream_data, const ConnectionData& connectionData, STimeInfo& time_info, void* userCookie);

        /**
         * @typedef OnConnectionStart
         * A callback invoked when a new TCP connection is identified (whether it begins with a SYN packet or not)
         * @param[in] connectionData Connection information
         * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly2 c'tor (or NULL if no cookie provided)
         */
        typedef void(*OnConnectionStart)(ConnectionData& connectionData, void* userCookie);

        /**
         * @typedef OnConnectionEnd
         * A callback invoked when a TCP connection is terminated, either by a FIN or RST packet or manually by the user
         * @param[in] connectionData Connection information
         * @param[in] reason The reason for connection termination: FIN/RST packet or manually by the user
         * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly2 c'tor (or NULL if no cookie provided)
         */
        typedef void(*OnConnectionEnd)(ConnectionData& connectionData, ConnectionEndReason reason, void* userCookie);

    public:
        /**
         * A c'tor for this class
         * @param[in] onMessageReadyCallback The callback to be invoked when new data arrives
         * @param[in] userCookie A pointer to an object provided by the user. This pointer will be returned when invoking the various callbacks. This parameter is optional, default cookie is NULL
         * @param[in] onConnectionStartCallback The callback to be invoked when a new connection is identified. This parameter is optional
         * @param[in] onConnectionEndCallback The callback to be invoked when a new connection is terminated (either by a FIN/RST packet or manually by the user). This parameter is optional
         */
        NetFlowReassembler(OnMessageReady onMessageReadyCallback, void* userCookie = NULL, OnConnectionStart onConnectionStartCallback = NULL,
            OnConnectionEnd onConnectionEndCallback = NULL, bool bProcessNonTCPProtocols = false) :
            tcpReassembly(
                static_cast<TcpReassembly_t::OnTcpMessageReady>(&NetFlowReassembler::IntOnTcpMessageReady),
                this, 
                NetFlowReassembler::IntOnTcpConnectionStart, 
                NetFlowReassembler::IntOnTcpConnectionEnd),
            m_lastPacketTime({}),
            m_onMessageReadyCallback(onMessageReadyCallback),
            m_userCookie(userCookie),
            m_onConnectionStartCallback(onConnectionStartCallback),
            m_onConnectionEndCallback(onConnectionEndCallback),
            m_bProcessNonTCPProtocols(bProcessNonTCPProtocols),
            m_stats()
        {

        }

        NetFlowReassemblerStats GetStats()
        {
            return m_stats;
        }

        void reassemblePacket(Packet& pkt)
        {
            using namespace pcpp;
            m_lastPacketTime = pkt.getRawPacketReadOnly()->getPacketTimeStamp();
            if (!m_startTime.tv_sec) m_startTime = m_lastPacketTime;

            bool isTCPPacket = false;
            isTCPPacket = pkt.isPacketOfType(TCP);
            if (isTCPPacket)
            {
                tcpReassembly.reassemblePacket(pkt);
            }
            else if (m_bProcessNonTCPProtocols)
            {
                bool bDefragmentationRequired = false;
                bool isIPv4Packet = false;
                bool isIPv6Packet = false;
                if (pkt.isPacketOfType(IPv4))
                {
                    bDefragmentationRequired = isIPv4Packet = true;
                }
                else if (pkt.isPacketOfType(IPv6))
                {
                    bDefragmentationRequired = isIPv6Packet = true;
                }

                if (bDefragmentationRequired)
                {
                    IPReassembly::ReassemblyStatus status;

                    // process the packet in the IP reassembly mechanism
                    Packet* result = ipReassembly.processPacket(&pkt, status);

                    // write fragment/packet to file if:
                    // - packet is fully reassembled (status of REASSEMBLED)
                    // - packet isn't a fragment 
                    if (result && (status == IPReassembly::REASSEMBLED || status == IPReassembly::NON_FRAGMENT))
                    {
                        reassemblyNonTCPPacket(*result);
                        //writer->writePacket(*result->getRawPacket());
                        //stats.totalPacketsWritten++;
                    }
                }
            }
            m_lastPacketTime = timeval();
        }

        void reassemblePacket(RawPacket* rawPacket)
        {
            Packet parsedPacket(rawPacket);
            reassemblePacket(parsedPacket);
        }

    public:
        /**
         * Close a connection manually. If the connection doesn't exist or already closed an error log is printed. This method will cause the TcpReassembly2#OnTcpConnectionEnd to be invoked with
         * a reason of TcpReassembly2#TcpReassemblyConnectionClosedManually
         * @param[in] flowKey A 4-byte hash key representing the connection. Can be taken from a ConnectionData instance
         */
        void closeConnection(uint32_t flowKey);

        /**
         * Close all open connections manually. This method will cause the TcpReassembly2#OnTcpConnectionEnd to be invoked for each connection with a reason of
         * TcpReassembly2#TcpReassemblyConnectionClosedManually
         */
        void closeAllConnections();

    private:
        static void IntOnTcpMessageReady(int side, NetStreamData& tcpData, const ConnectionData& connInfo, void* userCookie)
        {
            NetFlowStreamData nfTcpData(tcpData.getData(), tcpData.getDataLength());
            //NetFlowConnectionData nfConnInfo(IPPROTO_TCP, tcpData.getConnectionData());
            static_cast<NetFlowReassembler*>(userCookie)->IntOnMessageReady(side, nfTcpData, connInfo);
        }

        void IntOnMessageReady(int side, NetFlowStreamData& tcpData, const ConnectionData& conn_info)
        {
            timeval t = m_lastPacketTime;
            STimeInfo ti = {
                m_lastPacketTime,
                time_utils::time_diff(m_startTime, t),
                time_utils::time_diff(conn_info.startTime, t)
            };
            m_onMessageReadyCallback(side, tcpData, conn_info, ti, m_userCookie);
        }

        static void IntOnTcpConnectionStart(ConnectionData& pcppConnectionData, void* userCookie)
        {
            //NetFlowConnectionData connectionData(IPPROTO_TCP, pcppConnectionData);
            auto& connectionData = pcppConnectionData;
            NetFlowReassembler* pThis = static_cast<NetFlowReassembler*>(userCookie);
            ++pThis->m_stats.nNumberOfProcessedConnections;
            pThis->m_onConnectionStartCallback(connectionData, pThis->m_userCookie);
        }

        static void IntOnTcpConnectionEnd(ConnectionData& pcppConnectionData, ConnectionEndReason reason, void* userCookie)
        {
            //NetFlowConnectionData connectionData(IPPROTO_TCP, pcppConnectionData);
            auto& connectionData = pcppConnectionData;
            NetFlowReassembler* pThis = static_cast<NetFlowReassembler*>(userCookie);
            pThis->m_onConnectionEndCallback(connectionData, reason, pThis->m_userCookie);
        }

        void reassemblyNonTCPPacket(Packet& packet)
        {
            using namespace pcpp;

            size_t dataPayloadSize = 0;
            uint8_t* pPayload = nullptr;
            uint8_t protocol = 0;

            if (!packet.isPacketOfType(IPv4) && !packet.isPacketOfType(IPv6)) {
                // No IP layer detected
                return;
            }
            {
                IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
                if (ipv4Layer != NULL)
                {
                    pPayload = ipv4Layer->getLayerPayload();
                    dataPayloadSize = ipv4Layer->getLayerPayloadSize();
                    protocol = ipv4Layer->getIPv4Header()->protocol;
                }
                else
                {
                    IPv6Layer* ipv6Layer = packet.getLayerOfType<IPv6Layer>();
                    if (!ipv6Layer) return;
                    pPayload = ipv6Layer->getLayerPayload();
                    dataPayloadSize = ipv6Layer->getLayerPayloadSize();
                    protocol = ipv6Layer->getIPv6Header()->nextHeader;
                }
            }

            if (protocol == IPPROTO_UDP) 
            {
                UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
                if (udpLayer) {
                    dataPayloadSize = udpLayer->getLayerPayloadSize();
                    pPayload = udpLayer->getLayerPayload();
                }
            }

            // calculate flow key for this packet
            SIPConnectionInfo connInfo;
            connInfo.Fill(&packet);

            uint32_t flowKey = netflow::hash5Tuple(connInfo);
            auto pConnection = tcpReassembly.LookupConnection(flowKey, connInfo);
            int conn_idx = 0;

            // if this packet belongs to a connection that was already closed (for example: data packet that comes after FIN), ignore it
            //if (m_ClosedConnectionList.find(flowKey) != m_ClosedConnectionList.end())
            while (pConnection && pConnection->bClosed)
            {
                //LOG_DEBUG("Ignoring packet of already closed flow [0x%X]", flowKey);
                return;
            }

            // calculate packet's source and dest IP address
            std::unique_ptr<pcpp::IPAddress> srcIP = connInfo.getSrcIpAddress();
            std::unique_ptr<pcpp::IPAddress> dstIP = connInfo.getDstIpAddress();

            // find the connection in the connection map
            if (!pConnection)
            {
                pConnection = tcpReassembly.CreateNewConnection(flowKey, connInfo);

                auto& c = pConnection->connection;
                timeval ts = packet.getRawPacket()->getPacketTimeStamp();
                c.setStartTime(ts);

                // fire connection start callback
                IntOnTcpConnectionStart(c, this);
            }
            //else // connection already exists
            {
                auto& c = pConnection->connection;
                timeval currTime = packet.getRawPacket()->getPacketTimeStamp();
                if (currTime.tv_sec > c.endTime.tv_sec ||
                    (currTime.tv_sec == c.endTime.tv_sec && currTime.tv_usec > c.endTime.tv_usec))
                {
                    c.setEndTime(currTime);
                }
            }

            auto& c = pConnection->connection;

            int sideIndex = -1;
            // check if packet matches side 0
            if (c.srcIP->equals(srcIP.get()) && c.connParams.portSrc == connInfo.portSrc)
            {
                sideIndex = 0;
            }
            // check if packet matches side 1
            else if (c.dstIP->equals(srcIP.get()) && c.connParams.portDst == connInfo.portSrc)
            {
                sideIndex = 1;
            }
            // packet doesn't match either side. This case doesn't make sense but it's handled anyway. Packet will be ignored
            else
            {
                //LOG_ERROR("Error occurred - packet doesn't match either side of the connection!!");
                return;
            }

            // send data to the callback
            NetFlowStreamData nfTcpData(pPayload, dataPayloadSize);
            IntOnMessageReady(sideIndex, nfTcpData, pConnection->connection);
        }


    private:
        timeval m_lastPacketTime;
        timeval m_startTime;
        OnMessageReady m_onMessageReadyCallback;
        OnConnectionStart m_onConnectionStartCallback;
        OnConnectionEnd m_onConnectionEndCallback;
        void* m_userCookie;
        bool m_bProcessNonTCPProtocols;

        IPReassembly ipReassembly;
        TcpReassembly_t tcpReassembly;
        NetFlowReassemblerStats m_stats;

        //std::map<uint32_t, NetFlowConnectionData*> m_ConnectionList;
        //std::vector<NetFlowConnectionData> m_ConnectionInfo;
    };

    void NetFlowReassembler::closeAllConnections()
    {
        tcpReassembly.closeAllConnections();
    }

}; // namespace netflow

#endif // __NETFLOW_REASSEMBLER__INCLUDED__