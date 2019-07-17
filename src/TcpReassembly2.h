#ifndef PACKETPP_TCP_REASSEMBLY2
#define PACKETPP_TCP_REASSEMBLY2

#include "Packet.h"
#include "IpAddress.h"
#include "PointerVector.h"
#include "IPUtilsEx.h"
#include <map>
#include <list>
#include <functional>

/**
 * @file
 * This source code is modified version of TcpReassembly.h from PcapPlusPlus library
 * This is an implementation of TCP reassembly logic, which means reassembly of TCP messages spanning multiple TCP segments (or packets).<BR>
 * This logic can be useful in analyzing messages for a large number of protocols implemented on top of TCP including HTTP, SSL/TLS, FTP and many many more.
 *
 * __General Features:__
 * - Manage multiple TCP connections under one pcpp#TcpReassembly2 instance
 * - Support TCP retransmission
 * - Support out-of-order packets
 * - Support missing TCP data
 * - TCP connections can end "naturally" (by FIN/RST packets) or manually by the user
 * - Support callbacks for new TCP data, connection start and connection end
 *
 * __Logic Description:__
 * - The user creates an instance of the pcpp#TcpReassembly2 class
 * - Then the user starts feeding it with TCP packets
 * - The pcpp#TcpReassembly2 instance manages all TCP connections from the packets it's being fed. For each connection it manages its 2 sides (A->B and B->A)
 * - When a packet arrives, it is first classified to a certain TCP connection
 * - Then it is classified to a certain side of the TCP connection
 * - Then the pcpp#TcpReassembly2 logic tries to understand if the data in this packet is the expected data (sequence-wise) and if it's new (e.g isn't a retransmission)
 * - If the packet data matches these criteria a callback is being invoked. This callback is supplied by the user in the creation of the pcpp#TcpReassembly2 instance. This callback contains
 *   the new data (of course), but also information about the connection (5-tuple, 4-byte hash key describing the connection, etc.) and also a pointer to a "user cookie", meaning a pointer to
 *   a structure provided by the user during the creation of the pcpp#TcpReassembly2 instance
 * - If the data in this packet isn't new, it's being ignored
 * - If the data in this packet isn't expected (meaning this packet came out-of-order), then the data is being queued internally and will be sent to the user when its turn arrives
 *   (meaning, after the data before arrives)
 * - If the missing data doesn't arrive until a new message from the other side of the connection arrives or until the connection ends - this will be considered as missing data and the
 *   queued data will be sent to the user, but the string "[X bytes missing]" will be added to the message sent in the callback
 * - pcpp#TcpReassembly2 supports 2 more callbacks - one is invoked when a new TCP connection is first seen and the other when it's ended (either by a FIN/RST packet or manually by the user).
 *   Both of these callbacks contain data about the connection (5-tuple, 4-byte hash key describing the connection, etc.) and also a pointer to a "user cookie", meaning a pointer to a
 *   structure provided by the user during the creation of the pcpp#TcpReassembly2 instance. The end connection callback also provides the reason for closing it ("naturally" or manually)
 *
 * __Basic Usage and APIs:__
 * - pcpp#TcpReassembly2 c'tor - Create an instance, provide the callbacks and the user cookie to the instance
 * - pcpp#TcpReassembly2#ReassemblePacket() - Feed pcpp#TcpReassembly2 instance with packets
 * - pcpp#TcpReassembly2#closeConnection() - Manually close a connection by a flow key
 * - pcpp#TcpReassembly2#closeAllConnections() - Manually close all currently opened connections
 * - pcpp#TcpReassembly2#OnTcpMessageReady callback - Invoked when new data arrives on a certain connection. Contains the new data as well as connection data (5-tuple, flow key)
 * - pcpp#TcpReassembly2#OnTcpConnectionStart callback - Invoked when a new connection is identified
 * - pcpp#TcpReassembly2#OnTcpConnectionEnd callback - Invoked when a connection ends (either by FIN/RST or manually by the user)
 */

/**
 * @namespace netflow
 */
namespace netflow
{
    using pcpp::IPAddress;
    //using pcpp::TcpReassembly;
    using pcpp::Packet;
    using pcpp::RawPacket;
    using pcpp::ProtocolType;

/**
 * @struct ConnectionData
 * Represents basic TCP/UDP + IP connection data
 */
struct ConnectionData
{
    SIPConnectionInfo connParams;

    /** Source IP address */
    IPAddress* srcIP;
    /** Destination IP address */
    IPAddress* dstIP;

    /** A 4-byte hash key representing the connection */
    uint32_t flowKey;
    /** Start TimeStamp of the connection */
    timeval startTime;
    /** End TimeStamp of the connection */
    timeval endTime;

    /**
     * A c'tor for this struct that basically zeros all members
     */
    ConnectionData() : connParams({}), srcIP(NULL), dstIP(NULL), flowKey(0), startTime(), endTime() {}

    /**
     * A d'tor for this strcut. Notice it frees the memory of srcIP and dstIP members
     */
    ~ConnectionData();

    /**
     * A copy constructor for this struct. Notice it clones ConnectionData#srcIP and ConnectionData#dstIP
     */
    ConnectionData(const ConnectionData& other);

    /**
     * An assignment operator for this struct. Notice it clones ConnectionData#srcIP and ConnectionData#dstIP
     */
    ConnectionData& operator=(const ConnectionData& other);

    /**
     * Set source IP
     * @param[in] sourceIP A pointer to the source IP to set. Notice the IPAddress object will be cloned
     */
    void setSrcIpAddress(const IPAddress* sourceIP) { srcIP = sourceIP->clone(); }

    /**
     * Set destination IP
     * @param[in] destIP A pointer to the destination IP to set. Notice the IPAddress object will be cloned
     */
    void setDstIpAddress(const IPAddress* destIP) { dstIP = destIP->clone(); }

    /**
     * Set startTime of Connection
     * @param[in] startTime integer value
     */
    void setStartTime(const timeval &startTime) { this->startTime = startTime; }

    /**
     * Set endTime of Connection
     * @param[in] endTime integer value
     */
    void setEndTime(const timeval &endTime) { this->endTime = endTime; }

    

private:

    void copyData(const ConnectionData& other);
};


//class TcpReassembly2;


/**
 * @class TcpStreamData
 * When following a TCP connection each packet may contain a piece of the data transferred between the client and the server. This class represents these pieces: each instance of it
 * contains a piece of data, usually extracted from a single packet, as well as information about the connection
 */
class NetStreamData
{
    //friend class TcpReassembly2;

public:

    /**
     * A c'tor for this class that basically zeros all members
     */
    NetStreamData();

    /**
     * A c'tor for this class that get data from outside and set the internal members. Notice that when this class is destroyed it also frees the TCP data it stores
     * @param[in] tcpData A buffer containing the TCP data piece
     * @param[in] tcpDataLength The length of the buffer
     * @param[in] connData TCP connection information for this TCP data
     */
    NetStreamData(uint8_t* tcpData, size_t tcpDataLength, bool bDataOwner = true);

    /**
     * A d'tor for this class
     */
    ~NetStreamData();

    /**
     * A copy c'tor for this class. Notice the data buffer is copied from the source instance to this instance, so even if the source instance is destroyed the data in this instance
     * stays valid. When this instance is destroyed it also frees the data buffer
     * @param[in] other The instance to copy from
     */
    NetStreamData(NetStreamData& other);

    /**
     * Overload of the assignment operator. Notice the data buffer is copied from the source instance to this instance, so even if the source instance is destroyed the data in this instance
     * stays valid. When this instance is destroyed it also frees the data buffer
     * @param[in] other The instance to copy from
     * @return A reference to this instance
     */
    NetStreamData& operator=(const NetStreamData& other);

    /**
     * A getter for the data buffer
     * @return A pointer to the buffer
     */
    uint8_t* getData() const { return m_Data; }

    /**
     * A getter for buffer length
     * @return Buffer length
     */
    size_t getDataLength() const { return m_DataLen; }

private:
    uint8_t* m_Data;
    size_t m_DataLen;
    //ConnectionData m_Connection;
    bool m_bOwner;

    void setDeleteDataOnDestruction(bool flag) { m_bOwner = flag; }
    void copyData(const NetStreamData& other);
};

struct SConnMgrCtxBase
{
};

template<class TCtx/* = SConnMgrTCPReassemblyCtx<> */>
struct TConnectionsMgr
{
    typedef TCtx Ctx_t;
    typedef std::shared_ptr<TCtx> CtxPtr_t;
    std::map<uint32_t /*hash*/, std::list<CtxPtr_t>> m_ConnectionList;
};

/**
 * @class TcpReassembly2
 * A class containing the TCP reassembly logic. Please refer to the documentation at the top of TcpReassembly2.h for understanding how to use this class
 */
class TcpReassembly2Base
{
public:
    /**
     * An enum for connection end reasons
     */
    enum ConnectionEndReason
    {
        /** Connection ended because of FIN or RST packet */
        TcpReassemblyConnectionClosedByFIN_RST,
        /** Connection ended manually by the user */
        TcpReassemblyConnectionClosedManually
    };

    /**
     * @typedef OnTcpMessageReady
     * A callback invoked when new data arrives on a connection
     * @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where 0 is the first side seen in the connection and 1 is the second side seen
     * @param[in] tcpData The TCP data itself + connection information
     * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly2 c'tor (or NULL if no cookie provided)
     */
    typedef void (*OnTcpMessageReady)(int side, NetStreamData& tcpData, const ConnectionData& connInfo, void* userCookie);
    /**
     * @typedef OnTcpConnectionStart
     * A callback invoked when a new TCP connection is identified (whether it begins with a SYN packet or not)
     * @param[in] connectionData Connection information
     * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly2 c'tor (or NULL if no cookie provided)
     */
    typedef void (*OnTcpConnectionStart)(ConnectionData& connectionData, void* userCookie);

    /**
     * @typedef OnTcpConnectionEnd
     * A callback invoked when a TCP connection is terminated, either by a FIN or RST packet or manually by the user
     * @param[in] connectionData Connection information
     * @param[in] reason The reason for connection termination: FIN/RST packet or manually by the user
     * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly2 c'tor (or NULL if no cookie provided)
     */
    typedef void (*OnTcpConnectionEnd)(ConnectionData& connectionData, ConnectionEndReason reason, void* userCookie);

    /**
     * A c'tor for this class
     * @param[in] onMessageReadyCallback The callback to be invoked when new data arrives
     * @param[in] userCookie A pointer to an object provided by the user. This pointer will be returned when invoking the various callbacks. This parameter is optional, default cookie is NULL
     * @param[in] onConnectionStartCallback The callback to be invoked when a new connection is identified. This parameter is optional
     * @param[in] onConnectionEndCallback The callback to be invoked when a new connection is terminated (either by a FIN/RST packet or manually by the user). This parameter is optional
     */
    TcpReassembly2Base(OnTcpMessageReady onMessageReadyCallback, void* userCookie = NULL, OnTcpConnectionStart onConnectionStartCallback = NULL, OnTcpConnectionEnd onConnectionEndCallback = NULL);

    /**
     * A d'tor for this class. Frees all internal structures. Notice that if the d'tor is called while connections are still open, all data is lost and TcpReassembly2#OnTcpConnectionEnd won't
     * be called for those connections
     */
    ~TcpReassembly2Base();

    /**
     * The most important method of this class which gets a packet from the user and processes it. If this packet opens a new connection, ends a connection or contains new data on an
     * existing connection, the relevant callback will be called (TcpReassembly2#OnTcpMessageReady, TcpReassembly2#OnTcpConnectionStart, TcpReassembly2#OnTcpConnectionEnd)
     * @param[in] tcpData A reference to the packet to process
     */
    void reassemblePacket(Packet& tcpData);

    /**
     * The most important method of this class which gets a raw packet from the user and processes it. If this packet opens a new connection, ends a connection or contains new data on an
     * existing connection, the relevant callback will be invoked (TcpReassembly2#OnTcpMessageReady, TcpReassembly2#OnTcpConnectionStart, TcpReassembly2#OnTcpConnectionEnd)
     * @param[in] tcpRawData A reference to the raw packet to process
     */
    void reassemblePacket(RawPacket* tcpRawData);

    /**
     * Close a connection manually. If the connection doesn't exist or already closed an error log is printed. This method will cause the TcpReassembly2#OnTcpConnectionEnd to be invoked with
     * a reason of TcpReassembly2#TcpReassemblyConnectionClosedManually
     * @param[in] flowKey A 4-byte hash key representing the connection. Can be taken from a ConnectionData instance
     */
    void closeConnection(const ConnectionData& connData);

    /**
     * Close all open connections manually. This method will cause the TcpReassembly2#OnTcpConnectionEnd to be invoked for each connection with a reason of
     * TcpReassembly2#TcpReassemblyConnectionClosedManually
     */
    void closeAllConnections();

    /**
     * Get a list of all connections managed by this TcpReassembly2 instance (both connections that are open and those that are already closed)
     * @return A list of all connections managed. Notice this list is constant and cannot be changed by the user
     */
    const std::vector<ConnectionData>& getConnectionInformation() const;

    /**
     * Check if a certain connection managed by this TcpReassembly2 instance is currently opened or closed
     * @param[in] connection The connection to check
     * @return A positive number (> 0) if connection is opened, zero (0) if connection is closed, and a negative number (< 0) if this connection isn't managed by this TcpReassembly2 instance
     */
    int isConnectionOpen(const ConnectionData& connection) const;

protected:
    struct TcpFragment
    {
        uint32_t sequence;
        size_t dataLength;
        uint8_t* data;

        TcpFragment() { sequence = 0; dataLength = 0; data = NULL; }
        ~TcpFragment() { if (data != NULL) delete [] data; }
    };

    struct TcpOneSideData
    {
        IPAddress* srcIP;
        uint16_t srcPort;
        uint32_t sequence;
        pcpp::PointerVector<TcpFragment> tcpFragmentList;
        bool gotFinOrRst;

        void setSrcIP(IPAddress* sourrcIP);

        TcpOneSideData() { srcIP = NULL; srcPort = 0; sequence = 0; gotFinOrRst = false; }

        ~TcpOneSideData() { if (srcIP != NULL) delete srcIP; }
    };

    struct TcpReassemblyData
    {
        int numOfSides;
        int prevSide;
        TcpOneSideData twoSides[2];
        //ConnectionData connData;

        TcpReassemblyData() { numOfSides = 0; prevSide = -1; }
    };

    struct SConnMgrTCPReassemblyBaseCtx
    {
        ConnectionData connection;
        std::shared_ptr<TcpReassemblyData> tcpReassemblyData;
        bool bClosed = false;
        int conn_idx = 0; // The index of connection with same parameters
    };

    OnTcpMessageReady m_OnMessageReadyCallback;
    OnTcpConnectionStart m_OnConnStart;
    OnTcpConnectionEnd m_OnConnEnd;
    void* m_UserCookie;

    //std::map<uint32_t, TcpReassemblyData*> m_ConnectionList;
    //std::map<uint32_t, bool> m_ClosedConnectionList;
    //std::vector<ConnectionData> m_ConnectionInfo;

    void checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, SConnMgrTCPReassemblyBaseCtx* pConnection, int sideIndex, bool cleanWholeFragList);

    std::string prepareMissingDataMessage(uint32_t missingDataLen);

    void handleFinOrRst(TcpReassemblyData* tcpReassemblyData, SConnMgrTCPReassemblyBaseCtx* pConnection, int sideIndex, uint32_t flowKey);

    void closeConnectionInternal(SConnMgrTCPReassemblyBaseCtx* pConnection, ConnectionEndReason reason);

protected:
    virtual SConnMgrTCPReassemblyBaseCtx* CreateNewConnection(uint32_t flowKey, const SIPConnectionInfo& connInfo) = 0;
    virtual SConnMgrTCPReassemblyBaseCtx* LookupConnection(uint32_t flowKey, const SIPConnectionInfo& connInfo) const = 0;
    virtual void ForEachConnection(std::function<bool(SConnMgrTCPReassemblyBaseCtx* pConn)> fnOnConnection) = 0;
    virtual void ClearAllConnections() = 0;
};

template<class TBaseCtx = SConnMgrCtxBase, class TFriend = void>
class TcpReassembly2: public TcpReassembly2Base
{
public:
    friend TFriend;
    struct SConnMgrTCPReassemblyCtx : public SConnMgrTCPReassemblyBaseCtx, public TBaseCtx
    {
    };
    typedef TConnectionsMgr< SConnMgrTCPReassemblyCtx > ConnMgr_t;

public:
    TcpReassembly2(OnTcpMessageReady onMessageReadyCallback, void* userCookie = NULL, OnTcpConnectionStart onConnectionStartCallback = NULL, OnTcpConnectionEnd onConnectionEndCallback = NULL) :
        TcpReassembly2Base(onMessageReadyCallback, userCookie, onConnectionStartCallback, onConnectionEndCallback) {}

protected:
    SConnMgrTCPReassemblyBaseCtx* CreateNewConnection(uint32_t flowKey, const SIPConnectionInfo& connInfo) override
    {
        auto& lst = m_connMgr.m_ConnectionList[flowKey];
        auto spNewItem = std::make_shared<ConnMgr_t::Ctx_t>();
        auto new_item = lst.insert(lst.begin(), std::move(spNewItem));
        auto pNewItem = static_cast<SConnMgrTCPReassemblyBaseCtx*>(new_item->get());
        auto& conn = pNewItem->connection;
        conn.connParams = connInfo;
        conn.flowKey = flowKey;
        conn.setSrcIpAddress(connInfo.getSrcIpAddress().get());
        conn.setDstIpAddress(connInfo.getDstIpAddress().get());
        return pNewItem;
    }
    
    SConnMgrTCPReassemblyBaseCtx* LookupConnection(uint32_t flowKey, const SIPConnectionInfo& connInfo) const override
    {
        auto it = m_connMgr.m_ConnectionList.find(flowKey);
        while (it != m_connMgr.m_ConnectionList.end()) 
        {
            auto& lst = it->second;
            for (auto& spCtx : lst) {
                auto pItem = static_cast<SConnMgrTCPReassemblyBaseCtx*>(spCtx.get());
                if (pItem->connection.connParams.EqualAnySide(connInfo)) {
                    return pItem;
                }
            }
            break;
        }
        return nullptr;
    }

    void ForEachConnection(std::function<bool(SConnMgrTCPReassemblyBaseCtx* pConn)> fnOnConnection) override
    {
        auto itNext = m_connMgr.m_ConnectionList.begin();
        for (auto it = itNext; it != m_connMgr.m_ConnectionList.end(); it = itNext)
        {
            itNext = it;
            ++itNext;

            auto& lst = it->second;
            auto itNextLst = lst.begin();
            for (auto itLst = itNextLst; itLst != lst.end(); itLst = itNextLst)
            {
                itNextLst = itLst;
                ++itNextLst;
                auto spConn = *itLst;
                auto pConn = static_cast<SConnMgrTCPReassemblyBaseCtx*>(spConn.get());
                if (!fnOnConnection(pConn)) {
                    return;
                }
            }
        }
    }

    void ClearAllConnections() override
    {
        m_connMgr.m_ConnectionList.clear();
    }

protected:
    ConnMgr_t m_connMgr;
};

}

#endif /* PACKETPP_TCP_REASSEMBLY2 */
