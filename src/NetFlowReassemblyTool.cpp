/**
 * TcpReassemblyEx application
 * =========================
 * This is an application that captures data transmitted as part of TCP connections, organizes the data and stores it in a way that is convenient for protocol analysis and debugging.
 * This application reconstructs the TCP data streams and stores each connection in a separate file(s). TcpReassemblyEx understands TCP sequence numbers and will correctly reconstruct
 * data streams regardless of retransmissions, out-of-order delivery or data loss.
 * TcpReassemblyEx works more or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options.
 * The main purpose of it is to demonstrate the TCP reassembly capabilities in PcapPlusPlus.
 * Main features and capabilities:
 *   - Captures packets from pcap/pcapng files or live traffic
 *   - Handles TCP retransmission, out-of-order packets and packet loss
 *   - Possibility to set a BPF filter to process only part of the traffic
 *   - Write each connection to a separate file
 *   - Write each side of each connection to a separate file
 *   - Limit the max number of open files in each point in time (to avoid running out of file descriptors for large files / heavy traffic)
 *   - Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in each side + total), number of TCP messages (in each side + total),
 *     number of bytes (in each side + total)
 *   - Write to console only (instead of files)
 *   - Set a directory to write files to (default is current directory)
 *
 * For more details about modes of operation and parameters run TcpReassemblyEx -h
 */

#include "NetFlowReassembler.h"
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
#include <getopt.h>
#ifdef _WIN32
#include <direct.h>
#endif

using namespace netflow;
using namespace pcpp;

inline 
std::string time_str_for_fname(timeval t)
{
    time_t nowtime;
    struct tm nowtm;
    char tmbuf[64];

    nowtime = t.tv_sec;
    if (localtime_s(&nowtm, &nowtime)) nowtm = tm();
    strftime(tmbuf, sizeof tmbuf, "%Y%m%d%H%M%S", &nowtm);
    return tmbuf;
}


#define EXIT_WITH_ERROR(reason, ...) do { \
    printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
    printUsage(); \
    exit(1); \
    } while(0)


#if defined(WIN32) || defined(WINx64)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif


// unless the user chooses otherwise - default number of concurrent used file descriptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 500


static struct option TcpAssemblyOptions[] =
{
    {"interface",  required_argument, 0, 'i'},
    {"input-file",  required_argument, 0, 'r'},
    {"output-dir", required_argument, 0, 'o'},
    {"list-interfaces", no_argument, 0, 'l'},
    {"filter", required_argument, 0, 'e'},
    {"chunks-header", no_argument, 0, 'd'},
    {"json", no_argument, 0, 'j'},
    {"write-metadata", no_argument, 0, 'm'},
    {"write-to-console", no_argument, 0, 'c'},
    {"separate-sides", no_argument, 0, 's'},
    {"max-file-desc", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};


/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the application
 */
class GlobalConfig
{
private:

    /**
     * A private c'tor (as this is a singleton)
     */
    GlobalConfig() { 
        writeMetadata = false; 
        outputDir = ""; 
        writeToConsole = false; 
        separateSides = false; 
        writeChunksHeader = false; 
        writeJsonData = false;
        maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES; 
        m_RecentConnsWithActivity = NULL;
    }

    // A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key. This LRU list is used to decide which connection was seen least
    // recently in case we reached max number of open file descriptors and we need to decide which files to close
    LRUList<uint32_t>* m_RecentConnsWithActivity;

public:

    // a flag indicating whether to write a metadata file for each connection (containing several stats)
    bool writeMetadata;

    // the directory to write files to (default is current directory)
    std::string outputDir;

    // a flag indicating whether to write TCP data to actual files or to console
    bool writeToConsole;

    // a flag indicating whether to write both side of a connection to the same file (which is the default) or write each side to a separate file
    bool separateSides;

    // max number of allowed open files in each point in time
    size_t maxOpenFiles;

    // a flag indicating whether to write data chunk header before each data chunk
    bool writeChunksHeader;

    // a flag indicating whether to write data chunks as JSON-encoded line
    bool writeJsonData;

    /**
     * A method getting connection parameters as input and returns a filename and file path as output.
     * The filename is constructed by the IPs (src and dst) and the TCP ports (src and dst)
     */
    std::string getFileName(ConnectionData connData, int side, bool separareSides)
    {
        std::stringstream stream;

        // if user chooses to write to a directory other than the current directory - add the dir path to the return value
        if (outputDir != "")
            stream << outputDir << SEPARATOR;
        
        std::string timeStart = time_str_for_fname(connData.startTime);

        std::string sourceIP = connData.srcIP->toString();
        std::string destIP = connData.dstIP->toString();
        std::string protocol = netflow::protocol_number_to_name(connData.connParams.protocol);

        // for IPv6 addresses, replace ':' with '_'
        std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
        std::replace(destIP.begin(), destIP.end(), ':', '_');

        stream << timeStart << "-" << protocol << "-";

        // side == 0 means data is sent from client->server
        if (side <= 0 || separareSides == false)
            stream << sourceIP << "." << connData.connParams.portSrc << "-" << destIP << "." << connData.connParams.portDst;
        else // side == 1 means data is sent from server->client
            stream << destIP << "." << connData.connParams.portDst << "-" << sourceIP << "." << connData.connParams.portSrc;

        // return the file path
        return stream.str();
    }

    /**
     * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file or overwrite it.
     * Return value is a pointer to the new file stream
     */
    std::ostream* openFileStream(std::string fileName, bool reopen)
    {
        // if the user chooses to write only to console, don't open anything and return std::cout
        if (writeToConsole)
            return &std::cout;

        // open the file on the disk (with append or overwrite mode)
        if (reopen)
            return new std::ofstream(fileName.c_str(), std::ios_base::binary | std::ios_base::app);
        else
            return new std::ofstream(fileName.c_str(), std::ios_base::binary);
    }


    /**
     * Close a file stream
     */
    void closeFileSteam(std::ostream* fileStream)
    {
        // if the user chooses to write only to console - do nothing and return
        if (!writeToConsole)
        {
            // close the file stream
            std::ofstream* fstream = (std::ofstream*)fileStream;
            fstream->close();

            // free the memory of the file stream
            delete fstream;
        }
    }


    /**
     * Return a pointer to the least-recently-used (LRU) list of connections
     */
    LRUList<uint32_t>* getRecentConnsWithActivity()
    {
        // his is a lazy implementation - the instance isn't created until the user requests it for the first time.
        // the side of the LRU list is determined by the max number of allowed open files at any point in time. Default is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES
        // but the user can choose another number
        if (m_RecentConnsWithActivity == NULL)
            m_RecentConnsWithActivity = new LRUList<uint32_t>(maxOpenFiles);

        // return the pointer
        return m_RecentConnsWithActivity;
    }


    /**
     * The singleton implementation of this class
     */
    static inline GlobalConfig& getInstance()
    {
        static GlobalConfig instance;
        return instance;
    }
};


/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats data on the connection
 */
struct NetFlowReassemblyData
{
    // pointer to 2 file stream - one for each side of the connection. If the user chooses to write both sides to the same file (which is the default), only one file stream is used (index 0)
    std::ostream* fileStreams[2];

    // flags indicating whether the file in each side was already opened before. If the answer is yes, next time it'll be opened in append mode (and not in overwrite mode)
    bool reopenFileStreams[2];

    // a flag indicating on which side was the latest message on this connection
    int curSide;

    // stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
    int numOfDataPackets[2];
    int numOfMessagesFromSide[2];
    int bytesFromSide[2];

    /**
     * the default c'tor
     */
    NetFlowReassemblyData() { fileStreams[0] = NULL; fileStreams[1] = NULL; clear(); }

    /**
     * The default d'tor
     */
    ~NetFlowReassemblyData()
    {
        // close files on both sides if open
        if (fileStreams[0] != NULL)
            GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);

        if (fileStreams[1] != NULL)
            GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);
    }

    /**
     * Clear all data (put 0, false or NULL - whatever relevant for each field)
     */
    void clear()
    {
        // for the file stream - close them if they're not null
        if (fileStreams[0] != NULL)
        {
            GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);
            fileStreams[0] = NULL;
        }

        if (fileStreams[1] != NULL)
        {
            GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);
            fileStreams[1] = NULL;
        }

        reopenFileStreams[0] = false;
        reopenFileStreams[1] = false;
        numOfDataPackets[0] = 0;
        numOfDataPackets[1] = 0;
        numOfMessagesFromSide[0] = 0;
        numOfMessagesFromSide[1] = 0;
        bytesFromSide[0] = 0;
        bytesFromSide[1] = 0;
        curSide = -1;
    }
};


// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, NetFlowReassemblyData> NetFlowReassemblyConnMgr;
typedef NetFlowReassemblyConnMgr::iterator NetFlowReassemblyConnMgrIter;


/**
 * Print application usage
 */
void printUsage()
{
    printf("\nUsage:\n"
            "------\n"
            "%s [-hvlcmsdj] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]\n"
            "\nOptions:\n\n"
            "    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file\n"
            "    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface\n"
            "    -o output_dir : Specify output directory (default is '.')\n"
            "    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets\n"
            "    -f max_files  : Maximum number of file descriptors to use\n"
            "    -c            : Write all output to console (nothing will be written to files)\n"
            "    -m            : Write a metadata file for each connection\n"
            "    -s            : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)\n"
            "    -d            : Write data chunks headers (by default data is written without any splitter)\n"
            "    -j            : Write data chunks and metadata in JSON format (one line for each data chunk)\n"
            "    -l            : Print the list of interfaces and exit\n"
            "    -v            : Displays the current version and exists\n"
            "    -h            : Display this help message and exit\n\n", AppName::get().c_str());
    exit(0);
}


/**
 * Print application version
 */
void printAppVersion()
{
    using namespace pcpp;
    printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
    printf("Built: %s\n", getBuildDateTime().c_str());
    printf("Built from: %s\n", getGitInfo().c_str());
    exit(0);
}


/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
    const std::vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    printf("\nNetwork interfaces:\n");
    for (std::vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
        printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
    }
    exit(0);
}

static void data_to_hex_and_visible(size_t data_len, void* data, std::string& dataHex, std::string& dataVisible)
{
    size_t l = data_len * 2;
    size_t vis_pos = 0;
    const unsigned char* chunk_data = (const unsigned char*)data;
    dataHex.resize(l);
    dataVisible.resize(data_len * 6); // '\u00FF'
    for (size_t i = 0; i < l; ++i) {
        char v = (chunk_data[i >> 1] >> ((i & 1) ? 0 : 4)) & 0xF;
        v += (v >= 10) ? ('A' - 10) : '0';
        dataHex[i] = v;
    }
    l >>= 1;
    for (size_t i = 0; i < l; ++i)
    {
        char v = (char)chunk_data[i];
        switch (v)
        {
        case '\b':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = 'b';
            break;
        case '\r':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = 'r';
            break;
        case '\n':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = 'n';
            break;
        case '\f':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = 'f';
            break;
        case '\t':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = 't';
            break;
        case '"':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = '"';
            break;
        case '\\':
            dataVisible[vis_pos++] = '\\';
            dataVisible[vis_pos++] = '\\';
            break;
        default:
            if (v < ' ' || v >= 0x7F) { 
                // '\u00FF'
                dataVisible[vis_pos++] = '\\';
                dataVisible[vis_pos++] = 'u';
                dataVisible[vis_pos++] = '0';
                dataVisible[vis_pos++] = '0';
                dataVisible[vis_pos++] = dataHex[i * 2];
                dataVisible[vis_pos++] = dataHex[i * 2 + 1];
            }
            else {
                dataVisible[vis_pos++] = v;
            }
        }
    }
    dataVisible.resize(vis_pos);
}


/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int sideIndex, NetFlowStreamData& tcpData, const ConnectionData& connectionData, STimeInfo& t, void* userCookie)
{
    // extract the connection manager from the user cookie
    NetFlowReassemblyConnMgr* connMgr = (NetFlowReassemblyConnMgr*)userCookie;

    // check if this flow already appears in the connection manager. If not add it
    NetFlowReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);
    if (iter == connMgr->end())
    {
        connMgr->insert(std::make_pair(connectionData.flowKey, NetFlowReassemblyData()));
        iter = connMgr->find(connectionData.flowKey);
    }

    int side;

    // if the user wants to write each side in a different file - set side as the sideIndex, otherwise write everything to the same file ("side 0")
    if (GlobalConfig::getInstance().separateSides)
        side = sideIndex;
    else
        side = 0;

    // if the file stream on the relevant side isn't open yet (meaning it's the first data on this connection)
    if (iter->second.fileStreams[side] == NULL)
    {
        // add the flow key of this connection to the list of open connections. If the return value isn't NULL it means that there are too many open files
        // and we need to close the connection with least recently used file(s) in order to open a new one.
        // The connection with the least recently used file is the return value
        uint32_t* flowKeyToCloseFiles = GlobalConfig::getInstance().getRecentConnsWithActivity()->put(connectionData.flowKey);

        // if flowKeyToCloseFiles isn't NULL it means we need to close the open files in this connection (the one with the least recently used files)
        if (flowKeyToCloseFiles != NULL)
        {
            // find the connection from the flow key
            NetFlowReassemblyConnMgrIter iter2 = connMgr->find(*flowKeyToCloseFiles);
            if (iter2 != connMgr->end())
            {
                // close files on both sides (if they're open)
                for (int index = 0; index < 1; index++)
                {
                    if (iter2->second.fileStreams[index] != NULL)
                    {
                        // close the file
                        GlobalConfig::getInstance().closeFileSteam(iter2->second.fileStreams[index]);
                        iter2->second.fileStreams[index] = NULL;

                        // set the reopen flag to true to indicate that next time this file will be opened it will be opened in append mode (and not overwrite mode)
                        iter2->second.reopenFileStreams[index] = true;
                    }
                }
            }

            delete flowKeyToCloseFiles;
        }

        // get the file name according to the 5-tuple etc.
        std::string fileName = GlobalConfig::getInstance().getFileName(
            connectionData, sideIndex, GlobalConfig::getInstance().separateSides) +
            (GlobalConfig::getInstance().writeJsonData ? ".json" : ".txt");

        // open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was already opened before)
        iter->second.fileStreams[side] = GlobalConfig::getInstance().openFileStream(fileName, iter->second.reopenFileStreams[side]);
    }

    // if this messages comes on a different side than previous message seen on this connection
    if (sideIndex != iter->second.curSide)
    {
        // count number of message in each side
        iter->second.numOfMessagesFromSide[sideIndex]++;

        // set side index as the current active side
        iter->second.curSide = sideIndex;
    }

    // count number of packets and bytes in each side of the connection
    iter->second.numOfDataPackets[sideIndex]++;
    iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

    if (GlobalConfig::getInstance().writeJsonData)
    {
        std::stringstream ss;
        std::string dataHex;
        std::string dataVisible;
        data_to_hex_and_visible(tcpData.getDataLength(), (char*)tcpData.getData(), dataHex, dataVisible);
        ss << std::fixed << std::setprecision(5) <<
            "{"
                "\"side\":\"" << sideIndex << "\","
                "\"time\":{"
                    "\"abs\":\"" << time_utils::time_double(t.absolute_time) << "\"," 
                    "\"conn\":\"" << time_utils::time_double(t.relative_connection_time) << "\""
                "},"
                "\"size\":\"" << tcpData.getDataLength() << "\","
                "\"data\":\"" << dataVisible << "\","
                "\"data_hex\":\"" << dataHex << "\""
            "}\r\n";
        std::string dataChunkStr = ss.str();
        // write the new data to the file
        iter->second.fileStreams[side]->write((char*)dataChunkStr.c_str(), dataChunkStr.length());
    }
    else 
    {
        if (GlobalConfig::getInstance().writeChunksHeader)
        {
            std::stringstream ss;
            ss <<
                "\r\n"
                "{\"_\":\"--------------------\","
                "\"side\":\"" << sideIndex << "\","
                "\"size\":\"" << tcpData.getDataLength() << "\""
                "}\r\n";
            std::string splitter = ss.str();
            iter->second.fileStreams[side]->write((char*)splitter.c_str(), splitter.length());
        }
        // write the new data to the file
        iter->second.fileStreams[side]->write((char*)tcpData.getData(), tcpData.getDataLength());
    }
}


/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(ConnectionData& connectionData, void* userCookie)
{
    // get a pointer to the connection manager
    NetFlowReassemblyConnMgr* connMgr = (NetFlowReassemblyConnMgr*)userCookie;

    // look for the connection in the connection manager
    NetFlowReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

    // assuming it's a new connection
    if (iter == connMgr->end())
    {
        // add it to the connection manager
        connMgr->insert(std::make_pair(connectionData.flowKey, NetFlowReassemblyData()));
    }
}


/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(ConnectionData& connectionData, NetFlowReassembler::ConnectionEndReason reason, void* userCookie)
{
    // get a pointer to the connection manager
    NetFlowReassemblyConnMgr* connMgr = (NetFlowReassemblyConnMgr*)userCookie;

    // find the connection in the connection manager by the flow key
    NetFlowReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

    // connection wasn't found - shouldn't get here
    if (iter == connMgr->end())
        return;

    // write a metadata file if required by the user
    if (GlobalConfig::getInstance().writeMetadata)
    {
        if (GlobalConfig::getInstance().writeJsonData)
        {
            std::string fileName = GlobalConfig::getInstance().getFileName(connectionData, 0, false) + "-metadata.json";
            std::ofstream metadataFile(fileName.c_str());

            metadataFile << std::fixed << std::setprecision(5) <<
                "{\n"
                    "\t\"total\": {"
                        "\"bytes\":\"" << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << "\","
                        "\"packets\":\"" << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << "\","
                        "\"messages\":\"" << (iter->second.numOfMessagesFromSide[0] + iter->second.numOfMessagesFromSide[1]) << "\""
                    "},\n"
                    "\t\"side_0\":{"
                        "\"bytes\":\"" << (iter->second.bytesFromSide[0]) << "\","
                        "\"packets\":\"" << (iter->second.numOfDataPackets[0]) << "\","
                        "\"messages\":\"" << (iter->second.numOfMessagesFromSide[0]) << "\""
                    "},\n"
                    "\t\"side_1\":{"
                        "\"bytes\":\"" << (iter->second.bytesFromSide[1]) << "\","
                        "\"packets\":\"" << (iter->second.numOfDataPackets[1]) << "\","
                        "\"messages\":\"" << (iter->second.numOfMessagesFromSide[1]) << "\""
                    "}\n"
                "}\n";
            
            metadataFile.close();
        }
        else
        {
            std::string fileName = GlobalConfig::getInstance().getFileName(connectionData, 0, false) + "-metadata.txt";
            std::ofstream metadataFile(fileName.c_str());
            metadataFile << "Number of data packets in side 0:  " << iter->second.numOfDataPackets[0] << std::endl;
            metadataFile << "Number of data packets in side 1:  " << iter->second.numOfDataPackets[1] << std::endl;
            metadataFile << "Total number of data packets:      " << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << std::endl;
            metadataFile << std::endl;
            metadataFile << "Number of bytes in side 0:         " << iter->second.bytesFromSide[0] << std::endl;
            metadataFile << "Number of bytes in side 1:         " << iter->second.bytesFromSide[1] << std::endl;
            metadataFile << "Total number of bytes:             " << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << std::endl;
            metadataFile << std::endl;
            metadataFile << "Number of messages in side 0:      " << iter->second.numOfMessagesFromSide[0] << std::endl;
            metadataFile << "Number of messages in side 1:      " << iter->second.numOfMessagesFromSide[1] << std::endl;
            metadataFile.close();
        }
    }

    // remove the connection from the connection manager
    connMgr->erase(iter);
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void* cookie)
{
    bool* shouldStop = (bool*)cookie;
    *shouldStop = true;
}


/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(RawPacket* packet, PcapLiveDevice* dev, void* tcpReassemblyCookie)
{
    // get a pointer to the TCP reassembly instance and feed the packet arrived to it
    NetFlowReassembler* tcpReassembly = (NetFlowReassembler*)tcpReassemblyCookie;
    tcpReassembly->reassemblePacket(packet);
}

std::vector<std::string> expand_file_names(const std::vector<std::string>& fileNames)
{
    std::vector<std::string> vecRes;
    for (auto& fileName : fileNames) {
        // ToDO: to implement *.pcap => [1.pcap; 2.pcap; ...]
        vecRes.push_back(fileName);
    }
    return vecRes;
}

void finalize_and_show_stats(NetFlowReassembler& reasm)
{
    //// extract number of connections before closing all of them
    //size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

    // close all connections which are still opened
    reasm.closeAllConnections();

    printf("Done! processed %I64u connections\n", reasm.GetStats().nNumberOfProcessedConnections);
}

/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void doTcpReassemblyOnPcapFiles(const std::vector<std::string>& fileNameMasks, NetFlowReassembler& tcpReassembly, std::string bpfFiler = "")
{
    std::vector<std::string> fileNames = expand_file_names(fileNameMasks);
    std::vector<std::unique_ptr<IFileReaderDevice>> vecReaders;

    for (auto& fileName : fileNames) 
    {
        // open input file (pcap or pcapng file)
        printf("Opening file '%s'.\n", fileName.c_str());
        IFileReaderDevice* reader = IFileReaderDevice::getReader(fileName.c_str());
        std::unique_ptr<IFileReaderDevice> spReader(reader);

        // try to open the file device
        if (!reader->open()) {
            continue;
        }

        // set BPF filter if set by the user
        if (bpfFiler != "")
        {
            if (!reader->setFilter(bpfFiler))
                EXIT_WITH_ERROR("Cannot set BPF filter to pcap file");
        }

        vecReaders.push_back(std::move(spReader));
    }

    if (vecReaders.empty()) {
        EXIT_WITH_ERROR("Cannot open pcap/pcapng file");
    }

    for (auto& spReader : vecReaders)
    {
        auto reader = spReader.get();
        printf("Processing file '%s'.\n", reader->getFileName().c_str());

        // run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
        RawPacket rawPacket;
        while (reader->getNextPacket(rawPacket))
        {
            //timeval = rawPacket.getPacketTimeStamp()
            tcpReassembly.reassemblePacket(&rawPacket);
        }

        reader->close();
    }

    finalize_and_show_stats(tcpReassembly);
}

/**
 * The method responsible for TCP reassembly on live traffic
 */
void doTcpReassemblyOnLiveTraffic(PcapLiveDevice* dev, NetFlowReassembler& tcpReassembly, std::string bpfFiler = "")
{
    // try to open device
    if (!dev->open())
        EXIT_WITH_ERROR("Cannot open interface");

    // set BPF filter if set by the user
    if (bpfFiler != "")
    {
        if (!dev->setFilter(bpfFiler))
            EXIT_WITH_ERROR("Cannot set BPF filter to interface");
    }

    printf("Starting packet capture on '%s'...\n", dev->getIPv4Address().toString().c_str());

    // start capturing packets. Each packet arrived will be handled by onPacketArrives method
    dev->startCapture(onPacketArrives, &tcpReassembly);

    // register the on app close event to print summary stats on app termination
    bool shouldStop = false;
    ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

    // run in an endless loop until the user presses ctrl+c
    while(!shouldStop)
        PCAP_SLEEP(1);

    // stop capturing and close the live device
    dev->stopCapture();
    dev->close();

    finalize_and_show_stats(tcpReassembly);
}


/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
    AppName::init(argc, argv);

    std::string interfaceNameOrIP = "";
    std::vector<std::string> vecInputPcapFileNames;
    std::string bpfFilter = "";
    std::string outputDir = "";
    bool writeMetadata = false;
    bool writeToConsole = false;
    bool separateSides = false;
    bool writeChunksHeader = false;
    bool writeJsonData = false;
    size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;

    int optionIndex = 0;
    char opt = 0;

    while((opt = getopt_long (argc, argv, "i:r:o:e:f:mcsdjvhl", TcpAssemblyOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'i':
                interfaceNameOrIP = optarg;
                break;
            case 'r':
                vecInputPcapFileNames.push_back(optarg);
                break;
            case 'o':
                outputDir = optarg;
                break;
            case 'e':
                bpfFilter = optarg;
                break;
            case 's':
                separateSides = true;
                break;
            case 'd':
                writeChunksHeader = true;
                break;
            case 'j':
                writeJsonData = true;
                break;
            case 'm':
                writeMetadata = true;
                break;
            case 'c':
                writeToConsole = true;
                break;
            case 'f':
                maxOpenFiles = (size_t)atoi(optarg);
                break;
            case 'h':
                printUsage();
                break;
            case 'v':
                printAppVersion();
                break;
            case 'l':
                listInterfaces();
                break;
            default:
                printUsage();
                exit(-1);
        }
    }

    // if no interface nor input pcap file were provided - exit with error
    if (vecInputPcapFileNames.empty() && interfaceNameOrIP == "")
        EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

    // verify output dir exists
    if (!outputDir.empty() && !directoryExists(outputDir)) {
#if defined(_WIN32)
        _mkdir(outputDir.c_str());
#else 
        mkdir(outputDir.c_str(), 0744);
#endif
        if (!directoryExists(outputDir)) {
            EXIT_WITH_ERROR("Output directory doesn't exist");
        }
    }

    // set global config singleton with input configuration
    GlobalConfig::getInstance().outputDir = outputDir;
    GlobalConfig::getInstance().writeMetadata = writeMetadata;
    GlobalConfig::getInstance().writeToConsole = writeToConsole;
    GlobalConfig::getInstance().separateSides = separateSides;
    GlobalConfig::getInstance().writeChunksHeader = writeChunksHeader;
    GlobalConfig::getInstance().writeJsonData = writeJsonData;
    GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

    // create the object which manages info on all connections
    NetFlowReassemblyConnMgr connMgr;

    // create the TCP reassembly instance
    NetFlowReassembler tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, 
        tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback,
        true);

    // analyze in pcap file mode
    if (!vecInputPcapFileNames.empty())
    {
        doTcpReassemblyOnPcapFiles(vecInputPcapFileNames, tcpReassembly, bpfFilter);
    }
    else // analyze in live traffic mode
    {
        // extract pcap live device by interface name or IP address
        PcapLiveDevice* dev = NULL;
        IPv4Address interfaceIP(interfaceNameOrIP);
        if (interfaceIP.isValid())
        {
            dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
            if (dev == NULL)
                EXIT_WITH_ERROR("Couldn't find interface by provided IP");
        }
        else
        {
            dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
            if (dev == NULL)
                EXIT_WITH_ERROR("Couldn't find interface by provided name");
        }

        // start capturing packets and do TCP reassembly
        doTcpReassemblyOnLiveTraffic(dev, tcpReassembly, bpfFilter);
    }
}
