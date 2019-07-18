# pcap2conn
==============

pcap2conn (https://github.com/Stanislav-Povolotsky/pcap2conn) is based on TcpReassembly example from PcapPlusPlus https://github.com/seladb/PcapPlusPlus

This is an application that captures data transmitted as part of transport level connections (TCP, UDP, ...), organizes the data and stores it in a way that is convenient for protocol analysis and debugging.
This application reconstructs the connection data streams and stores each connection in a separate file(s). pcap2conn understands TCP sequence numbers and will correctly reconstruct
data streams regardless of retransmissions, out-of-order delivery or data loss.

pcap2conn works more or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options.

Main features and capabilities:
- Captures packets from pcap/pcapng files or live traffic
- Handles TCP retransmission, out-of-order packets and packet loss
- Possibility to set a BPF filter to process only part of the traffic
- Write each connection to a separate file
- Write each side of each connection to a separate file
- Limit the max number of open files in each point in time (to avoid running out of file descriptors for large files / heavy traffic)
- Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in each side + total), number of data messages (in each side + total), umber of bytes (in each side + total)
- Write to console only (instead of files)
- Set a directory to write files to (default is current directory)


# Using the utility
-----------------

pcap2conn [-hvlcmsdj] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]

Options:

    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file
    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface
    -o output_dir : Specify output directory (default is '.')
    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets
    -f max_files  : Maximum number of file descriptors to use
    -c            : Write all output to console (nothing will be written to files)
    -m            : Write a metadata file for each connection
    -s            : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)
    -d            : Write data chunks headers (by default data is written without any splitter)
    -j            : Write data chunks and metadata in JSON format (one line for each data chunk)
    -l            : Print the list of interfaces and exit
    -v            : Displays the current version and exists
    -h            : Display this help message and exit

### Examples:
Example 1: capturing live traffic, extracting and displaying only HTTP-connections
```
pcap2conn -i \Device\NPF_{YOURGUID-GUID-GUID-GUID-GUIDGUIDGUID} -c -e "tcp port 80"
```
 * (-i) live capture on selected network interface  
 * (-c) output to the screen  
 * (-e) include only HTTP traffic  
  
![How it works](https://user-images.githubusercontent.com/19610545/61442187-cf7b8500-a94f-11e9-8372-05e7c6629ace.gif)
