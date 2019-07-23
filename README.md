# pcap2conn

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
#### Example 1: capturing live traffic, extracting and displaying only HTTP-connections
```
pcap2conn -i \Device\NPF_{YOURGUID-GUID-GUID-GUID-GUIDGUIDGUID} -c -e "tcp port 80"
```
 * (-i interface) live capture on selected network interface  
 * (-c) output to the console
 * (-e) include only HTTP-connections
  
![Example 1: capturing live traffic, extracting and displaying only HTTP-connections](https://user-images.githubusercontent.com/19610545/61442187-cf7b8500-a94f-11e9-8372-05e7c6629ace.gif)

#### Example 2: extracting connections from PCAP-file to text files
```
pcap2conn -r data.pcapng -e "tcp port 23"
```
 * (-r input_file) read packets from file   
 * (-e) include only TELNET-connections
  
![Example 2: extracting connections from PCAP-file to text files](https://user-images.githubusercontent.com/19610545/61617950-758efe00-ac74-11e9-8414-345ac6ab2f8b.gif)

#### Example 3: extracting connections from PCAP-file to JSON files and replaying extracted dump  
```
pcap2conn -r data.pcapng -e "tcp port 23" -j
python json_dump_replay_tcp_server.py extracted-json-dump.json
```
 * (-r input_file) read packets from file   
 * (-e "filter") include only TELNET-connections
 * (-j) save reassembled data chunks in JSON format
  
![Example 3: extracting connections from PCAP-file to JSON files and replaying extracted dump](https://user-images.githubusercontent.com/19610545/61697281-983a1900-ad3f-11e9-917e-f4d88c603aa9.gif)  
Content of JSON-dump (20190722111130-TCP-192.168.56.1.58783-192.168.56.203.23.json):
```
{"side":"0","time":{"abs":"1563783092.38793","conn":"3.82366"},"size":"3","data":"ls\n","data_hex":"6C730A"}
{"side":"1","time":{"abs":"1563783100.60212","conn":"12.03785"},"size":"1460","data":"adduser.conf\nadjtime\naliases\nalternatives\namap\nanacrontab\napache2\napg.conf\napm\napparmor\napparmor.d\nappstream.conf\napt\narpwatch\navahi\nbash.bashrc\nbash_completion\nbash_completion.d\nbdfproxy\nbeef-xss\nbindresvport.blacklist\nbinfmt.d\nbluetooth\nbtscanner.dtd\nbtscanner.xml\nca-certificates\nca-certificates.conf\ncalendar\nchatscripts\nchkrootkit.conf\nchromium\ncisco-torch\nconsole-setup\ncontainerd\ncouchdb\ncracklib\ncron.d\ncron.daily\ncron.hourly\ncron.monthly\ncrontab\ncron.weekly\ncryptsetup-initramfs\ncrypttab\ncupshelpers\ndarkstat\ndbus-1\ndconf\ndebconf.conf\ndebian_version\ndebtags\ndefault\ndeluser.conf\ndhcp\ndictionaries-common\ndkms\ndleyna-server-service.conf\ndns2tcpd.conf\ndocker\ndpkg\ndradis\ndrirc\nemacs\nemail-addresses\nenvironment\nettercap\nexim4\nfirebird\nfirefox-esr\nflasm.ini\nfonts\nforemost.conf\nfragroute.conf\nfreetds\nfstab\nfuse.conf\ngai.conf\ngdb\ngdm3\ngeoclue\nghostscript\nglvnd\ngnome\ngroff\ngroup\ngroup-\ngrub.d\ngshadow\ngshadow-\ngss\ngssapi_mech.conf\ngtk-2.0\ngtk-3.0\nguymager\nhdparm.conf\nhost.conf\nhostname\nhosts\nhosts.allow\nhosts.deny\nifplugd\nImageMagick-6\ninetsim\ninit\ninit.d\ninitramfs-tools\ninputrc\ninsserv.conf.d\niproute2\nissue\nissue.net\njava-10-openjdk\njava-8-openjdk\njava-9-openjdk\njohn\nkernel\nking-phisher\nkismet\nldap\nld.so.cache\nld.so.conf\nld.so.conf.d\nlibao.conf\nlibaudit.conf\nlibblockdev\nlibccid_Info.plist\nlibibverbs.d\nlibnl-3\nlibpaper.d\nlighttpd\nlocale.alias\nlocale.gen\nlocaltime\nlogcheck\nlogin.defs\nlogrotate.conf\nlogrotate.d\nlsb-release\nlvm\nlynis\nmacchanger\nma","data_hex":"616464757365722E636F6E660A61646A74696D650A616C69617365730A616C7465726E6174697665730A616D61700A616E6163726F6E7461620A617061636865320A6170672E636F6E660A61706D0A61707061726D6F720A61707061726D6F722E640A61707073747265616D2E636F6E660A6170740A61727077617463680A61766168690A626173682E6261736872630A626173685F636F6D706C6574696F6E0A626173685F636F6D706C6574696F6E2E640A62646670726F78790A626565662D7873730A62696E6472657376706F72742E626C61636B6C6973740A62696E666D742E640A626C7565746F6F74680A62747363616E6E65722E6474640A62747363616E6E65722E786D6C0A63612D6365727469666963617465730A63612D6365727469666963617465732E636F6E660A63616C656E6461720A63686174736372697074730A63686B726F6F746B69742E636F6E660A6368726F6D69756D0A636973636F2D746F7263680A636F6E736F6C652D73657475700A636F6E7461696E6572640A636F75636864620A637261636B6C69620A63726F6E2E640A63726F6E2E6461696C790A63726F6E2E686F75726C790A63726F6E2E6D6F6E74686C790A63726F6E7461620A63726F6E2E7765656B6C790A637279707473657475702D696E697472616D66730A63727970747461620A6375707368656C706572730A6461726B737461740A646275732D310A64636F6E660A646562636F6E662E636F6E660A64656269616E5F76657273696F6E0A646562746167730A64656661756C740A64656C757365722E636F6E660A646863700A64696374696F6E61726965732D636F6D6D6F6E0A646B6D730A646C65796E612D7365727665722D736572766963652E636F6E660A646E7332746370642E636F6E660A646F636B65720A64706B670A6472616469730A64726972630A656D6163730A656D61696C2D6164647265737365730A656E7669726F6E6D656E740A65747465726361700A6578696D340A66697265626972640A66697265666F782D6573720A666C61736D2E696E690A666F6E74730A666F72656D6F73742E636F6E660A66726167726F7574652E636F6E660A667265657464730A66737461620A667573652E636F6E660A6761692E636F6E660A6764620A67646D330A67656F636C75650A67686F73747363726970740A676C766E640A676E6F6D650A67726F66660A67726F75700A67726F75702D0A677275622E640A67736861646F770A67736861646F772D0A6773730A6773736170695F6D6563682E636F6E660A67746B2D322E300A67746B2D332E300A6775796D616765720A68647061726D2E636F6E660A686F73742E636F6E660A686F73746E616D650A686F7374730A686F7374732E616C6C6F770A686F7374732E64656E790A6966706C7567640A496D6167654D616769636B2D360A696E657473696D0A696E69740A696E69742E640A696E697472616D66732D746F6F6C730A696E70757472630A696E73736572762E636F6E662E640A6970726F757465320A69737375650A69737375652E6E65740A6A6176612D31302D6F70656E6A646B0A6A6176612D382D6F70656E6A646B0A6A6176612D392D6F70656E6A646B0A6A6F686E0A6B65726E656C0A6B696E672D706869736865720A6B69736D65740A6C6461700A6C642E736F2E63616368650A6C642E736F2E636F6E660A6C642E736F2E636F6E662E640A6C6962616F2E636F6E660A6C696261756469742E636F6E660A6C6962626C6F636B6465760A6C6962636369645F496E666F2E706C6973740A6C6962696276657262732E640A6C69626E6C2D330A6C696270617065722E640A6C696768747470640A6C6F63616C652E616C6961730A6C6F63616C652E67656E0A6C6F63616C74696D650A6C6F67636865636B0A6C6F67696E2E646566730A6C6F67726F746174652E636F6E660A6C6F67726F746174652E640A6C73622D72656C656173650A6C766D0A6C796E69730A6D61636368616E6765720A6D61"}
{"side":"1","time":{"abs":"1563783100.60224","conn":"12.03796"},"size":"1452","data":"chine-id\nmagic\nmagic.mime\nmailcap\nmailcap.order\nmailname\nmanpath.config\nmatplotlibrc\nmc\nmenu\nmenu-methods\nmercurial\nmime.types\nminicom\nmiredo\nmiredo.conf\nmke2fs.conf\nmodprobe.d\nmodules\nmodules-load.d\nmotd\nmtab\nmysql\nnagios-plugins\nnanorc\nnetsniff-ng\nnetwork\nNetworkManager\nnetworks\nnewt\nnfc\nnginx\nnikto.conf\nnipper.conf\nnsswitch.conf\nntp.conf\nODBCDataSources\nodbc.ini\nodbcinst.ini\nopenal\nOpenCL\nopensc\nopenvpn\nopt\nos-release\np0f\nPackageKit\npam.conf\npam.d\npapersize\npasswd\npasswd-\npcmcia\nperl\nphp\npm\npolkit-1\npostgresql\npostgresql-common\nppp\nprofile\nprofile.d\nprotocols\nproxychains.conf\npulse\npython\npython2.7\npython3\npython3.6\nrc0.d\nrc1.d\nrc2.d\nrc3.d\nrc4.d\nrc5.d\nrc6.d\nrcS.d\nreader.conf.d\nrearj.cfg\nredsocks.conf\nreportbug.conf\nresolvconf\nresolv.conf\nresponder\nrmt\nrpc\nrsyslog.conf\nrsyslog.d\nrygel.conf\nsamba\nsane.d\nscalpel\nscreenrc\nsddm.conf\nsearchsploit_rc\nsecuretty\nsecurity\nselinux\nsensors3.conf\nsensors.d\nservices\nsgml\nshadow\nshadow-\nshells\nsiege\nskel\nsmartd.conf\nsmartmontools\nsmi.conf\nsnmp\nsparta.conf\nspeech-dispatcher\nsqlmap\nssh\nssl\nstunnel\nsubgid\nsubgid-\nsubuid\nsubuid-\nsubversion\nsudoers\nsudoers.d\nsysctl.conf\nsysctl.d\nsysstat\nsystemd\nterminfo\ntexmf\nthin2.5\ntimezone\ntimidity\ntmpfiles.d\ntwofi\nucf.conf\nudev\nudisks2\nufw\nunicornscan\nupdatedb.conf\nupdate-motd.d\nUPower\nusb_modeswitch.conf\nusb_modeswitch.d\nvdpau_wrapper.cfg\nvim\nvmware-tools\nvpnc\nvulkan\nwgetrc\nwildmidi\nwireshark\nwpa_supplicant\nX11\nxdg\nxinetd.conf\nxinetd.d\nxml\nxpdf\nxprobe2\nzsh\n","data_hex":"6368696E652D69640A6D616769630A6D616769632E6D696D650A6D61696C6361700A6D61696C6361702E6F726465720A6D61696C6E616D650A6D616E706174682E636F6E6669670A6D6174706C6F746C696272630A6D630A6D656E750A6D656E752D6D6574686F64730A6D657263757269616C0A6D696D652E74797065730A6D696E69636F6D0A6D697265646F0A6D697265646F2E636F6E660A6D6B653266732E636F6E660A6D6F6470726F62652E640A6D6F64756C65730A6D6F64756C65732D6C6F61642E640A6D6F74640A6D7461620A6D7973716C0A6E6167696F732D706C7567696E730A6E616E6F72630A6E6574736E6966662D6E670A6E6574776F726B0A4E6574776F726B4D616E616765720A6E6574776F726B730A6E6577740A6E66630A6E67696E780A6E696B746F2E636F6E660A6E69707065722E636F6E660A6E737377697463682E636F6E660A6E74702E636F6E660A4F44424344617461536F75726365730A6F6462632E696E690A6F646263696E73742E696E690A6F70656E616C0A4F70656E434C0A6F70656E73630A6F70656E76706E0A6F70740A6F732D72656C656173650A7030660A5061636B6167654B69740A70616D2E636F6E660A70616D2E640A706170657273697A650A7061737377640A7061737377642D0A70636D6369610A7065726C0A7068700A706D0A706F6C6B69742D310A706F737467726573716C0A706F737467726573716C2D636F6D6D6F6E0A7070700A70726F66696C650A70726F66696C652E640A70726F746F636F6C730A70726F7879636861696E732E636F6E660A70756C73650A707974686F6E0A707974686F6E322E370A707974686F6E330A707974686F6E332E360A7263302E640A7263312E640A7263322E640A7263332E640A7263342E640A7263352E640A7263362E640A7263532E640A7265616465722E636F6E662E640A726561726A2E6366670A726564736F636B732E636F6E660A7265706F72746275672E636F6E660A7265736F6C76636F6E660A7265736F6C762E636F6E660A726573706F6E6465720A726D740A7270630A727379736C6F672E636F6E660A727379736C6F672E640A727967656C2E636F6E660A73616D62610A73616E652E640A7363616C70656C0A73637265656E72630A7364646D2E636F6E660A73656172636873706C6F69745F72630A7365637572657474790A73656375726974790A73656C696E75780A73656E736F7273332E636F6E660A73656E736F72732E640A73657276696365730A73676D6C0A736861646F770A736861646F772D0A7368656C6C730A73696567650A736B656C0A736D617274642E636F6E660A736D6172746D6F6E746F6F6C730A736D692E636F6E660A736E6D700A7370617274612E636F6E660A7370656563682D646973706174636865720A73716C6D61700A7373680A73736C0A7374756E6E656C0A7375626769640A7375626769642D0A7375627569640A7375627569642D0A73756276657273696F6E0A7375646F6572730A7375646F6572732E640A73797363746C2E636F6E660A73797363746C2E640A737973737461740A73797374656D640A7465726D696E666F0A7465786D660A7468696E322E350A74696D657A6F6E650A74696D69646974790A746D7066696C65732E640A74776F66690A7563662E636F6E660A756465760A756469736B73320A7566770A756E69636F726E7363616E0A75706461746564622E636F6E660A7570646174652D6D6F74642E640A55506F7765720A7573625F6D6F64657377697463682E636F6E660A7573625F6D6F64657377697463682E640A76647061755F777261707065722E6366670A76696D0A766D776172652D746F6F6C730A76706E630A76756C6B616E0A7767657472630A77696C646D6964690A77697265736861726B0A7770615F737570706C6963616E740A5831310A7864670A78696E6574642E636F6E660A78696E6574642E640A786D6C0A787064660A7870726F6265320A7A73680A"}
{"side":"0","time":{"abs":"1563783123.26309","conn":"34.69881"},"size":"9","data":"uname -a\n","data_hex":"756E616D65202D610A"}
{"side":"1","time":{"abs":"1563783123.26511","conn":"34.70083"},"size":"89","data":"Linux kali 4.15.0-kali3-amd64 #1 SMP Debian 4.15.17-1kali1 (2018-04-25) x86_64 GNU/Linux\n","data_hex":"4C696E7578206B616C6920342E31352E302D6B616C69332D616D64363420233120534D502044656269616E20342E31352E31372D316B616C69312028323031382D30342D323529207838365F363420474E552F4C696E75780A"}
```
