package main

import(
	"os"
	"reflect"
	"unsafe"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"net"
)

func main(){

	SetProcessName("lol1");

	//flags
	modePtr := flag.String("mode", "client", "The mode of the application, may either be" +
		" client or server. Defaults to client.");
	ipPtr := flag.String("ip", "127.0.0.1", "The ip to connect to if in client mode.");
	portPtr := flag.Int("port", 80, "The port to connect to in client mode, or to listen on in server mode. Defaults to 80.");

	flag.Parse();
	
	switch *modePtr {
	case "client":
		fmt.Printf("Running in client mode. Connecting to %s at port %d.\n", *ipPtr, *portPtr);
		break;
	case "server":
		fmt.Printf("Running in server mode. Listening on port %d.\n", *portPtr);
	}
}

func intiateClient(ip String, port int){

	ip := &layers.IPv4{
		SrcIP: net.ParseIP(ip);
		
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
