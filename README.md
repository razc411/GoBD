# GoBD ReadMe
#############
----------------------
-----Installation-----
----------------------

To compile the GoBD program yourself first install golang, follow the guide below for exact directions for installing on your system.
	https://golang.org/doc/install

Install the required libraries by executing
	go get github.com/google/gopacket
	go get github.comn/goog/gopacket/pcap
	go get golang.org/x/crypto/ssh/terminal

To install GoBD execute
	go install GoBD 

after navigating to the source directory. You should now be able to run the program by typing 
	GoBD

You may also choose to use  
	go build GoBD 

and execute the created executable by typing:
	GoBD [options, refer to usage below]

---------------------------
Windows Installation-------
---------------------------

Follow the same instructions at golang.org/doc/install

Once this has been completed you will need two things: git and mingw64

Install git from 
	https://git-scm.com/download/win
Follow the installation instructions, ensure that Git is setup 
on your windows path during the installation.

Intall mingw64 from sourceforge
	http://sourceforge.net/projects/mingw-w64/
Follow the installation instructions, then go to advanced system settings and add
this to your path variable.
	C:\Path\To\Mingw64\bin

Ensure to set your GOROOT and GOPATH in the environment variables as well if you have not done
it in the previous Go install guide. The installer does not set these up for you.

Once this has been done, execute the installs for go
	go get github.com/google/gopacket
	go get github.comn/goog/gopacket/pcap
	go get golang.org/x/crypto/ssh/terminal

Now navigate to your GoBD directory and execut
	go install GoBD

and execute the created executable by typing:
	GoBD [options, refer to usage below]
---------------------------
Usage----------------------
---------------------------

For this info in more detail, type GoBD --help.

GoBD comes with several flags for program execution, they are as follows.
    -mode=[server | client] - sets the program to client or server mode.
    -ip=[ip address] - sets the ip address to send data to.
    -port=[port number] - sets the port to send data to.
    -lport=[port number] - sets the port to listen for incoming data on.
    -iface=[net interface name] - sets the net interface to listen to on the server
    -visible=[true or false] - sets whether the server should be visible or hidden

When using client or server mode, they should each have 2 different ports selected, these ports should be a reflection of each other. Take for example this execution:
    ./GoBD -ip=127.0.0.1 -iface=eth0 -port=222 -lport=223 -mode=client
    ./GoBD -ip=127.0.0.1 -iface=eth0 -port=223 -lport=222 -mode=server

It's important that you set the ports to different numbers, but make sure the lport and port combo of each execution match. The program will still work if the same port is used for everything, but you will get some strange behaviour. The server mode of GoBD must be executed with root privileges in order to allow packet sniffing to be performed. There is also one condition to any commands sent, they can only be to one program, no piping.

When running the server in hidden mode, it will disconnect from any terminal and run as a standalone
process.

There is a limit to data sent from client to server, any command over 65536 byte will be cut short,
though you shouldnt need to send such a massively long command.
-------------------------
Client Usage-------------
-------------------------

To learn more about this, type ?help while in client mode.

The client comes with its own set of options. You can send regular commands by just typing	
them into the terminal and hitting enter, but you can also send backdoor program commands by
prefixing the inputted command with ! 

Currently, the support backdoor program commands are:
	!setprocess [name] - sets the process name of the backdoor
	!exit - sends a kill signal to the backdoor

The authentication code for the client is: DAMNPANDIMENSIONALMICE

When executing on windows, the password will be visible, since golang has no support for hiding input
in a windows terminal.

-------------------------
