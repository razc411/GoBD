# GoBD ReadMe
#############
----------------------------
<h1> Linux Installation </h1>
----------------------------
To build and compile gobd execute the install script, change the package manager
to your package manager before executing.
   	   chmod +x install_gobd
	   ./install_gobd

Execute the program by typing:
	GoBD [options, refer to usage below]
	
------------------------------
<h1> Windows Installation </h1>
------------------------------
Follow the same instructions at golang.org/doc/install

Once this has been completed you will need two things: git and mingw64

Install git from 
	https://git-scm.com/download/win
Follow the installation instructions, ensure that Git is setup 
on your windows path during the installation.

Intall mingw64 from sourceforge:

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
    
---------------
<h1> Usage </h1>
---------------
For this info in more detail, type GoBD --help.

GoBD comes with several flags for program execution, they are as follows.

     -mode=[server | client] - sets the program to client or server mode.
     -ip=[ip address] - sets the ip address to send data to.
     -port=[port number] - sets the port to send data to.
     -lport=[port number] - sets the port to listen for incoming data on.
     -iface=[net interface name] - sets the net interface to listen to on the server
     -visible=[true or false] - sets whether the server should be visible or hidden
     -dMac=[mac address] - sets the destination mac address for communication
    
When using client or server mode, they should each have 2 different ports selected, these ports
should be a reflection of each other. Take for example this execution:

       ./GoBD -ip=127.0.0.1 -dMac=32:d1:d1:d1:a1:32 -iface=eth0 -port=222 -lport=223 -mode=client
       ./GoBD -ip=127.0.0.2 -dMac=32:d1:d1:d1:a1:33 -iface=eth0 -port=223 -lport=222 -mode=server

It's important that you set the ports to different numbers, a lot of the packet management relies on ports.

When running the server in hidden mode, it will disconnect from any terminal and run as a standalone process.

--------------------
<h1>Client Usage</h1>
--------------------
To learn more about this, type ?help while in client mode.

The client comes with its own set of options. You can send regular commands by just typing	
them into the terminal and hitting enter, but you can also send backdoor program commands by
prefixing the inputted command with ! 

Currently, the support backdoor program commands are:

	   !setprocess [name] - sets the process name of the backdoor
	   !monitor [filename] - monitors for a file on the backdoor and returns it to the client
	            when found.
	   !exit - sends a kill signal to the backdoor

The authentication code for the client is: DAMNPANDIMENSIONALMICE, this can be changed through the constant
in server.go.

When executing on windows, the password will be visible, since golang has no support for hiding input
in a windows terminal.
