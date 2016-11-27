//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_NETWORKMONITOR_H
#define HAANRAD_NETWORKMONITOR_H

//Network monitor listens for all traffic on the network. Determining whether the packets our our own or not. If they
//they are not, then it will collect samples using the TrafficAnalyzer to store it.

//Network monitor needs to watch out how much it listens and when it listens so as to reduce the amount of resource
//consumption it needs

//NetworkMonitor should be aware of how busy the system is. If the computer is working hard, more resources could be
//sent to the Monitor without causing issues ?

//NetworkMonitor also is in charge of ensuring a complete message is received and authenticated from the client as messages
//may arrive out of order, encrypted, and not all in one packet - maybe not even the same kind of packet ?

#include "../TrafficAnalyzer.h"
#include "../../shared/HCrypto.h"
#include "../SystemState.h"
#include <iostream>
#include <pcap.h>

using namespace std;

class NetworkMonitor {

private:
    int rawTCPSocket = -1;
    int rawUDPSocket = -1;

    int epollDescriptor = -1;

    const int EPOLL_QUEUE_LENGTH = 10;


    TrafficAnalyzer * trafficAnalyzer = nullptr;
    HCrypto * crypto = nullptr;

    pcap_t * currentFD;

    bool getInterface();

    string * command = nullptr;

    pcap_if_t * allInterfaces = nullptr;
    pcap_if_t * listeningInterface = nullptr;

    static NetworkMonitor * instance;
    NetworkMonitor(TrafficAnalyzer * analyzer, HCrypto * crypto, string clientIP);

    bool isFullCommand();

    void parseApplicationContent(PacketMeta * meta, char * applicationLayer);
    void parseTransportContent(PacketMeta * meta);

    static void packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);

    bool isOwnPacket(PacketMeta * meta);
    string clientIP = "";

public:



    static NetworkMonitor * getInstance(TrafficAnalyzer * analyzer, HCrypto * crypto, string clientIP);

    string * listenForTraffic();

    void killListening();
};


#endif //HAANRAD_NETWORKMONITOR_H
