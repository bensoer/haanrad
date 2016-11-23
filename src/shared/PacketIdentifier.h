//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_PACKETFACTORY_H
#define HAANRAD_PACKETFACTORY_H


#include <netinet/ip.h>
#include "../haanrad/PacketMeta.h"
#include <mutex>

class PacketIdentifier{
private:
    static std::mutex lock;

public:
    static bool isDNS(char * applicationLayer);
    static bool isHTTP(char * applicationLayer);
    static bool isTLS(char * applicationLayer);

    static PacketMeta generatePacketMeta(char packet[IP_MAXPACKET], int length = -1);
    static char * findApplicationLayer(PacketMeta * meta);
    static char * findTransportLayer(PacketMeta * meta);

};


#endif //HAANRAD_PACKETFACTORY_H
