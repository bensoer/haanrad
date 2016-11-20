//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_PACKETFACTORY_H
#define HAANRAD_PACKETFACTORY_H


#include <netinet/ip.h>
#include "../haanrad/PacketMeta.h"

class PacketIdentifier{
public:
    static bool isDNS(char * applicationLayer);
    static bool isHTTP(char * applicationLayer);
    static bool isTLS(char * applicationLayer);

    static PacketMeta generatePacketMeta(char packet[IP_MAXPACKET]);
    static char * findApplicationLayer(PacketMeta * meta);
    static char * findTransportLayer(PacketMeta * meta);

};


#endif //HAANRAD_PACKETFACTORY_H
