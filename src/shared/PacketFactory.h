//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_PACKETFACTORY_H
#define HAANRAD_PACKETFACTORY_H


#include <netinet/ip.h>
#include "../haanrad/PacketMeta.h"

class PacketFactory {
public:
    static bool isDNS(char * applicationLayer);
    static bool isHTTP(char * applicationLayer);

    static PacketMeta generatePacketMeta(char packet[IP_MAXPACKET]);
};


#endif //HAANRAD_PACKETFACTORY_H
