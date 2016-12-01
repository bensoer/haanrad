//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_PACKETMETA_H
#define HAANRAD_PACKETMETA_H

#include <netinet/ip.h>

/**
 * ApplicationType is an enum that represents the various supported ApplicationLayer types of a PacketMEta
 */
struct ApplicationType{
    enum ApplicationTypeEnum { HTTP = 80, DNS = 53, TLS = 443, UNKNOWN = -1};
};

/**
 * TransportType is an enum that represents the various support TransportLayer types of a PacketMeta
 */
struct TransportType{
    enum TransportTypeEnum { TCP = 6, UDP = 17, UNKNOWN = -1};
};

/**
 * NetworkType is an enum that represents the various supported NetworkLayer types of a PacketMeta
 */
struct NetworkType{
    enum NetworkTypeEnum { IPv4 = 4, IPv6 = 6, UNKNOWN = -1};
};


//packet meta needs to store a raw copy of its packet and pointer to where to store data in a response ?
//this way when picking the correct packet we can also mimmick the common traffic as if we belong

class PacketMeta {

public:
    NetworkType::NetworkTypeEnum ipType;
    TransportType::TransportTypeEnum transportType;
    ApplicationType::ApplicationTypeEnum applicationType;
    char packet[IP_MAXPACKET];

};


#endif //HAANRAD_PACKETMETA_H
