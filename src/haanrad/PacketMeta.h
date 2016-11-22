//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_PACKETMETA_H
#define HAANRAD_PACKETMETA_H

#include <netinet/ip.h>

struct ApplicationType{
    enum ApplicationTypeEnum { HTTP = 80, DNS = 53, TLS = 443, UNKNOWN = -1};
};

struct TransportType{
    enum TransportTypeEnum { TCP = 6, UDP = 17, UNKNOWN = -1};
};

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
