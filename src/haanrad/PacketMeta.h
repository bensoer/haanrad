//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_PACKETMETA_H
#define HAANRAD_PACKETMETA_H

struct ApplicationType{
    enum ApplicationTypeEnum { HTTP, DNS, UNKNOWN = -1};
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
};


#endif //HAANRAD_PACKETMETA_H
