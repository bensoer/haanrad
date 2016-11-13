//
// Created by bensoer on 12/11/16.
//

#include "PacketFactory.h"
#include "Structures.h"
#include <netinet/tcp.h>

PacketMeta PacketFactory::generatePacketMeta(char packet[IP_MAXPACKET]) {

    PacketMeta meta;

    struct iphdr * ip = (struct iphdr *)packet;
    char * applicationLayer = nullptr;
    int ipHeaderType = ip->version;
    int ipHeaderLength = (ip->ihl * 4);
    int protocol = ip->protocol;

    //what is the IP Type
    switch(ipHeaderType){
        case NetworkType::IPv4:
            meta.ipType = NetworkType::IPv4;
            break;
        case NetworkType ::IPv6:
            meta.ipType = NetworkType::IPv6;
            break;
        default:
            meta.ipType = NetworkType::UNKNOWN;
    }

    //what is the transport protocol
    switch(protocol){
        case TransportType::TCP: {
            meta.transportType = TransportType::TCP;
            struct tcphdr * tcp = (struct tcphdr *)(packet + ipHeaderLength);
            int byteOffset = ((tcp->doff * 32) / 8);
            applicationLayer = (packet + ipHeaderLength + byteOffset);

            if(PacketFactory::isHTTP(applicationLayer)){
                meta.applicationType = ApplicationType::HTTP;
            }else{
                meta.applicationType = ApplicationType::UNKNOWN;
            }

            break;
        }
        case TransportType::TransportTypeEnum::UDP: {
            meta.transportType = TransportType::UDP;
            applicationLayer = (packet + ipHeaderLength + 8);

            //check application layer has content for a valid UDP protocol
            if(PacketFactory::isDNS(applicationLayer)) {
                meta.applicationType = ApplicationType::DNS;
            }else{
                meta.applicationType = ApplicationType::UNKNOWN;
            }

            break;
        }
        default: {
            meta.transportType = TransportType::UNKNOWN;
        }

    }

    return meta;

}

bool PacketFactory::isDNS(char *applicationLayer) {

    struct DNS_HEADER * dns = (struct DNS_HEADER * )applicationLayer;
    if(dns->qr == 0){
        //in a query the answer and auth should be 0, with questions at 1
        if(dns->ans_count == 0 && dns->auth_count == 0  && dns->q_count == 1){
            //in query the add_count could be from 0 - 2
            if(dns->add_count == 0 || dns->add_count == 1 || dns->add_count == 2){
                //in query the rcode and z code should be 0
                if(dns->rcode == 0 && dns->z == 0){
                    return true;
                }
            }
        }
    }else if(dns->qr == 1){

        //in response questions should still be one but answers could be anywhere from 0 or more
        if((dns->ans_count >= 0 || dns->auth_count >= 0 || dns->add_count >= 0) && dns->q_count == 1){
            //the response counts should be less then 255 though
            if(dns->ans_count < 255 & dns->auth_count < 255 && dns->add_count < 255){
                //in response z value should still be 0
                if(dns->z == 0){
                    return true;
                }
            }
        }
    }

    return false;

}

bool PacketFactory::isHTTP(char *applicationLayer) {



    return false;
}