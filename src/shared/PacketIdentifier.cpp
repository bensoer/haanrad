//
// Created by bensoer on 12/11/16.
//

#include "PacketIdentifier.h"
#include "Structures.h"
#include "Logger.h"
#include "../haanrad/SystemState.h"
#include <netinet/tcp.h>
#include <cstring>

char* PacketIdentifier::findApplicationLayer(PacketMeta * meta) {

    char * applicationLayer = nullptr;
    char * transportLayer = PacketIdentifier::findTransportLayer(meta);

    if(meta->transportType == TransportType::TCP){
        struct tcphdr * tcp = (struct tcphdr *)(transportLayer);
        int byteOffset = ((tcp->doff * 32) / 8);
        applicationLayer = (transportLayer + byteOffset);
    }else if(meta->transportType == TransportType::UDP){
        applicationLayer = (transportLayer + 8);
    }else{
        Logger::debug("PacketIdentifier:findApplicationLayer - Unable To Determine Protocol. Could Not Fetch Application Layer");
    }

    return applicationLayer;


}

char* PacketIdentifier::findTransportLayer(PacketMeta *meta) {

    struct iphdr * ip = (struct iphdr *)meta->packet;
    char * transportLayer = nullptr;
    int ipHeaderLength = (ip->ihl * 4);

    transportLayer = (meta->packet + ipHeaderLength);

    return transportLayer;
}

PacketMeta PacketIdentifier::generatePacketMeta(char packet[IP_MAXPACKET]) {
    Logger::debug("PacketIdentifier:generatePacketMeta - Generating Meta From Packet Information");

    PacketMeta meta;
    memcpy(meta.packet, packet, IP_MAXPACKET);

    struct iphdr * ip = (struct iphdr *)packet;
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
            Logger::debug("PacketIdentifier:generatePacketMeta - IP Type Is Unknown");
            meta.ipType = NetworkType::UNKNOWN;
    }

    //what is the transport protocol
    switch(protocol){
        case TransportType::TCP: {
            Logger::debug("PacketIdentifier:generatePacketMeta - Transport Protocol Is TCP");
            meta.transportType = TransportType::TCP;
            struct tcphdr * tcp = (struct tcphdr *)(packet + ipHeaderLength);
            int byteOffset = ((tcp->doff * 32) / 8);
            char * applicationLayer = (packet + ipHeaderLength + byteOffset);

            if(PacketIdentifier::isHTTP(applicationLayer)){
                meta.applicationType = ApplicationType::HTTP;
            }else if(PacketIdentifier::isTLS(applicationLayer)){
                meta.applicationType = ApplicationType::TLS;
            }else{
                meta.applicationType = ApplicationType::UNKNOWN;
            }

            break;
        }
        case TransportType::TransportTypeEnum::UDP: {
            Logger::debug("PacketIdentifier:generatePacketMeta - Transport Protocol Is UDP");
            meta.transportType = TransportType::UDP;
            char * applicationLayer = (packet + ipHeaderLength + 8);

            //check application layer has content for a valid UDP protocol
            if(PacketIdentifier::isDNS(applicationLayer)) {
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

bool PacketIdentifier::isDNS(char *applicationLayer) {
    Logger::debug("PacketIdentifier:isDNS - Determining If Packet Is A DNS Packet");
    struct DNS_HEADER * dns = (struct DNS_HEADER * )applicationLayer;

    if(dns->qr == 0){
        //in a query the answer and auth should be 0, with questions at 1
        short ans_count = ntohs(dns->ans_count);
        short auth_count = ntohs(dns->auth_count);
        short q_count = ntohs(dns->q_count);
        if(ans_count == 0 && auth_count == 0  && q_count == 1){
            //in query the add_count could be from 0 - 2
            short add_count = ntohs(dns->add_count);
            if(add_count == 0 || add_count == 1 || add_count == 2){
                //in query the rcode and z code should be 0
                if(dns->rcode == 0 && (dns->z == 0 || dns->z == 1)){ // WE NEED Z
                    Logger::debug("PacketIdentifier:isDNS - Packet Is A DNS Query");
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
                if(dns->z == 0 || dns->z == 1){ //WE NEED Z
                    Logger::debug("PacketIdentifier:isDNS - Packet Is a DNS Response");
                    return true;
                }

            }
        }
    }else{
        Logger::debug("PacketIDentifier:isDNS - Packet Is Not A DNS Packet");
    }

    return false;

}

bool PacketIdentifier::isHTTP(char *applicationLayer) {



    return false;
}

bool PacketIdentifier::isTLS(char *applicationLayer) {
    Logger::debug("PacketIdentifier:isTLS - Determining If Packet Is A TLS Packet");
    struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;

    Logger::hexDebug(tls->contentType);
    Logger::debugl(" | ");
    Logger::hexDebug(tls->type);
    Logger::debugl(" | ");
    Logger::hexDebug(tls->length);
    Logger::debug("");

    if(tls->contentType == 23 && tls->type == 771 && tls->length > 0){
        Logger::debug("PacketIdentifier:isTLS - Packet Is A TLS Packet");
        return true;
    }

    Logger::debug("PacketIdentifier:isTLS - Packet Is Not A TLS Packet");
    return false;



}