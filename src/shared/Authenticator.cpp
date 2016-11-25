//
// Created by bensoer on 12/11/16.
//

#include <netinet/tcp.h>
#include <cstring>
#include "Authenticator.h"
#include "Logger.h"
#include "PacketIdentifier.h"
#include "Structures.h"

string Authenticator::password;

bool Authenticator::isAuthenticPacket(PacketMeta * meta) {

    //parameter should be a pointer to the payload of our message ?
    //what if content is in the header though ?

    //we need to know the structure of our packet now to determine if it is ours

    if(meta->applicationType != ApplicationType::ApplicationTypeEnum::UNKNOWN){
        Logger::debug("Authenticator:isAuthenticPacket - ApplicationType Is Known. Checking Types");

        switch(meta->applicationType){
            case ApplicationType::ApplicationTypeEnum::TLS:{

                //every TLS packet starts with the password in the body
                Logger::debug("Authenticator:isAuthenticPacket - This is A TLS Packet. Password Is In The Body");

                char * applicationLayer = PacketIdentifier::findApplicationLayer(meta);
                struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
                char * payload = applicationLayer + sizeof(struct TLS_HEADER);
                string strPayload(payload);

                unsigned long passwordLength = Authenticator::password.length();
                string start = strPayload.substr(0,passwordLength);
                Logger::debug("Authenticator:isAuthenticPacket - Password Compare: SET >" + Authenticator::password
                              + "< VS. PARSED >" + start + "<");
                if(start.compare(Authenticator::password) == 0){

                    Logger::debug("Authenticator:isAuthenticPacket - Packet Is Authentic. Removing Password From Payload");
                    //since it is valid, strip off the password from the payload, leaving only the haanrad packet
                    string haanradPacket = strPayload.substr(passwordLength);
                    Logger::debug("Authenticator:isAuthenticPacket - Haanrad Packet Is: >" + haanradPacket + "<");
                    memcpy(payload, haanradPacket.c_str(), haanradPacket.size());
                    payload[haanradPacket.length()] = '\0';
                    Logger::debug("Authenticator:isAuthenticPacket - Payload Now Is: >" + string(payload) + "<");

                    return true;
                }
                break;
            }
            case ApplicationType::ApplicationTypeEnum ::DNS:{

                //every DNS packet Z = 1
                Logger::debug("Authenticator:isAuthenticPacket - This is A DNS Packet. Password Is In The Z");
                char * applicationLayer = PacketIdentifier::findApplicationLayer(meta);
                struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;

                if(dns->z == 1){
                    return true;
                }

                break;
            }
            default:{
                Logger::debug("Authenticator:isAuthenticPacket - Could Not Determine How To Authenticate For Application Type. Can't Use");
                return false;
            }
        }

        return false;
    }else{

        //means this could be TCP or UDP
        switch(meta->transportType){
            case TransportType::TransportTypeEnum ::TCP:{

                //every tcp packet has Reserved = 1
                Logger::debug("Authenticator:isAuthenticPacket - This Is A TCP Packet. Password Is In The Reserved 1 Flag");

                char * transportLayer = PacketIdentifier::findTransportLayer(meta);
                struct tcphdr * tcp = (struct tcphdr *)transportLayer;

                if(tcp->res1 == 1){
                    return true;
                }

                break;
            }
            case TransportType::TransportTypeEnum ::UDP:{

                //all udp data has no frag offset and has Reserved Flag 1 set
                Logger::debug("Authenticator:isAuthenticPacket - This Is A UDP Packet. Password Is In The IP Reversed 1 Flag");

                struct iphdr * ip = (struct iphdr *)meta->packet;
                //NOTE THIS ASSUMES frag_off is in BYTE ORDER: Byte Order: 0x2000. Normal Order: 0x8000
                if(ip->frag_off == IPOPT_RESERVED1){
                    return true;
                }
                break;
            }
            default: {
                Logger::debug("Authenticator:isAuthenticPacket - Could Not Determine How To Authenticate For Transport Type. Can't Use");
                return false;
            }
        }

        return false;
    };
}

string Authenticator::getPassword() {
    return Authenticator::password;
}

bool Authenticator::addAuthSignature(PacketMeta * meta) {

    //parameter should be a pointer to the payload of our message ?

    if(meta->applicationType != ApplicationType::ApplicationTypeEnum::UNKNOWN){

        switch(meta->applicationType){
            case ApplicationType::ApplicationTypeEnum::TLS:{

                //every TLS packet starts with the password in the body. For TLS, auth needs to be added before encryption

                char * applicationLayer = PacketIdentifier::findApplicationLayer(meta);
                struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
                char * payload = applicationLayer + sizeof(struct TLS_HEADER);
                string strPayload(payload);

                string signedPayload = (Authenticator::password + strPayload);
                memcpy(payload, signedPayload.c_str(), signedPayload.size());
                payload[signedPayload.length()] = '\0';

                break;
            }
            case ApplicationType::ApplicationTypeEnum ::DNS:{

                //every DNS packet Z = 1

                char * applicationLayer = PacketIdentifier::findApplicationLayer(meta);
                struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;
                dns->z = 1;

                break;
            }
            default:{
                Logger::debug("Authenticator:addAuthSignature - Could Not Determine How To Add Auth Signature For Application Type. Can't Use");
                return false;
            }
        }

        return true;
    }else{

        //means this could be TCP or UDP
        switch(meta->transportType){
            case TransportType::TransportTypeEnum ::TCP:{

                //every tcp packet has Reserved = 1
                char * transportLayer = PacketIdentifier::findTransportLayer(meta);
                struct tcphdr * tcp = (struct tcphdr *)transportLayer;
                tcp->res1 = 1;
                break;
            }
            case TransportType::TransportTypeEnum ::UDP:{

                //all udp data has no frag offset and has Reserved Flag 1 set

                struct iphdr * ip = (struct iphdr *)meta->packet;
                //NOTE THIS ASSUMES frag_off is in BYTE ORDER: Byte Order: 0x2000. Normal Order: 0x8000
                ip->frag_off = IPOPT_RESERVED1;
                break;
            }
            default: {
                Logger::debug("Authenticator:addAuthSignature - Could Not Determine How To Add Auth Signature For Application Type. Can't Use");
                return false;
            }
        }

        return true;
    };

}

void Authenticator::setPassword(string password) {
    Authenticator::password = password;
}