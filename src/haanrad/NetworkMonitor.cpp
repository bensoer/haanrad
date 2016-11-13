//
// Created by bensoer on 31/10/16.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <zconf.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include "NetworkMonitor.h"
#include "../shared/Logger.h"
#include "../shared/Authenticator.h"
#include "../shared/PacketIdentifier.h"
#include <sys/epoll.h>


NetworkMonitor::NetworkMonitor(TrafficAnalyzer * trafficAnalyzer) {

    this->trafficAnalyzer = trafficAnalyzer;

    if((this->rawTCPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("rawTCPSocket creation");
    }

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg = 1;
    if (setsockopt (this->rawTCPSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        perror("TCP - setsockopt");
    }

    if((this->rawUDPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0){
        perror("rawUDPSocket creation");
    }

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg2 = 1;
    if (setsockopt (this->rawUDPSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        perror("UDP - setsockopt");
    }

    //IP_HDRINCL to stop the kernel from building the packet headers
    /*{
        int one = 1;
        const int *val = &one;
        if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            perror("setsockopt");
    }*/


    //register both of these sockets with epoll
    if((this->epollDescriptor = epoll_create(this->EPOLL_QUEUE_LENGTH)) < 0){
        perror("Error Creating Epoll Descriptor");
    }

    struct epoll_event tcpEvent;
    tcpEvent.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLET;
    tcpEvent.data.fd = this->rawTCPSocket;

    if(epoll_ctl(epollDescriptor, EPOLL_CTL_ADD, this->rawTCPSocket, &tcpEvent) == -1){
        perror("Error Adding RawTCP to Epoll");
    }else{
        Logger::debug("NetworkMonitor - Successfully Added TCPSocket Descriptor To The Epoll Event Loop");
    }

    struct epoll_event udpEvent;
    udpEvent.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLET;
    udpEvent.data.fd = this->rawUDPSocket;

    if(epoll_ctl(epollDescriptor, EPOLL_CTL_ADD, this->rawUDPSocket, &udpEvent) == -1){
        perror("Error Adding RawUDP to Epoll");
    }else{
        Logger::debug("NetworkMonitor - Successfully Added UDPSocket Descriptor To The Epoll Event Loop");
    }

}

string * NetworkMonitor::listenForTraffic() {

    Logger::debug("NetworkMonitor:listenForTraffic - Setting Up For Read");
    char BUFFER[IP_MAXPACKET];

    struct epoll_event events [ this->EPOLL_QUEUE_LENGTH];
    int num_fd = epoll_wait(this->epollDescriptor, events, this->EPOLL_QUEUE_LENGTH, -1);
    if(num_fd < 0){
        Logger::debug("NetworkMonitor:listenForTraffic - Epoll Wait Error");
        return nullptr;
    }

    Logger::debug("NetworkMonitor:listenForTraffic - Epoll Returned. Now Reading Results");
    for(unsigned int i = 0; i < num_fd; i++){

        //check for errors
        if(events[i].events & (EPOLLHUP | EPOLLERR)){
            Logger::debug("NetworkMonitor:listenForTraffic - Epoll Had An Error. Closing Descriptor");
            close(events[i].data.fd);
            continue;
        }

        if(!(events[i].events & EPOLLIN)){
            Logger::debug("NetworkMonitor::listenForTraffic - Critical Error. Event Has Nothing To Read and No Errors. Why is it here?. Skipping For Now");
            continue;
        }

        // if we make it here then everything is fine and we can start reading from the descriptor
        long bytesRead = read(events[i].data.fd, BUFFER, IP_MAXPACKET);

        Logger::debug("NetworkMonitor:listeningForTraffic - Read Complete");

        struct iphdr * ip = (struct iphdr *)BUFFER;
        int ipHeaderLength = (ip->ihl * 4);
        int protocol = (ip->protocol);

        printf("%d\n", ipHeaderLength);
        printf("%d\n", protocol);

        //how do we know its our packet ?
        //using packet identifier need to determine where our payload information is
        //then need to determine how to authenticate it
        if(Authenticator::isAuthenticPacket(BUFFER)){




        }else{
            //if it is not our packet give it to the TrafficAnalyzer
            this->trafficAnalyzer->addPacketMetaToHistory(PacketIdentifier::generatePacketMeta(BUFFER));

        }
    }


}