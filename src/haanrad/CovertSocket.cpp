//
// Created by bensoer on 31/10/16.
//

#include "CovertSocket.h"
#include "../shared/Logger.h"
#include "SystemState.h"

#include <cerrno>
#include <cstring>

CovertSocket::CovertSocket(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto) {
    this->trafficAnalyzer = trafficAnalyzer;
    this->crypto = crypto;

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
        //if were in startup we get the last one, otherwise its the best one
        meta = this->trafficAnalyzer->getLastPacketAdded();
    }else{
        meta = this->trafficAnalyzer->getBestPacketToSend();
    }


}