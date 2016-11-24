//
// Created by root on 23/11/16.
//

#include "CovertSocketThread.h"

CovertSocketThread::CovertSocketThread(CovertSocketQueue *queue, CovertSocket * covertSocket) {
    this->covertSocketQueue = queue;
    this->covertSocket = covertSocket;
}

void CovertSocketThread::start() {

    //this is basically an infinite loop
    while(this->keepRunning){

        std::string haanradPacket = this->covertSocketQueue->getNextPacketToSend();
        if(haanradPacket.compare("") != 0) {
            //this is a valid packet that needs to be sent
            this->covertSocket->send(haanradPacket);
        }
    }
}

void CovertSocketThread::stop(){
    this->keepRunning = false;
}