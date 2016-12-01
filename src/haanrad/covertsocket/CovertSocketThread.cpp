//
// Created by root on 23/11/16.
//

#include "CovertSocketThread.h"

CovertSocketThread::CovertSocketThread(CovertSocketQueue *queue, CovertSocket * covertSocket) {
    this->covertSocketQueue = queue;
    this->covertSocket = covertSocket;
}

/**
 * start is the main thread entrance method. start executes in an infinite loop until stop is called. The method
 * continually polls the CovertSocketQueue for new data, and upon receiving it, sends it using the CovertSocket send
 * method
 */
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

/**
 * stops the CovertSocketThread from operating. This will cause the start function to return
 */
void CovertSocketThread::stop(){
    this->keepRunning = false;
}