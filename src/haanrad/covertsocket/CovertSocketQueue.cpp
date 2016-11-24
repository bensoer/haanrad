//
// Created by root on 23/11/16.
//

#include "CovertSocketQueue.h"

void CovertSocketQueue::addPacketToSend(std::string haanradPacket) {
    this->lock.lock();
    this->queue.push(haanradPacket);
    this->lock.unlock();
}

std::string CovertSocketQueue::getNextPacketToSend() {
    this->lock.lock();
    if(this->queue.empty()){

        this->lock.unlock();
        return "";

    }else{
        std::string haanradPacket = this->queue.front();
        this->lock.unlock();
        return haanradPacket;
    }

}