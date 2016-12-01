//
// Created by root on 23/11/16.
//

#include "CovertSocketQueue.h"

/**
 * addPAcketToSend adds the passed in HAAN packet as a string to the queue to be sent via the CovertSocket using
 * thread safe mechanisms
 * @param haanradPacket String - the HAAN packet represented as a string
 */
void CovertSocketQueue::addPacketToSend(std::string haanradPacket) {
    this->lock.lock();
    this->queue.push(haanradPacket);
    this->lock.unlock();
}

/**
 * getNextPacketToSend polls the queue for new packets to send. If there are none, an empty string is retunred, otherwise
 * the appropriate HAAN packet is returned using thread safe mechanisms
 * @return String  - the HAAN packet represented as a string
 */
std::string CovertSocketQueue::getNextPacketToSend() {
    this->lock.lock();
    if(this->queue.empty()){

        this->lock.unlock();
        return "";

    }else{
        std::string haanradPacket = this->queue.front();
        this->queue.pop();
        this->lock.unlock();
        return haanradPacket;
    }

}