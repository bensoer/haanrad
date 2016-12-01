//
// Created by root on 23/11/16.
//

#include "ExecutorQueue.h"

/**
 * addToExeutor adds the passed in HAAN packet represented as a string to the queue using thread safe mechanisms
 * @param haanradPacket String - A HAAN packet represented as a string
 */
void ExecutorQueue::addToExecutor(std::string haanradPacket) {
    this->lock.lock();
    this->queue.push(haanradPacket);
    this->lock.unlock();
}

/**
 * getExecutionTask fetches a HAAN packet from the queue to be processed for execution. This is implemented using thread
 * safe mechanisms. Either the HAAN packet represented as a string is retunred or an empty string is returned symbolizing
 * an empty queue
 * @return String - the HAAN packet represented as a string or an empty string representing an empty queue
 */
std::string ExecutorQueue::getExecutionTask() {

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