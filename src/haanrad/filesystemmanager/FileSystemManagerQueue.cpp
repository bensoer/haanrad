//
// Created by root on 24/11/16.
//

#include "FileSystemManagerQueue.h"

/**
 * addToQueue adds the passed in Message object to the queue using thread safe mechanisms. Items added to this queue
 * will be processed by the FileSystemManagerThread
 * @param message
 */
void FileSystemManagerQueue::addToQueue(Message message) {

    this->lock.lock();
    this->queue.push(message);
    this->lock.unlock();
}

/**
 * getFileMessage polls the queue for Message objects using thread safe mechanisms.
 * @return Message - A Message object of a new FileSystem change or an INTERCLIENT message of type EMPTY representing
 * and empty queue
 */
Message FileSystemManagerQueue::getFileMessage() {
    this->lock.lock();

    if(this->queue.empty()){

        Message message;
        message.messageType = MessageType::INTERCLIENT;
        message.interMessageCode = InterClientMessageType::EMPTY;

        this->lock.unlock();
        return message;
    }else{

        Message message = this->queue.front();
        this->queue.pop();
        this->lock.unlock();
        return message;

    }

}