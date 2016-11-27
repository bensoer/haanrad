//
// Created by root on 24/11/16.
//

#include "FileSystemManagerQueue.h"

void FileSystemManagerQueue::addToQueue(Message message) {

    this->lock.lock();
    this->queue.push(message);
    this->lock.unlock();
}


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