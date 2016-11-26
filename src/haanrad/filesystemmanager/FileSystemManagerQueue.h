//
// Created by root on 24/11/16.
//

#ifndef HAANRAD_FILESYSTEMMANAGERQUEUE_H
#define HAANRAD_FILESYSTEMMANAGERQUEUE_H


#include <mutex>
#include <queue>
#include "../../client/Message.h"

class FileSystemManagerQueue {

public:

    void addToQueue(Message message);

    Message getFileMessage();


private:

    std::queue<Message> queue;
    std::mutex lock;
};


#endif //HAANRAD_FILESYSTEMMANAGERQUEUE_H
