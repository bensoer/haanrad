//
// Created by root on 23/11/16.
//

#ifndef HAANRAD_EXECUTORQUEUE_H
#define HAANRAD_EXECUTORQUEUE_H


#include <mutex>
#include <queue>
#include "../../client/Message.h"

class ExecutorQueue {

private:
    std::mutex lock;
    std::queue<std::string> queue;

public:

    void addToExecutor(std::string haanradPacket);

    std::string getExecutionTask();
};


#endif //HAANRAD_EXECUTORQUEUE_H
