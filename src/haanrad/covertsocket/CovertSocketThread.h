//
// Created by root on 23/11/16.
//

#ifndef HAANRAD_COVERTSOCKETTHREAD_H
#define HAANRAD_COVERTSOCKETTHREAD_H


#include "CovertSocketQueue.h"
#include "CovertSocket.h"

class CovertSocketThread {

private:
    CovertSocketQueue * covertSocketQueue = nullptr;
    CovertSocket * covertSocket = nullptr;

    bool keepRunning = true;

public:
    CovertSocketThread(CovertSocketQueue * queue, CovertSocket * covertSocket);

    void start();
    void stop();
};


#endif //HAANRAD_COVERTSOCKETTHREAD_H
