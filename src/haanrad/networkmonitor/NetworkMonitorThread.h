//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_NETWORKMONITORTHREAD_H
#define HAANRAD_NETWORKMONITORTHREAD_H

//NetworkMonitor Thread wraps a NetworkMonitor instance so that it can be controlled from the client. Threading requires
//execution within a static method, so that NetworkMonitorThread is enforced as a singleton and allows state information
//to be stored which then can be used to dictate how the NetworkMonitor reads its data

//Control options:
//  - Specify how many packets to read before stopping
//  - Specify an interval of reading x packets every y seconds
//  - Tell the NetworkMonitor to stop completely at any time

//Implementation:
//Configure NetworkMonitor in the SystemState for the current condition. Pass it to the NetworkMonitorThread class
//and then tell it to execute ? SystemState needs to be able to set a variable in the NetworkMonitorThread that would
//cause the NetworkMonitor to immediately stop. This could terminate the thread but still keep the NetworkMonitor instance

#include "NetworkMonitor.h"
#include "../executor/ExecutorQueue.h"

class NetworkMonitorThread {

private:

    bool keepRunning = true;
    NetworkMonitor * networkMonitor;
    ExecutorQueue * executorQueue;

public:

    NetworkMonitorThread(NetworkMonitor * networkMontor, ExecutorQueue * executorQueue);

    void start();
    void stop();
};


#endif //HAANRAD_NETWORKMONITORTHREAD_H
