//
// Created by bensoer on 31/10/16.
//

#include "NetworkMonitorThread.h"
#include "../../shared/Logger.h"
#include "../executor/ExecutorQueue.h"

NetworkMonitorThread::NetworkMonitorThread(NetworkMonitor *networkMonitor, ExecutorQueue * executorQueue) {
    this->networkMonitor = networkMonitor;
    this->executorQueue = executorQueue;
}

void NetworkMonitorThread::start() {

    int startupCount = 0;

    while(this->keepRunning){

        string * haanradPacket = this->networkMonitor->listenForTraffic();

        if(haanradPacket == nullptr && startupCount < 5){
            Logger::debug("NetworkMonitorThread:start - NetworkMonitor Returned nullptr. Assumed Startup Error");
            startupCount++;
        }

        if(haanradPacket != nullptr && startupCount > 0){
            startupCount = 0;
        }

        if(haanradPacket == nullptr && startupCount == 5){
            Logger::debug("NetworkMonitorThread:start - NetworkMonitor Failed To Start 5 Times Consecutively. Haanrad Can't Operate");
            Logger::debug("NetworkMonitorThread:start - Injecting hsuicide command to Terminate");

            //NOTE EXPLICIT INJECTION OF HARDCODED SUICIDE
            haanradPacket = new string("{HAAN4hsuicideHAAN}");
        }

        Logger::debug("NetworkMonitorThread:start - Full Haanrad Packet Retrieved");
        Logger::debug("NetworkMonitorThread:start - Packet: >" + *haanradPacket + "<");

        //from here it should pass this contents to the executor to sort out
        this->executorQueue->addToExecutor(*haanradPacket);

        //cleanup the string
        delete(haanradPacket);

    }
}

void NetworkMonitorThread::stop() {
    this->keepRunning = false;
}