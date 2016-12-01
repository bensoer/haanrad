//
// Created by bensoer on 31/10/16.
//

#include "NetworkMonitorThread.h"
#include "../../shared/utils/Logger.h"
#include "../executor/ExecutorQueue.h"

NetworkMonitorThread::NetworkMonitorThread(NetworkMonitor *networkMonitor, ExecutorQueue * executorQueue) {
    this->networkMonitor = networkMonitor;
    this->executorQueue = executorQueue;
}

/**
 * start is the main entrance method that is executed on a seperate thread. This method will hang until the stop command
 * is called and will cotninualy loop polling the network monitor to listenForTraffic and error check the results. If
 * there is too many errors, start will terminate Haanrad. On success, start will pass the received message to the
 * ExecutorQueue to be parsed and checked for its purpose
 */
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

    }
}

/**
 * stop will terminate execution of message parsing from the network by stopping the start method processing. This method
 * will cause the start method to unhang
 */
void NetworkMonitorThread::stop() {
    this->keepRunning = false;
}