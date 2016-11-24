//
// Created by bensoer on 31/10/16.
//

#include "NetworkMonitorThread.h"
#include "../../shared/Logger.h"

NetworkMonitorThread::NetworkMonitorThread(NetworkMonitor *networkMonitor) {
    this->networkMonitor = networkMonitor;
}

void NetworkMonitorThread::start() {

    while(this->keepRunning){

        string * haanradPacket = this->networkMonitor->listenForTraffic();

        Logger::debug("NetworkMonitorThread:start - Full Haanrad Packet Retrieved");
        Logger::debug("NetworkMonitorThread:start - Packet: >" + *haanradPacket + "<");

        this->stop();

    }
}

void NetworkMonitorThread::stop() {
    this->keepRunning = false;
}