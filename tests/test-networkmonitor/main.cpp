//
// Created by bensoer on 12/11/16.
//

#include "../../src/haanrad/NetworkMonitor.h"
#include "../../src/shared/Logger.h"

int main(int argc, char * argv[]){

    Logger::setDebug(true);

    NetworkMonitor * monitor = new NetworkMonitor();

    string * command = monitor->listenForTraffic();

    delete(monitor);
    monitor = nullptr;

    return 0;

}