//
// Created by bensoer on 12/11/16.
//

#include "../../src/haanrad/NetworkMonitor.h"
#include "../../src/shared/Logger.h"

int main(int argc, char * argv[]){

    Logger::setDebug(true);

    TrafficAnalyzer * analyzer = new TrafficAnalyzer(10);
    NetworkMonitor * monitor = new NetworkMonitor(analyzer);

    string * command = monitor->listenForTraffic();

    delete(analyzer);
    analyzer = nullptr;
    delete(monitor);
    monitor = nullptr;

    return 0;

}