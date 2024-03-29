//
// Created by bensoer on 12/11/16.
//

#include "../../src/haanrad/networkmonitor/NetworkMonitor.h"
#include "../../src/shared/utils/Logger.h"
#include "../../src/shared/HCrypto.h"

int main(int argc, char * argv[]){

    Logger::setDebug(true);

    Time * time = new Time();
    SystemState * ss = SystemState::getInstance(time);
    TrafficAnalyzer * analyzer = new TrafficAnalyzer(10);
    HCrypto * crypto = new HCrypto();
    crypto->initialize("password");
    NetworkMonitor * monitor = NetworkMonitor::getInstance(analyzer,crypto, "127.0.0.1");

    string * command = monitor->listenForTraffic();

    delete(analyzer);
    analyzer = nullptr;
    delete(monitor);
    monitor = nullptr;

    return 0;

}