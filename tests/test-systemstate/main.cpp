

#include "../../src/haanrad/SystemState.h"
#include "../../src/shared/utils/Logger.h"

int main(int argc, char * argv[]){


    Logger::setDebug(true);
    Logger::debug("Creating System State");
    Time * time = new Time();
    SystemState * ss = SystemState::getInstance(time);

    Logger::debug("Calculating CPU Stats");

    sleep(10);

    //get system average cpu
    double avgProcessCPUUsage = ss->getAverageProcessCPUUsage();
    //get our percent usage of cpu
    double cpuUsage = ss->getPercentageOfCPUUsed();

    Logger::debug("Average CPU Usage: " + to_string(avgProcessCPUUsage) + " Clock Ticks");
    Logger::debug("Our % of CPU Usage: " + to_string(cpuUsage) + " Clock Ticks");

    Logger::debug("Calculating RAM Stats");

    //get system average ram usage
    double avgProcessRAMUsage = ss->getAverageProcessRAMUsage();
    //get our percent usage of ram
    double ramUsage = ss->getPercentageOfRAMUsed();

    Logger::debug("Average RAM Usage: " + to_string(avgProcessRAMUsage) + " Pages In Resident Set");
    Logger::debug("Our % of RAM Usage: " + to_string(ramUsage) + " Pages In Resident Set");

    Logger::debug("Calculating Network Stats");

    //determine how busy it is
    double inboundBitRate = ss->getInboundBitRate();
    double outboundBitRate = ss->getOutboundBitRate();

    Logger::debug("System Inbound BitRate: " + to_string(inboundBitRate));
    Logger::debug("System Outbound BitRate: " + to_string(outboundBitRate));
}
