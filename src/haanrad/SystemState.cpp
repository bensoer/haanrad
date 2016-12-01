//
// Created by bensoer on 31/10/16.
//

#include <zconf.h>
#include <algorithm>
#include <sys/time.h>
#include "SystemState.h"
#include "../shared/proc/ProcHelper.h"
#include "../shared/utils/Logger.h"


SystemState::SystemStateMode SystemState::currentState = SystemStateMode::STARTUP;
SystemState * SystemState::instance = nullptr;

SystemState::SystemState(Time * time) {
    this->time = time;

    this->resetNetworkCheckTime();

    //set history to so that future is correct
    this->getInboundBitRate(true);
    this->getOutboundBitRate(true);
    this->getAverageProcessCPUUsage(true);
    this->getPercentageOfCPUUsed(true);
}

SystemState * SystemState::getInstance(Time * time) {

    if(SystemState::instance == nullptr){
        SystemState::instance = new SystemState(time);
    }

    return SystemState::instance;
}

/**
 * getSystemTime is a helper method that gets the current system time in Unic timestamp in milliseconds
 * @return Long Int - the Unix timestamp in milliseconds
 */
long int SystemState::getSystemTime() {

    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; //get current timestamp in milliseconds

    return ms;
}

/**
 * resetNEtworkCheckTime fetches the current timestamp and sets it as the new network check time
 */
void SystemState::resetNetworkCheckTime() {

    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; //get current timestamp in milliseconds

    this->previousCheckTime = ms;
}

/**
 * getOutboundBitRate calculates the outbound bitrate of the system using the ProcHelper
 * @param setHistoryOnly Bool - sets whether to set only the history inforamtion from the calculation. If this is true,
 * 0 is retunred from the function
 * @return Long Long - The outbound bitrate in bits or 0 if setHistoryOnly si true
 */
unsigned long long SystemState::getOutboundBitRate(bool setHistoryOnly) {

    ProcHelper * helper = new ProcHelper();
    vector<ProcDev> * interfaceList = helper->getAllNetworkInterfaceStats();

    unsigned long long totalOutboundBits = 0;
    for_each(interfaceList->begin(), interfaceList->end(), [&totalOutboundBits](ProcDev interface){
        totalOutboundBits += (interface.sentBytes * 8);

    });



    long int now = this->getSystemTime();
    unsigned long long bitRate = 0;

    if(setHistoryOnly){
        this->previousOutboundBits = totalOutboundBits;
    }else{
        time_t difference = now - this->previousCheckTime;
        unsigned long long bitDifference = (totalOutboundBits - this->previousOutboundBits);
        bitRate = (bitDifference / difference);
        this->previousOutboundBits = totalOutboundBits;
    }

    interfaceList->clear();
    delete(interfaceList);
    interfaceList = nullptr;
    delete(helper);
    helper = nullptr;

    return bitRate;
}

/**
 * getInboundBitRate calculates the inbound bitrate of the system using the ProcHelper
 * @param setHistoryOnly Bool - sets whether to set only the history inforamtion from the calculation. If this is true,
 * 0 is retunred from the function
 * @return Long Long - The intbound bitrate in bits or 0 if setHistoryOnly si true
 */
unsigned long long SystemState::getInboundBitRate(bool setHistoryOnly) {

    ProcHelper * helper = new ProcHelper();
    vector<ProcDev> * interfaceList = helper->getAllNetworkInterfaceStats();

    unsigned long long totalInboundBits = 0;
    for_each(interfaceList->begin(), interfaceList->end(), [&totalInboundBits](ProcDev interface){
        totalInboundBits += (interface.receivedBytes * 8);

        //cleanup now
        //delete(interface);
        //interface = nullptr;
    });

    long int now = this->getSystemTime();
    unsigned long long bitRate = 0;

    if(setHistoryOnly){
        this->previousInboundBits = totalInboundBits;
    }else{
        time_t difference = now - this->previousCheckTime;
        unsigned long long bitDifference = totalInboundBits - this->previousInboundBits;
        bitRate = (bitDifference / difference);
        this->previousInboundBits = totalInboundBits;
    }

    interfaceList->clear();
    delete(interfaceList);
    interfaceList = nullptr;
    delete(helper);
    helper = nullptr;

    return bitRate;
}

/**
 * getAverageProcessCPUUsage calculates the average CPU time used by all processes running on the system
 * @param setHistoryOnly Bool - set whether to return the average in milliseconds or only set the history variables for future
 * calculations
 * @return Double - the average in milliseconds of the process cpu usage or 0 if setHistoryOnly is true
 */
double SystemState::getAverageProcessCPUUsage(bool setHistoryOnly) {

    Logger::debug("SystemStats - Calculating Average CPU Usage Per Process");

    ProcHelper * helper = new ProcHelper();
    vector<int> * pids = helper->getAllProcessIDs();

    unsigned long long totalCPUUsed = 0;
    double totalProcesses = pids->size();

    for_each(pids->begin(), pids->end(), [&totalCPUUsed, &totalProcesses, helper](int pid){

        ProcStat * stat = helper->parseProcessStatInformation(pid);
        totalCPUUsed += (stat->utime + stat->stime);
    });

    unsigned long long difference = totalCPUUsed - this->previousTotalCPUTime;

    //should we store this new difference for next measurement ?
    this->previousTotalCPUTime = totalCPUUsed;

    pids->clear();
    delete(pids);
    pids=nullptr;
    delete(helper);
    helper = nullptr;

    return (difference/ totalProcesses);

}

/**
 * getPercentageOfCPUUsed calculates what percent of the CPU time has been spend executing Haanrad
 * @param setHistoryOnly Bool - set whether to return the calculated percent or to only set the history variables
 * needed for the next calculation
 * @return Double - the percentage of usage or 0 if setHistoryOnly is true
 */
double SystemState::getPercentageOfCPUUsed(bool setHistoryOnly) {

    Logger::debug("SystemStats - Calculating Percentage of CPU Used");
    ProcHelper * helper = new ProcHelper();
    int haanradPID = getpid();
    vector<int> * pids = helper->getAllProcessIDs();
    ProcStat * haanradStat = nullptr;

    unsigned long long totalTime = 0;

    for_each(pids->begin(), pids->end(), [helper, &totalTime, haanradPID, &haanradStat](int pid){

        if(pid == haanradPID){
            haanradStat = helper->parseProcessStatInformation(pid);
            totalTime += (haanradStat->utime + haanradStat->stime);
        }else{
            ProcStat * stat = helper->parseProcessStatInformation(pid);
            totalTime += (stat->utime + stat->stime);
            //delete(stat);
            //stat = nullptr;
        }
    });


    long long haanradTotalTime = ((haanradStat->utime + haanradStat->stime) - this->previousHaanradCPUTime);
    unsigned long long CPUDifference = 0;
    if(setHistoryOnly){
        this->previousTotalCPUTime = totalTime;
        this->previousHaanradCPUTime = (haanradStat->utime + haanradStat->stime);
        return 0;
    }else{
        CPUDifference = totalTime - this->previousTotalCPUTime;
        this->previousHaanradCPUTime = (haanradStat->utime + haanradStat->stime);
        this->previousTotalCPUTime = totalTime;
    }

    delete(haanradStat);
    haanradStat = nullptr;
    pids->clear();
    delete(pids);
    pids = nullptr;
    delete(helper);
    helper = nullptr;

    if(haanradTotalTime == 0 && CPUDifference == 0){
        return 0.00000000000;
    }else if(haanradTotalTime > CPUDifference) {
        Logger::debug("SystemState:getPercentageOfCPUUsage - Error Misread. Could Not Read Stats Properly. haanradTotalTime: >"
                      + to_string(haanradTotalTime) + "< CPUDifference: >" + to_string(CPUDifference) + "<");
        return 0.00000000000;
    }else{
        return ((haanradTotalTime / CPUDifference) * 100);
    }



}

/**
 * getAverageProcessRAMUsage calculates the average amount of space every process is using in memory currently
 * @return Double - the average amount of ram used
 */
double SystemState::getAverageProcessRAMUsage() {

    Logger::debug("SystemStats - Calculating Average RAM Usage Per Process");

    ProcHelper * helper = new ProcHelper();
    vector<int> * pids = helper->getAllProcessIDs();

    double totalRAMUsed = 0;
    double totalProcesses = pids->size();

    for_each(pids->begin(), pids->end(), [&totalRAMUsed, &totalProcesses, helper](int pid){

        ProcStat * stat = helper->parseProcessStatInformation(pid);
        totalRAMUsed += stat->rss;
    });

    return (totalRAMUsed/ totalProcesses);

}

/**
 * getPercentageOfRAMUsed calculates how much RAM haanrad is using in compared to all other processes on the system
 * @return Double the percentage of RAM haanrad is using
 */
double SystemState::getPercentageOfRAMUsed() {

    Logger::debug("SystemState - Calculating RAM Usage Percent");
    int haanradPID = getpid();
    ProcHelper * helper = new ProcHelper();
    vector<int> * pids = helper->getAllProcessIDs();
    ProcStat * haanradStat = nullptr;
    double totalProcessesRAM = 0;

    //calculate percentage
    for_each(pids->begin(), pids->end(), [&totalProcessesRAM, &haanradStat, haanradPID, helper](int pid){

        if(pid == haanradPID){
            haanradStat = helper->parseProcessStatInformation(pid);
            totalProcessesRAM += haanradStat->rss;
        }else{
            ProcStat * stat = helper->parseProcessStatInformation(pid);
            totalProcessesRAM += stat->rss;
            delete(stat);
            stat = nullptr;
        }
    });

    Logger::debug("SystemState - Making Calculation and Cast");
    double percentageHaanradTakes = (haanradStat->rss / totalProcessesRAM) * 100;

    Logger::debug("SystemState - Cleaning Up And returning");
    delete(haanradStat);
    haanradStat = nullptr;
    pids->clear();
    delete(pids);
    pids = nullptr;
    delete(helper);
    helper = nullptr;

    return percentageHaanradTakes;
}