//
// Created by bensoer on 31/10/16.
//

#include <zconf.h>
#include <algorithm>
#include "SystemState.h"
#include "../shared/ProcHelper.h"
#include "../shared/Logger.h"

double SystemState::getAverageProcessCPUUsage() {

    Logger::debug("SystemStats - Calculating Average RAM Usage Per Process");

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

    pids->clear();
    delete(pids);
    pids=nullptr;
    delete(helper);
    helper = nullptr;

    return (difference/ totalProcesses);

}

int SystemState::getPercentageOfCPUUsed() {

    Logger::debug("SystemStats - Calculating Percentage of CPU Used");
    ProcHelper * helper = new ProcHelper();
    int haanradPID = getpid();
    vector<int> * pids = helper->getAllProcessIDs();
    ProcStat * haanradStat = nullptr;

    unsigned long long totalTime;

    for_each(pids->begin(), pids->end(), [helper, &totalTime, haanradPID, &haanradStat](int pid){

        if(pid == haanradPID){
            haanradStat = helper->parseProcessStatInformation(pid);
            totalTime += (haanradStat->utime + haanradStat->stime);
        }else{
            ProcStat * stat = helper->parseProcessStatInformation(pid);
            totalTime += (stat->utime + stat->stime);
            delete(stat);
            stat = nullptr;
        }
    });


    unsigned long long haanradTotalTime = ((haanradStat->utime + haanradStat->stime) - this->previousHaanradCPUTime);
    unsigned long long CPUDifference = totalTime - this->previousTotalCPUTime;

    this->previousHaanradCPUTime = (haanradStat->utime + haanradStat->stime);
    this->previousTotalCPUTime = totalTime;

    delete(haanradStat);
    haanradStat = nullptr;
    pids->clear();
    delete(pids);
    pids = nullptr;
    delete(helper);
    helper = nullptr;

    return (int)((haanradTotalTime / CPUDifference) * 100);

}

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

int SystemState::getPercentageOfRAMUsed() {

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

    return (int)percentageHaanradTakes;
}