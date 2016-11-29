//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_TIME_H
#define HAANRAD_TIME_H

#include <mutex>
#include <sys/time.h>

//Time is essentially a wrapper of a timer which can be customized and set by the SystemState so that actions will only
//happen at appropriate points of execution
class Time {

private:

    static std::mutex tickLock;

    int interval;
    static int numberOfUsers;

    struct itimerval intervalTimer;

    bool skipBlocking = false;



public:

    static void timeoutHandler(int signum);

    Time(int interval = 1000, int numberOfUsers = 5);

    //called by SystemState to change the frequency
    void setNewTimeInterval(int interval);


    void hangForTick();

    void startTimer();

};


#endif //HAANRAD_TIME_H
