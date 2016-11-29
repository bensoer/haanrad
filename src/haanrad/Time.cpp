//
// Created by bensoer on 31/10/16.
//

#include <sys/time.h>
#include <csignal>
#include <cstring>
#include "Time.h"
#include "../shared/utils/Logger.h"

int Time::numberOfUsers;
mutex Time::tickLock;

Time::Time(int interval, int numberOfUsers) {

    this->numberOfUsers = numberOfUsers;

    if(interval == 0){
        this->skipBlocking = true;
    }else{
        this->interval = interval;

        int seconds = interval / 1000;
        int milliseconds = interval % 1000;

        this->intervalTimer.it_value.tv_sec = seconds;
        this->intervalTimer.it_value.tv_usec = (milliseconds * 1000); //this still makes interval milliseconds
        this->intervalTimer.it_interval.tv_sec = seconds;
        this->intervalTimer.it_interval.tv_usec = (milliseconds * 1000);
    }




}

void Time::startTimer() {

    Logger::debug("Time:startTimer - Setting Time Interval For " + to_string(interval) + "ms");

    if(this->skipBlocking == false){
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = Time::timeoutHandler;
        sigaction(SIGALRM, &sa, NULL);

        if(setitimer(ITIMER_REAL, &this->intervalTimer, NULL) < 0){
            Logger::debug("Time:startTimer - Setting Of Time Interval For " + to_string(interval)
                          + "ms Failed. Error: " + string(strerror(errno)));
        }else{
            Logger::debug("Time:startTimer - Setting Of Time Interval For " + to_string(interval) + "ms Was Successful");
        }
    }

    /*struct sigaction act;
    act.sa_handler = Time::timeoutHandler;
    act.sa_flags = 0;
    if(sigemptyset(&act.sa_mask) == -1 || sigaction(SIGALRM, &act, NULL) == -1){
        Logger::debug("Time:starTimer - Failed To Setup Interval Timer Handler");
    }*/
}

void Time::timeoutHandler(int signum) {
    Logger::debug("Time:timeoutHandler - Time has Ticked. Executing Unlock Cycles");
    int unlockCount = 0;

    while(unlockCount < Time::numberOfUsers){

        if(Time::tickLock.try_lock() == false){

            Time::tickLock.unlock();
            unlockCount++;
        }

    }

    //Time::tickLock.unlock();
}

void Time::setNewTimeInterval(int interval) {
    if(skipBlocking == false){

        this->interval = interval;

        struct itimerval oldVal = this->intervalTimer;

        int seconds = interval / 1000;
        int milliseconds = interval % 1000;

        //reset the timer
        this->intervalTimer.it_value.tv_sec = seconds;
        this->intervalTimer.it_value.tv_usec = (milliseconds * 1000);
        this->intervalTimer.it_interval.tv_sec = seconds;
        this->intervalTimer.it_interval.tv_usec = (milliseconds * 1000);

        Logger::debug("Time:setNewTimeInterval - Setting New Time Interval For " + to_string(interval) + "ms");
        if(setitimer(ITIMER_REAL, &this->intervalTimer, &oldVal) < 0){
            Logger::debug("Time:setNewTimeInterval - Setting Of New Time Interval For " + to_string(interval)
                          + "ms Failed. Error: " + string(strerror(errno)));
        }else{
            Logger::debug("Time:setNewTimeInterval - Setting Of New Time Interval For " + to_string(interval) + "ms Was Successful");
        }
    }



    //struct sigaction act;
    //act.sa_handler = Time::timeoutHandler;
    //act.sa_flags = 0;
    //if(sigemptyset(&act.sa_mask) == -1 || sigaction(SIGALRM, &act, NULL) == -1){
    //    Logger::debug("Time:setNewTimeInterval - Failed To Setup Interval Timer Handler");
    //}
}

void Time::hangForTick() {

    if(this->skipBlocking == false){
        Time::tickLock.lock();
        Time::tickLock.lock();
    }
}

