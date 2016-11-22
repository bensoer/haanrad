//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_TIME_H
#define HAANRAD_TIME_H

//Time is essentially a wrapper of a timer which can be customized and set by the SystemState so that actions will only
//happen at appropriate points of execution
class Time {

    //called by SystemState to change the frequency
    void setNewTimeInterval(int interval);

    //hanging function for CovertSocket ? Release will cause it to send
    void covertSocketIsReady();

    //hanging function for Main ? Release will cause it to move to next step
    void mainIsReady();

};


#endif //HAANRAD_TIME_H
