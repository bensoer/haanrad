//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_SYSTEMSTATE_H
#define HAANRAD_SYSTEMSTATE_H

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


};


#endif //HAANRAD_SYSTEMSTATE_H
