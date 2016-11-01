//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_COMMHANDLER_H
#define HAANRAD_COMMHANDLER_H

//CommHandler will handle all work with sending and receiving data between it and the backdoor
//CommHandler is meant to be continually running and thus checking for new packets

//Any new data collected is then Passed to the main thread via the MessageQueue - Maybe should spawn another thread to do that ? Then we can keep listening sooner

//CommHandler will also be dealing with trade ups and changes in listening ports that may occur during a communication session
class CommHandler {

};


#endif //HAANRAD_COMMHANDLER_H
