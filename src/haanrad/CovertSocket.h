//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_COVERTSOCKET_H
#define HAANRAD_COVERTSOCKET_H

//covert socket will send all data out of the network, using the TrafficAnalyzer to determine what packet is best
//suited to send at the time

//consideration should also be looked at in terms of what the time currently is, what the current amount of traffic is
//and how busy the system currently is

//if there is allot of network traffic. sending data could be done alot faster. less traffic will require more stealth
//in ensuring the correct kind of packet is sent and the number sent is appropriate

#include "TrafficAnalyzer.h"
#include "../shared/HCrypto.h"

class CovertSocket {


private:

    TrafficAnalyzer * trafficAnalyzer = nullptr;
    HCrypto * crypto = nullptr;

    int rawSocket = -1;

    string clientIP;

    unsigned short csum(unsigned short *ptr, int nbytes);


public:
    CovertSocket(TrafficAnalyzer * trafficAnalyzer, HCrypto * crypto, string clientIP);

    void send(string command);
};


#endif //HAANRAD_COVERTSOCKET_H
