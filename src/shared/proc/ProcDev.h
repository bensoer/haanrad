//
// Created by bensoer on 06/11/16.
//

#ifndef HAANRAD_PROCDEV_H
#define HAANRAD_PROCDEV_H

#include<string>

using namespace std;

class ProcDev {
public:
    string interface;

    long long receivedBytes;
    int receivedPackets;

    int sentBytes;
    long long sentPackets;

};


#endif //HAANRAD_PROCDEV_H
