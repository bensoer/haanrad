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

    unsigned long long receivedBytes;
    unsigned long long receivedPackets;

    unsigned long long sentBytes;
    unsigned long long sentPackets;

};


#endif //HAANRAD_PROCDEV_H
