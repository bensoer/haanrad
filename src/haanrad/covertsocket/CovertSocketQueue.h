//
// Created by root on 23/11/16.
//

#ifndef HAANRAD_COVERTSOCKETQUEUE_H
#define HAANRAD_COVERTSOCKETQUEUE_H


#include "../../shared/PacketMeta.h"
#include <queue>
#include <mutex>

class CovertSocketQueue {

private:
    std::mutex lock;

    std::queue<std::string> queue;

public:

    std::string getNextPacketToSend();

    void addPacketToSend(std::string haanradPacket);

};


#endif //HAANRAD_COVERTSOCKETQUEUE_H
