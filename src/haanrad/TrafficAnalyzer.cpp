//
// Created by bensoer on 31/10/16.
//


#include "TrafficAnalyzer.h"

#include "../shared/PacketFactory.h"
#include <ctime>

TrafficAnalyzer::TrafficAnalyzer(int historyLength) {

    this->data = new deque<deque<PacketMeta>>();
    this->data->push_back(deque<PacketMeta>());

    this->historyLength = historyLength;

    this->timestamps = new deque<time_t>();
    time_t time = std::time(nullptr);
    this->timestamps->push_back(time);
}

void TrafficAnalyzer::addPacketMetaToHistory(PacketMeta packet) {
    deque<PacketMeta> currentHistory = this->data->back(); //back returns a reference to the last item
    currentHistory.push_back(packet);
}

void TrafficAnalyzer::setNewTimeSegment() {

    unsigned long dataLength = this->data->size();
    if(dataLength + 1 > this->historyLength){
        this->data->pop_front();
    }
    this->data->push_back(deque<PacketMeta>());

    unsigned long timestampLength = this->timestamps->size();
    if(timestampLength + 1 > this->historyLength){
        this->timestamps->pop_front();
    }
    this->timestamps->push_back(std::time(nullptr));
}