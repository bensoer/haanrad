//
// Created by bensoer on 31/10/16.
//


#include "TrafficAnalyzer.h"

#include "../shared/PacketIdentifier.h"
#include "../shared/Logger.h"
#include <ctime>
#include <sys/time.h>
#include <algorithm>
#include <map>
#include <stdlib.h>

TrafficAnalyzer::TrafficAnalyzer(int historyLength) {

    this->data = new deque<deque<PacketMeta>>();
    this->data->push_back(deque<PacketMeta>());

    this->historyLength = historyLength;

    this->timestamps = new deque<time_t>();

    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; //get current timestamp in milliseconds
    this->timestamps->push_back(ms);
}

void TrafficAnalyzer::addPacketMetaToHistory(PacketMeta packet) {

    deque<PacketMeta> currentHistory = this->data->back(); //back returns a reference to the last item
    Logger::debug("TrafficAnalyzer:addPacketMetaToHistory - Adding Packet To History. Current History Holds: "
                  + to_string(currentHistory.size()) + " Entries");
    currentHistory.push_back(packet);
    Logger::debug("TrafficAnalyzer:addPacketMetaToHistory - Packet Entry Added. History Now Holds: "
                  + to_string(currentHistory.size()) + " Entries");

    this->data->emplace_back(currentHistory);

    if(currentHistory.size() >= 100){
        Logger::debug("TrafficAnalyzer:addPacketMetaToHistory - History Contains 100 or More Packets. Creating New Time Segment");
        this->setNewTimeSegment();
    }

}

void TrafficAnalyzer::setNewTimeSegment() {
    Logger::debug("TrafficAnalyzer:setNewTimeSegment - Setting New Time Segment");

    unsigned long dataLength = this->data->size();
    if(dataLength + 1 > this->historyLength){
        this->data->pop_front();
    }
    this->data->push_back(deque<PacketMeta>());

    unsigned long timestampLength = this->timestamps->size();
    if(timestampLength + 1 > this->historyLength){
        this->timestamps->pop_front();
    }

    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; //get current timestamp in milliseconds
    this->timestamps->push_back(ms);
}

PacketMeta TrafficAnalyzer::getBestPacketToSend() {

    deque<PacketMeta> currentHistory = this->data->back();

    long dnsPackets = 0;
    long tlsPackets = 0;
    long tcpPackets = 0;
    long udpPackets = 0;

    map<int, long> counts;
    counts.insert(pair<int, long>(ApplicationType::TLS, 0));
    counts.insert(pair<int, long>(ApplicationType::DNS, 0));
    counts.insert(pair<int, long>(TransportType::UDP, 0));
    counts.insert(pair<int, long>(TransportType::TCP, 0));

    for_each(currentHistory.begin(), currentHistory.end(), [&counts] (PacketMeta meta){

        if(meta.applicationType != ApplicationType::UNKNOWN){
            switch(meta.applicationType){
                case ApplicationType::DNS:{
                   counts[ApplicationType::DNS]++;
                    break;
                }
                case ApplicationType::TLS:{
                    counts[ApplicationType::TLS]++;
                    break;
                }
                default:{
                    Logger::debug("TrafficAnalyzer:getBestPacketToSend - Application Type Unknown. Unusable Packet");
                    break;
                }
            }
        }

        switch(meta.transportType){
            case TransportType::TCP:{
                counts[TransportType::TCP]++;
                break;
            }
            case TransportType::UDP:{
                counts[TransportType::UDP]++;
                break;
            }
            default:{
                Logger::debug("TrafficAnalyzer:getBestPAcketToSend - Transport Type Unknown. Unusable Packet");
                break;
            }
        }

    });

    int highestKey = 0;
    long highestValue = 0;
    for_each(counts.begin(), counts.end(), [&highestKey, &highestValue](pair<int, long> count){
        if(count.second > highestValue){
            highestKey = count.first;
            highestValue = count.second;
        }
    });

    if(highestKey > 17){
        //then its an application layer
        ApplicationType::ApplicationTypeEnum chosenType = (ApplicationType::ApplicationTypeEnum)highestKey;

        while(1){

            unsigned int index = rand() % currentHistory.size();
            if(currentHistory.at(index).applicationType == chosenType){

                return currentHistory.at(index);
            }

        }

    }else{
        //then its a transport layer
        TransportType::TransportTypeEnum chosenType = (TransportType::TransportTypeEnum)highestKey;

        while(1){

            unsigned int index = rand() % currentHistory.size();
            if(currentHistory.at(index).transportType == chosenType){

                return currentHistory.at(index);
            }

        }

    }
}

PacketMeta TrafficAnalyzer::getLastPacketAdded() {
    Logger::debug("TrafficAnalyzer:getLastPacketAdded - Fetching Last Packet Added To TrafficAnalyser");
    deque<PacketMeta> currentHistory = this->data->back();
    return currentHistory.back();
}