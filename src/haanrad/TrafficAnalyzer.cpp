//
// Created by bensoer on 31/10/16.
//


#include "TrafficAnalyzer.h"

#include "../shared/PacketIdentifier.h"
#include "../shared/utils/Logger.h"
#include <ctime>
#include <sys/time.h>
#include <algorithm>
#include <map>
#include <stdlib.h>

TrafficAnalyzer::TrafficAnalyzer(int historyLength) {

    this->data = new deque<PacketMeta>();
    //this->data->push_back(deque<PacketMeta>());

    this->historyLength = historyLength;

    this->timestamps = new deque<time_t>();

    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; //get current timestamp in milliseconds
    this->timestamps->push_back(ms);
}

/**
 * addPacketMetaToHistory adds the passed in packet to the history of packets to be analyzed for packet sending by
 * the CovertSocket
 * @param packet PacketMEta - object representation of a packet
 */
void TrafficAnalyzer::addPacketMetaToHistory(PacketMeta packet) {
    this->addPacketLock.lock();
    //deque<PacketMeta> currentHistory = this->data->back(); //back returns a reference to the last item
    Logger::debug("TrafficAnalyzer:addPacketMetaToHistory - Adding Packet To History. Current History Holds: "
                  + to_string(this->data->size()) + " Entries");
    this->data->push_back(packet);
    Logger::debug("TrafficAnalyzer:addPacketMetaToHistory - Packet Entry Added. History Now Holds: "
                  + to_string(this->data->size()) + " Entries");

    //this->data->emplace_back(currentHistory);


    if(this->data->size() >= 100){
        Logger::debug("TrafficAnalyzer:addPacketMetaToHistory - History Contains 100 or More Packets. Creating New Time Segment");
        this->data->pop_front();
    }

    this->addPacketLock.unlock();


}

/**
 * setNewTimeSegment is a helper method that will set a new base time interval segment and add it to the timestamp queue.
 * This is useful when storing multipl deque's of history, allowing for period based analyses. This functionality is currently
 * deprecated
 */
void TrafficAnalyzer::setNewTimeSegment() {
    Logger::debug("TrafficAnalyzer:setNewTimeSegment - Setting New Time Segment");

    /*unsigned long dataLength = this->data->size();
    if(dataLength + 1 > this->historyLength){
        //deque<PacketMeta> previousHistory = this->data->front();
        //previousHistory.clear();
        //this->data->pop_front();
        this->data->clear();

    }*/
    //this->data->push_back(deque<PacketMeta>());

    unsigned long timestampLength = this->timestamps->size();
    if(timestampLength + 1 > this->historyLength){
        this->timestamps->pop_front();
    }

    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; //get current timestamp in milliseconds
    this->timestamps->push_back(ms);
}

/**
 * getBestPAcketToSend takes a snapshot of the current packet queue and analysis it for the best packets to be sent
 * by the client. This is implemented by simply tallying all the different kinds of supported packet types and then
 * picking the most popular type. After which a random packet of the most popular type is picked from the snapshot
 * and returned
 * @return PacketMeta - An object representation of a packet, representing the best packet to send with at the
 * current snapshot of the packets stored in the TrafficAnalyzer
 */
PacketMeta TrafficAnalyzer::getBestPacketToSend() {
    //this->historyLock.lock();

    //deque<PacketMeta> currentHistory = this->data->back();

    this->addPacketLock.lock();
    deque<PacketMeta> historySnapshot((*this->data));
    this->addPacketLock.unlock();

    long dnsPackets = 0;
    long tlsPackets = 0;
    long tcpPackets = 0;
    long udpPackets = 0;

    map<int, long> counts;
    counts.insert(pair<int, long>(ApplicationType::TLS, 0));
    counts.insert(pair<int, long>(ApplicationType::DNS, 0));
    counts.insert(pair<int, long>(TransportType::UDP, 0));
    counts.insert(pair<int, long>(TransportType::TCP, 0));

    for_each(historySnapshot.begin(), historySnapshot.end(), [&counts] (PacketMeta meta){

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
        counts.clear();

        while(1){

            if(this->data->size() <= 0){
                Logger::debug("TrafficAnalyzer:getBestPAcketToSend - The Storage Is Empty!. Waiting To Try Again");
                continue;
            }

            unsigned int index = (rand() % historySnapshot.size());
            if(this->data->at(index).applicationType == chosenType){
                PacketMeta meta = this->data->at(index);
                return meta;
            }
        }

    }else{
        //then its a transport layer
        TransportType::TransportTypeEnum chosenType = (TransportType::TransportTypeEnum)highestKey;
        counts.clear();

        while(1){

            if(this->data->size() <= 0){
                Logger::debug("TrafficAnalyzer:getBestPacketToSend - The Storage Is Empty!. Waiting To Try Again");
                continue;
            }

            unsigned int index = (rand() % historySnapshot.size());
            if(this->data->at(index).transportType == chosenType && this->data->at(index).applicationType == ApplicationType::UNKNOWN){
                PacketMeta meta = this->data->at(index);
                return meta;
            }
        }

    }
}

/**
 * getLastPacketAdded is a method used during startup mode to fetch the DNS packet detected by the NetworkMonitor
 * @return PacketMEta - an object representation of a packet
 */
PacketMeta TrafficAnalyzer::getLastPacketAdded() {
    Logger::debug("TrafficAnalyzer:getLastPacketAdded - Fetching Last Packet Added To TrafficAnalyser");
    return this->data->back();
}