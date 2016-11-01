//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_TRAFFICANALYZER_H
#define HAANRAD_TRAFFICANALYZER_H

// TrafficAnalyzer stores statistic information and packet information on Traffic sent to it. It then based on this
// information will determine the best kind of packet that should be sent from the system.

// measurements should be based on ratios of packet types but also have time consideration. There may have been
// alot of DNS traffic but that stopped now for 20 minutes. Is DNS the best idea to send now ?

class TrafficAnalyzer {

};


#endif //HAANRAD_TRAFFICANALYZER_H
