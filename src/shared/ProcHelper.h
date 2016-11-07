//
// Created by bensoer on 06/11/16.
//

#ifndef HAANRAD_PROCHELPER_H
#define HAANRAD_PROCHELPER_H


#include <vector>
#include "ProcStat.h"
#include "ProcDev.h"

class ProcHelper {

public:

    ProcStat * parseProcessStatInformation(int pid);

    vector<int> * getAllProcessIDs();

    vector<ProcDev *> * getAllNetworkInterfaceStats();
};


#endif //HAANRAD_PROCHELPER_H
