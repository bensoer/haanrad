//
// Created by bensoer on 06/11/16.
//

#ifndef HAANRAD_PROCHELPER_H
#define HAANRAD_PROCHELPER_H


#include <vector>
#include "ProcStat.h"

class ProcHelper {

public:

    ProcStat * parseProcessStatInformation(int pid);

    vector<int> * getAllProcessIDs();
};


#endif //HAANRAD_PROCHELPER_H
