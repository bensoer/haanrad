//
// Created by bensoer on 06/11/16.
//

#ifndef HAANRAD_PROCSTAT_H
#define HAANRAD_PROCSTAT_H

#include<string>

using namespace std;

class ProcStat {

public:
    int pid;
    string comm;
    char state;
    int ppid;
    int pgrp;
    int session;
    int tty_nr;
    int tpgid;

    unsigned int flags;
    unsigned long minflt;
    unsigned long cminflt;
    unsigned long majflt;
    unsigned long cmajflt;

    unsigned long utime;
    unsigned long stime;
    unsigned int cutime;
    unsigned int cstime;

    unsigned int priority;
    unsigned int nice;
    unsigned int num_threads;
    unsigned int itrealvalue;
    unsigned long long starttime;
    unsigned long vsize;
    unsigned int rss;

};


#endif //HAANRAD_PROCSTAT_H
