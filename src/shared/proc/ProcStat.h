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

    int flags;
    long minflt;
    long cminflt;
    long majflt;
    long cmajflt;

    long utime;
    long stime;
    long cutime;
    long cstime;

    long priority;
    long nice;
    long num_threads;
    long itrealvalue;
    long long starttime;
    long vsize;
    long rss;

};


#endif //HAANRAD_PROCSTAT_H
