//
// Created by bensoer on 06/11/16.
//

#include <fstream>
#include <dirent.h>
#include "ProcHelper.h"
#include "Logger.h"

vector<ProcDev *> * ProcHelper::getAllNetworkInterfaceStats() {

    string fullPath = "/proc/net/dev";
    int BUFFSIZE = 255;
    char BUFFER[BUFFSIZE];
    char *datastart;
    vector<ProcDev *> * interfaceList = new vector<ProcDev *>();

    FILE * file;
    file = fopen(fullPath.c_str(), "-");
    if(file != nullptr){

        fgets(BUFFER,BUFFSIZE, file); //ignore the first line since its just header titles

        while(fgets(BUFFER, BUFFSIZE, file)){

            ProcDev * interface = new ProcDev();
            sscanf(BUFFER, "%s       %llu  %d     %d  %d  %d  %d   %d        %d       %llu",
            interface->interface, interface->receivedBytes, interface->receivedPackets, NULL, NULL, NULL, NULL,NULL,
            interface->sentBytes, interface->sentPackets);

            interfaceList->push_back(interface);
        }

        fclose(file);

        return interfaceList;

    }else{
        return nullptr;
    }

}


ProcStat * ProcHelper::parseProcessStatInformation(int pid) {

    FILE * file;
    string fullPath = "/proc/" + to_string(pid) + "/stat";

    ProcStat * stats = new ProcStat();
    file = fopen(fullPath.c_str(), "r");
    if(file != nullptr){

        fscanf(file, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld",
        stats->pid, stats->comm, stats->state, stats->ppid, stats->pgrp, stats->session, stats->tty_nr, stats->tpgid,
        stats->flags, stats->minflt, stats->cminflt, stats->majflt, stats->cmajflt, stats->utime, stats->stime,
        stats->cutime, stats->cstime, stats->priority, stats->nice, stats->num_threads, stats->itrealvalue, stats->starttime,
        stats->vsize, stats->rss);
    }

    fclose(file);
    return stats;

}

vector<int> * ProcHelper::getAllProcessIDs() {

    vector<int> * processIDs = new vector<int>();

    DIR *dp;
    struct dirent *dirp;
    if((dp = opendir("/proc")) == NULL){
        Logger::debug("Failed To Open Proc Folder. Can't Get Stats");
        return nullptr;
    }

    while((dirp = readdir(dp)) != NULL){
        if(dirp->d_type == DT_DIR){

            string dir(dirp->d_name);
            int processID;
            if(sscanf(dirp->d_name,"%d", processID) > 0){
                processIDs->push_back(processID);
            };
        }
    }

    return processIDs;
}