//
// Created by bensoer on 06/11/16.
//

#include <fstream>
#include <dirent.h>
#include <cstring>
#include "ProcHelper.h"
#include "Logger.h"

vector<ProcDev> * ProcHelper::getAllNetworkInterfaceStats() {

    string fullPath = "/proc/net/dev";
    int BUFFSIZE = 255;
    char BUFFER[BUFFSIZE];
    char *datastart;
    vector<ProcDev> * interfaceList = new vector<ProcDev>();

    FILE * file;
    file = fopen(fullPath.c_str(), "r");
    if(file != nullptr){

        fgets(BUFFER,BUFFSIZE, file); //ignore the first line since its just header titles
        fgets(BUFFER,BUFFSIZE, file); //ignore the first line since its just header titles

        while(fgets(BUFFER, BUFFSIZE, file)){

            //printf("Line: %s\n", BUFFER);

            int garbage;
            ProcDev interface;

            string strBUFFER(BUFFER);
            size_t colon = strBUFFER.find(':');
            interface.interface = strBUFFER.substr(0, colon);
            char * ptr = BUFFER + colon + 1;

            sscanf(ptr, "%llu %d %d %d %d %d %d %d %d %llu",
                   &interface.receivedBytes,
                   &interface.receivedPackets,
                   &garbage,
                   &garbage,
                   &garbage,
                   &garbage,
                   &garbage,
                   &garbage,
                   &interface.sentBytes,
                   &interface.sentPackets);

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

        char comm[1024];
        memset(comm, '\0', 1024);

        int BUFFERSIZE = 1024;
        char BUFFER[BUFFERSIZE];

        fgets(BUFFER, BUFFERSIZE, file);
        string strBUFFER(BUFFER);

        size_t firstSpace = strBUFFER.find(' ');
        size_t secondSpace = strBUFFER.find(' ', firstSpace + 1);
        size_t thirdSpace = strBUFFER.find(' ', secondSpace + 1);

        string pid = strBUFFER.substr(0, firstSpace);
        string name = strBUFFER.substr(firstSpace+1, (secondSpace - firstSpace) - 1);
        string state = strBUFFER.substr(secondSpace+1, (thirdSpace - secondSpace) - 1);

        stats->pid = stoi(pid);
        stats->comm = name;
        stats->state = state.at(0);

        //printf("PID: %s", pid);
        //printf("NAME: %s", name);
        //printf("STATE: %s", state);

        char * ptr = BUFFER + thirdSpace;
        sscanf(ptr,"%d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld",
               &stats->ppid,
               &stats->pgrp,
               &stats->session,
               &stats->tty_nr,
               &stats->tpgid,
               &stats->flags,
               &stats->minflt,
               &stats->cminflt,
               &stats->majflt,
               &stats->cmajflt,
               &stats->utime,
               &stats->stime,
               &stats->cutime,
               &stats->cstime,
               &stats->priority,
               &stats->nice,
               &stats->num_threads,
               &stats->itrealvalue,
               &stats->starttime,
               &stats->vsize,
               &stats->rss);

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
            if(sscanf(dirp->d_name,"%d", &processID) > 0){
                processIDs->push_back(processID);
            };
        }
    }

    return processIDs;
}