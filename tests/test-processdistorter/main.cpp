//
// Created by bensoer on 12/11/16.
//

#include <iostream>
#include <zconf.h>
#include "../../src/haanrad/ProcessDistorter.h"
#include "../../src/shared/utils/Logger.h"

using namespace std;

int main(int argc, char * argv[]){


    Logger::setDebug(true);
    Logger::debug("Starting Up");

    ProcessDistorter * pd = new ProcessDistorter(argv, false, true);
    pd->determineProcessName();

    Logger::debug("Now Looping");
    while(1){
        usleep(40 * 1000000); // 40 seconds

        Logger::debug("Renaming");
        pd->determineProcessName();
        Logger::debug("Rename Complete");
    }

    return 0;
}