//
// Created by root on 26/11/16.
//

#include <iostream>
#include <dirent.h>
#include <sys/stat.h>
#include <fstream>
#include "LocalFileManager.h"
#include "../shared/utils/Logger.h"

LocalFileManager::LocalFileManager(std::string syncRootDir) {
    this->syncRootDir = syncRootDir;
}

/**
 * buildOutDirectory builds out the directory passed as a parameter to the function. It will create the local sync folder
 * and then parse the passed in directory and check for missing folders in the structure. The passed in directory is
 * assumed to end with the last directory before the files that may be stored in it
 * @param haanradDir String - the directory that needs to be created under the sync folder
 */
void LocalFileManager::buildOutDirectory(std::string haanradDir) {

    unsigned long index = haanradDir.find_last_of('/');
    if(index == std::string::npos){
        Logger::debug("LocalFileManager::buildOutDirectory - Could Not Find Slash. Can't Sync Localy");
        //cout << "Local Sync Is A Problem" << endl;
    }

    std::string directory = haanradDir.substr(0, index);

    std::string fullDir = this->syncRootDir + "/" + directory;

    struct stat st;
    if(stat(fullDir.c_str(),&st) == 0){
        if(st.st_mode & S_IFDIR != 0){
            //directory already exists
            return;
        }
    }

    //can assume that the directory does not exist

    int offsetValue = 0;
    string fullDirCopy = fullDir;
    while((index = fullDirCopy.find('/')) != std::string::npos){

        string folderName = fullDirCopy.substr(0, index);
        if(folderName.compare(".") == 0 || folderName.compare("..") == 0){
            //this must be the first one. skip it
            offsetValue += (index + 1);
            fullDirCopy = fullDirCopy.substr(index + 1);
        }else{

            //folderName should be the path up to the folder we are creating
            string pathUpToCurrentSlash = fullDir.substr(0, (offsetValue + index));

            cout << "Making Directory: " << pathUpToCurrentSlash << endl;
            mkdir(pathUpToCurrentSlash.c_str(), 0777);

            fullDirCopy = fullDirCopy.substr(index + 1);
            offsetValue += (index + 1);
        }

    }

    if(fullDirCopy.length() > 0){
        //make the last part folder
        mkdir(fullDir.c_str(), 0777);
    }
}

/**
 * syncFile creates and writes the raw data contents to the specific haanradDir under the sync folder directory
 * @param haanradDir String - the directory and filename to be synced to file
 * @param rawData String - the raw data as a string to be written to the file in the haanradDir
 */
void LocalFileManager::syncFile(std::string haanradDir, string rawData) {

    unsigned long index = haanradDir.find_last_of('/');
    if(index == std::string::npos){
        Logger::debug("LocalFileManager::buildOutDirectory - Could Not Find Slash. Can't Sync Localy");
        cout << "Local Sync Is A Problem 2" << endl;
    }

    std::string directory = haanradDir.substr(0, index);
    std::string fileName = haanradDir.substr(index + 1);
    std::string fullDir = this->syncRootDir + "/" + directory + "/" + fileName;

    ofstream writer(fullDir.c_str(), ios::out| ios::binary);
    //writer.open(fullDir.c_str(), ios::out | ios::binary);
    writer.write(rawData.c_str(), rawData.length());
    writer.close();

}