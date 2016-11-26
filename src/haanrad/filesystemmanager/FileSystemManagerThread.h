//
// Created by root on 25/11/16.
//

#ifndef HAANRAD_FILESYSTEMMANAGERTHREAD_H
#define HAANRAD_FILESYSTEMMANAGERTHREAD_H


#include "FileSystemManagerQueue.h"
#include "FileSystemManager.h"

class FileSystemManagerThread {

private:

    bool keepRunning = true;

    FileSystemManager * fileSystemManager = nullptr;
    FileSystemManagerQueue * fileSystemManagerQueue = nullptr;

public:
    FileSystemManagerThread(FileSystemManager * fileSystemManager, FileSystemManagerQueue * queue);

    void start();
    void stop();
};


#endif //HAANRAD_FILESYSTEMMANAGERTHREAD_H
