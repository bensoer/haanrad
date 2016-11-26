//
// Created by root on 25/11/16.
//

#include "FileSystemManagerThread.h"
#include "../../shared/Logger.h"

FileSystemManagerThread::FileSystemManagerThread(FileSystemManager *fileSystemManager, FileSystemManagerQueue *queue) {
    this->fileSystemManager = fileSystemManager;
    this->fileSystemManagerQueue = queue;
}

void FileSystemManagerThread::start() {

    while(this->keepRunning){

        Logger::debug("FileSystemThread - Processing New File System Requests");
        //1) Add as many events as you can
        while(this->fileSystemManagerQueue->getFileMessage().interMessageCode != InterClientMessageType::EMPTY){

            Message message = this->fileSystemManagerQueue->getFileMessage();

            this->fileSystemManager->updateNotifyEvents(message);

        }

        Logger::debug("FileSystemThread - Now Hanging For File System Events");
        //2) Then hang on them - this will also process them
        this->fileSystemManager->hangForEvents();
        Logger::debug("FileSystemThread - A Hanging Cycle Has Completed. Looping");

    }

}

void FileSystemManagerThread::stop() {
    this->keepRunning = false;
}