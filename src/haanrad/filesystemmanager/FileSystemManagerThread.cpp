//
// Created by root on 25/11/16.
//

#include "FileSystemManagerThread.h"
#include "../../shared/utils/Logger.h"

FileSystemManagerThread::FileSystemManagerThread(FileSystemManager *fileSystemManager, FileSystemManagerQueue *queue) {
    this->fileSystemManager = fileSystemManager;
    this->fileSystemManagerQueue = queue;
}

/**
 * start is the main wrapper method representing the functionality that will be executed in a seperate thread. The start
 * method will hang continualy until the stop method is called. During this time the method continualy loops, polling the
 * FileSystemManagerQueue for new messages. If there is one, the FileSystemManager is then updated with all the new
 * messages, followed by the FileSystemMAnager hanging for file events.
 */
void FileSystemManagerThread::start() {

    while(this->keepRunning){

        Logger::debug("FileSystemThread - Processing New File System Requests");

        //1) Add as many events as you can
        Message message = this->fileSystemManagerQueue->getFileMessage();
        while(message.interMessageCode != InterClientMessageType::EMPTY){

            this->fileSystemManager->updateNotifyEvents(message);

            message = this->fileSystemManagerQueue->getFileMessage();
        }

        Logger::debug("FileSystemThread - Now Hanging For File System Events");
        //2) Then hang on them - this will also process them
        this->fileSystemManager->hangForEvents();
        Logger::debug("FileSystemThread - A Hanging Cycle Has Completed. Looping");

    }

}
/**
 * stop will cause the start method to unhang and terminate the FileSystemManager processing.
 */
void FileSystemManagerThread::stop() {
    this->keepRunning = false;
}