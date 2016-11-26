//
// Created by root on 23/11/16.
//

#ifndef HAANRAD_EXECUTOR_H
#define HAANRAD_EXECUTOR_H


#include "../../client/Message.h"
#include "../filesystemmanager/FileSystemManagerQueue.h"

class Executor {

private:

    std::string executeOnConsole(Message message);

    FileSystemManagerQueue * fileSystemManagerQueue;

public:

    Executor(FileSystemManagerQueue * fileSystemManagerQueue);

    static Message formatCommand(std::string haanradPacket);

    std::string execute(Message message);
};


#endif //HAANRAD_EXECUTOR_H
