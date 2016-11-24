//
// Created by root on 23/11/16.
//

#ifndef HAANRAD_EXECUTOR_H
#define HAANRAD_EXECUTOR_H


#include "../../client/Message.h"

class Executor {

private:

    static std::string executeOnConsole(Message message);

public:

    static Message formatCommand(std::string haanradPacket);

    static std::string execute(Message message);
};


#endif //HAANRAD_EXECUTOR_H
