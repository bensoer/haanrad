//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_MESSAGE_H
#define HAANRAD_MESSAGE_H

//Message is a class representing a thing stored in the MessageQueue. It can contain state information which is used
//by the client to determine whether human interaction is necessary or not

#include <string>

struct MessageType{
    enum MessageTypeEnum { DUD = 0x00, CMD = 0x01, FILE = 0x02, CMDANSWER = 0xFE, FILEANSWER = 0xFC,
        FILEDWNLD = 0x03, SPCCMD = 0x04};
};

class Message {

public:
    std::string rawMessage;
    MessageType::MessageTypeEnum messageType;
    std::string data;

};


#endif //HAANRAD_MESSAGE_H
