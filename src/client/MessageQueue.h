//
// Created by bensoer on 31/10/16.
//

#ifndef HAANRAD_MESSAGEQUEUE_H
#define HAANRAD_MESSAGEQUEUE_H


#include "Message.h"
#include <queue>
#include <mutex>

class MessageQueue {


private:

    std::mutex messageLock;

    std::queue<Message> client2Haanrad;
    std::queue<Message> haanrad2Client;
public:


    //Used By Main
    void sendToHaanrad(Message message);
    Message recvFromHaanrad();


    //Used By CommHandler
    Message getMessageToSend();

    void addMessageResponse(Message message);
};


#endif //HAANRAD_MESSAGEQUEUE_H
