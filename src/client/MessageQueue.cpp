//
// Created by bensoer on 31/10/16.
//

#include "MessageQueue.h"

void MessageQueue::sendToHaanrad(Message message) {
    messageLock.lock();
    client2Haanrad.push(message);
    messageLock.unlock();

}

Message MessageQueue::recvFromHaanrad() {
    messageLock.lock();

    if(haanrad2Client.empty()){
        messageLock.unlock();

        Message message;
        message.messageType = MessageType::INTERCLIENT;
        message.interMessageCode = InterClientMessageType::EMPTY;
        //message.rawCommandMessage = "";
        //message.data = "";

        return message;
    }else{
        Message message = haanrad2Client.front();
        haanrad2Client.pop();
        messageLock.unlock();
        return message;
    }


}

void MessageQueue::addMessageResponse(Message message) {
    messageLock.lock();
    haanrad2Client.push(message);
    messageLock.unlock();
}

Message MessageQueue::getMessageToSend() {
    messageLock.lock();
    Message message = client2Haanrad.front();
    client2Haanrad.pop();
    messageLock.unlock();
    return message;
}