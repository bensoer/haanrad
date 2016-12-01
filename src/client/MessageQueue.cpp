//
// Created by bensoer on 31/10/16.
//

#include "MessageQueue.h"

/**
 * sendToHaanrad adds the passed in Message object to the client2Haanrad queue using thread safe locking mechanisms
 * @param message Message - the Message object representing the HAAN packet to be sent to Haanrad
 */
void MessageQueue::sendToHaanrad(Message message) {
    messageLock.lock();
    client2Haanrad.push(message);
    messageLock.unlock();

}

/**
 * recvFromHaanrad polls the haanrad2Client queue using thread safe locking mechanisms to try and fetch any new results
 * from Haanrad. On failure the method returns an INTERCLIENT message of type EMPTY
 * @return Message - A message object representing a response from Haanrad or an EMPTY message if there are none
 */
Message MessageQueue::recvFromHaanrad() {
    messageLock.lock();

    if(haanrad2Client.empty()){


        Message message;
        message.messageType = MessageType::INTERCLIENT;
        message.interMessageCode = InterClientMessageType::EMPTY;
        //message.rawCommandMessage = "";
        //message.data = "";
        messageLock.unlock();
        return message;
    }else{
        Message message = haanrad2Client.front();
        haanrad2Client.pop();
        messageLock.unlock();
        return message;
    }


}

/**
 * addMessageResponse is a method used by the CommHAndler to add messages to be accessed by the console
 * @param message Message - a message object representing a response from Haanrad
 */
void MessageQueue::addMessageResponse(Message message) {
    messageLock.lock();
    haanrad2Client.push(message);
    messageLock.unlock();
}

/**
 * getMessageToSent is a method used by CommHAndler to fetch new commands for Haanrad. The method polls the client2Haanrad
 * queue using thread safe methods and returns a new Message or an INTERCLIENT message of type EMPTY if the queue is empty
 * @return Message - a message object representing a new command for Haanrad or an EMPTY Message
 */
Message MessageQueue::getMessageToSend() {
    messageLock.lock();

    if(client2Haanrad.empty()){
        Message message;
        message.messageType = MessageType::INTERCLIENT;
        message.interMessageCode = InterClientMessageType::EMPTY;

        messageLock.unlock();
        return message;
    }

    Message message = client2Haanrad.front();
    client2Haanrad.pop();
    messageLock.unlock();
    return message;
}