#include <iostream>
#include "MessageQueue.h"
#include "CommHandler.h"
#include "../shared/Logger.h"
#include "../shared/HCrypto.h"


void * listenBootstrapper(void * commHandlerListener){
    CommHandler * listener = (CommHandler *)commHandlerListener;
    listener->listenForMessages();
}

void * sendBootstrapper(void * commHandlerSender){
    CommHandler * sender = (CommHandler *)commHandlerSender;
    sender->processMessagesToSend();
}



int main() {

    Logger::setDebug(true);

    //Create MessageQueue
    MessageQueue * queue = new MessageQueue();
    HCrypto * crypto = new HCrypto();

    //Create CommHandler
    // - Pass MessageQueue
    CommHandler * commHandler = CommHandler::getInstance(queue, crypto);

    commHandler->listenForMessages();

    //Spawn CommHandler on new Thread

    //while

        //wait for message from MessageQueue

        //print out

        //wait for input from user if message requires it (Message Can Be An Object ?)

    return 0;
}