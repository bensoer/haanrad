//
// Created by bensoer on 04/11/16.
//

#include "Logger.h"
#include <iostream>


/**
 * statuc variable that enables and disables debug logging
 */
bool Logger::isDebug = false;

/**
 * debug writes the passed in message to console using Logger::println as long as debug mode is enabled
 * @param message String - the message to be printed
 */
void Logger::debug(string message) {
    if(Logger::isDebug){
        Logger::println(message);
    }
}

/**
 * debugl writes the passed in message to console if debug mode is enabled but does not include a return at the end
 * @param message Unsigned Char * - the message to be printed
 */
void Logger::debugl(unsigned char *message) {
    if(Logger::isDebug){
        cout << message;
    }
}

/**
 * hexDebug writes the passed in message to console if debug mode is enabled as hex dump data. A return at the end
 * is not included in the print
 * @param content Unsigned Char - The message to be printed
 */
void Logger::hexDebug(unsigned char content) {
    if(Logger::isDebug){
        printf("%08x : %d", content, content);
    }
}

/**
 * hexDebug writes the passed in message to console if debug mode is enabled as hex dump data. A return at the end
 * is not included in the print
 * @param content Unsigned Short - The short value to be printed
 */
void Logger::hexDebug(unsigned short content) {
    if(Logger::isDebug){
        printf("%08x : %d", content, content);
    }
}


/**
 * debugr is a brute force printer that primts the length value of bytes from the passed in message char. This ensures
 * even null terminators or data after the null terminator are printed
 * @param message Unsigned Char - The message being printed
 * @param length Int - The length of the message / the amount of bytes to print out from the message
 */
void Logger::debugr(unsigned char *message, int length) {
    if(Logger::isDebug){
        printf(">");
        for(int i = 0; i < length; i++){
            printf("%c", message[i]);
        }
        printf("<\n");
        for(int i = 0; i < length; i++){
            printf("%d:%c(%d) | ", i,message[i], message[i]);
        }
        printf("\n");
    }
}

/**
 * debug prints the passed in message to console if debug mode is enabled and appends the return character at the end
 * @param message Const Char * - The message to be printed
 */
void Logger::debug(unsigned char *message) {
    if(Logger::isDebug){
        cout << message << endl;
    }
}

/**
 * debugl prints the passed in message to console using Logger::print if debug mode is enabled
 * @param message String - the message to be printed
 */
void Logger::debugl(string message) {
    if(Logger::isDebug){
        Logger::print(message);
    }
}

/**
 * println is a helper method that prints the passed in message to stdout and appends a return character at the end
 * @param message String - the message to be printed
 */
void Logger::println(string message) {
    cout << message << endl;
}

/**
 * print is a helper method that prints the passed in message to stdout
 * @param message String - the message to be printed
 */
void Logger::print(string message) {
    cout << message;
}

/**
 * error is a helper method that prints the passed in message to stderr
 * @param message String - the message to be printed
 */
void Logger::error(string message) {
    cerr << message << endl;
}

/**
 * setDebug is a helper method that sets the state for the logger as to whether it is in debug mode or not
 * @param state Boolean - state as to whether the Logger can print debug messages or not. True = debug messages are printed
 */
void Logger::setDebug(bool state) {
    Logger::isDebug = state;
}