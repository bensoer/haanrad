//
// Created by bensoer on 04/11/16.
//

#ifndef HAANRAD_LOGGER_H
#define HAANRAD_LOGGER_H

#include<string>

using namespace std;

class Logger {


private:
    static bool isDebug;

public:

    static void setDebug(bool state);

    static void print(string message);
    static void println(string message);

    static void error(string message);
    static void debug(string message);

    static void debugl(string message);
    static void debugl(unsigned char * message);
    static void debug(unsigned char * message);

    static void debugr(unsigned char * message, int length);

    static void hexDebug(unsigned char content);
    static void hexDebug(unsigned short content);

};


#endif //HAANRAD_LOGGER_H
