//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_AUTHENTICATOR_H
#define HAANRAD_AUTHENTICATOR_H

#include <string>

using namespace std;

class Authenticator {

private:
    static string password;

public:
    static bool isAuthenticPacket(char * packet);

    static void addAuthSignature(char * packet);

    static void setPassword(string password);
};


#endif //HAANRAD_AUTHENTICATOR_H
