//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_AUTHENTICATOR_H
#define HAANRAD_AUTHENTICATOR_H


class Authenticator {

public:
    static bool isAuthenticPacket(char * packet);

    static void addAuthSignature(char * packet);
};


#endif //HAANRAD_AUTHENTICATOR_H
