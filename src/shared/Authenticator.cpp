//
// Created by bensoer on 12/11/16.
//

#include "Authenticator.h"

string Authenticator::password;

bool Authenticator::isAuthenticPacket(char *packet) {

    //parameter should be a pointer to the payload of our message ?
    //what if content is in the header though ?

    //we need to know the structure of our packet now to determine if it is ours

    return false;

}

void Authenticator::addAuthSignature(char *packet) {

    //parameter should be a pointer to the payload of our message ?

}

void Authenticator::setPassword(string password) {
    Authenticator::password = password;
}