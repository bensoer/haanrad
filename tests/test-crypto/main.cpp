//
// Created by bensoer on 15/11/16.
//

#include <cstring>
#include <iostream>
#include "../../src/shared/HCrypto.h"
#include "../../src/shared/PacketIdentifier.h"
#include "../../src/shared/Structures.h"
#include "../../src/shared/Logger.h"

using namespace std;

int main(int argc, char * argv[]){


    Logger::setDebug(true);

    Logger::debug("Creating Fake PAcket");
    PacketMeta * meta = new PacketMeta();
    meta->ipType = NetworkType::IPv4;
    meta->transportType = TransportType::TCP;
    meta->applicationType = ApplicationType::TLS;

    meta->packet;
    char * applicationLayer = meta->packet;

    unsigned char message[] =  "A completely different but substantialy longer encrypted string. \tn. this might have issues\0";


    struct TLS_HEADER * tls = (struct TLS_HEADER * )applicationLayer;
    tls->contentType=23;
    tls->type = 771;
    tls->length = sizeof(message);

    char * ptr = applicationLayer + sizeof(struct TLS_HEADER);

    memcpy(ptr, message, sizeof(message));

    Logger::debug("Creating Crypto Handler");
    HCrypto * crypto = new HCrypto("password");
    Logger::debug("Now Encrypting");
    crypto->encryptPacket(meta, applicationLayer);
    Logger::debug("Now Decrypting");
    crypto->decryptPacket(meta, applicationLayer);
    Logger::debug("Printing Results");
    cout << ">" << string(ptr) << "<" << endl;

    return 0;
}