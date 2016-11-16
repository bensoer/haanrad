//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_CRYPTO_H
#define HAANRAD_CRYPTO_H


#include "../haanrad/PacketMeta.h"
#include <string>
#include <openssl/sha.h>

class Crypto {

private:
    std::string plainKey;
    unsigned char cypherkey[SHA256_DIGEST_LENGTH];

public:

    Crypto(std::string key);
    ~Crypto();

    void decryptPacket(PacketMeta * meta, char * applicationLayer);
    void encryptPacket(PacketMeta * meta, char * applicationLayer);
};


#endif //HAANRAD_CRYPTO_H
