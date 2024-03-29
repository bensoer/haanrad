//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_CRYPTO_H
#define HAANRAD_CRYPTO_H


#include "PacketMeta.h"
#include <string>
#include <openssl/sha.h>

class HCrypto {

private:
    std::string plainKey;
    unsigned char cypherkey[SHA256_DIGEST_LENGTH];
    unsigned int cryptBufferSize = 1024;

public:

    HCrypto();
    ~HCrypto();

    void initialize(std::string key);

    bool decryptPacket(PacketMeta * meta, char * applicationLayer);
    bool encryptPacket(PacketMeta * meta, char * applicationLayer);

    void setCryptBufferSize(unsigned int buffersize);
};


#endif //HAANRAD_CRYPTO_H
