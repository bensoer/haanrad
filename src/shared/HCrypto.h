//
// Created by bensoer on 12/11/16.
//

#ifndef HAANRAD_CRYPTO_H
#define HAANRAD_CRYPTO_H


#include "../haanrad/PacketMeta.h"
#include <string>
#include <openssl/sha.h>

class HCrypto {

private:
    std::string plainKey;
    unsigned char cypherkey[SHA256_DIGEST_LENGTH];
    int cryptBufferSize = 1024;

public:

    HCrypto(std::string key);
    ~HCrypto();

    bool decryptPacket(PacketMeta * meta, char * applicationLayer);
    bool encryptPacket(PacketMeta * meta, char * applicationLayer);

    void setCryptBufferSize(int buffersize);
};


#endif //HAANRAD_CRYPTO_H
