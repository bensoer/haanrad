//
// Created by bensoer on 12/11/16.
//

#include "Crypto.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include "openssl/sha.h"
#include "Structures.h"
#include "Logger.h"

Crypto::~Crypto() {
    EVP_cleanup();
    ERR_free_strings();
}

Crypto::Crypto(std::string key) {
    Logger::debug("Crypto - Setting Key");
    this->plainKey = key;

    Logger::debug("Crypto - Generating Hash");
    //take the key and generate a sha256 key from it
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key.c_str(), key.length());
    SHA256_Final(hash, &sha256);

    Logger::debug("Crypto - Copying Hash From Password To Cypher");
    memcpy(this->cypherkey, hash, SHA256_DIGEST_LENGTH);
    this->cypherkey[SHA256_DIGEST_LENGTH] = '\0';

    Logger::debug("Crypto - Loading All Configurations For OpenSSL");
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

}


//we need patterns now to know what to decrypt and how to decrypt it

void Crypto::decryptPacket(PacketMeta * meta, char *applicationLayer) {

    //if its a TLS packet use AES
    if(meta->applicationType == ApplicationType::TLS){
        Logger::debug("Crypto:decryptPacket - Packet is A TLS Packet");

        struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
        char * payload = applicationLayer + sizeof(struct TLS_HEADER);

        Logger::debugl("Crypto:decryptPacket - Encrypted Payload Is: >");
        Logger::debugl(payload);
        Logger::debug("<");

        EVP_CIPHER_CTX * ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())){
            Logger::debug("Crypto:decryptPacket - There Was An Error Creating The Context");
            return;
        }

        //grab first 128 bits of the message contianing the iv
        unsigned char iv[17];
        unsigned char encryptedPayload[tls->length - 16];
        memcpy(&iv, payload, 16);
        iv[17] = '\0';

        Logger::debugl("Crypto:decryptPacket - vector: >");
        Logger::debugl(iv);
        Logger::debug("<");


        Logger::debug("Crypto:encryptPacket - Length Is: " + to_string(tls->length));
        payload += 16;
        memcpy(&encryptedPayload, payload, (tls->length - 16));

        Logger::debugl("Crypto:decryptPacket - Encrypted Payload >");
        Logger::debugl(encryptedPayload);
        Logger::debug("<");

        unsigned char plaintext[1024];
        memset(plaintext, 0, 1024);
        int len;
        int plaintextLength;

        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, this->cypherkey, iv)){
            Logger::debug("Crypto:decryptPacket - There Was An Error Initializing the Decryption");
        }

        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, encryptedPayload, (tls->length - 16))){
            Logger::debug("Crypto:decryptPacket - There Was An Error Decrypting The Payload");
        }

        plaintextLength = len;

        if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
            Logger::debug("Crypto:decryptPacket - There Was An Error Finalizing Decryption of The Payload");
        }

        plaintextLength += len;

        payload -= 16;
        memcpy(payload, plaintext, plaintextLength);
        payload[plaintextLength] = '\0';
        tls->length = (plaintextLength +1);

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);



        return;
    }


}

void Crypto::encryptPacket(PacketMeta * meta, char *applicationLayer) {

    if(meta->applicationType == ApplicationType::TLS){
        Logger::debug("Crypto:encryptPacket - Packet is A TLS Packet");

        struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
        char * payload = applicationLayer + sizeof(struct TLS_HEADER);

        Logger::debug("Crypto:encryptPacket - Payload Being Encrypted Is: >" + string(payload) + "<");
        //cout << ">" << payload << "< " << endl;

        EVP_CIPHER_CTX *ctx;
        unsigned char iv[17];
        memset(iv, 65, 16);
        RAND_bytes(iv, 16);
        iv[16] = '\0';

        Logger::debugl("Crypto: vector: >");
        Logger::debugr(iv, 17);
        Logger::debug("<");

        //Logger::debug("Crypto:encryptPacket - The IV Is Initialized To: >" + string((char *)iv) + "<");

        unsigned char ciphertext[1024];
        memset(ciphertext, 0, 1024);

        int len;
        int ciphertext_len = 0;

        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new())){
            Logger::debug("Crypto:encryptPacket - There was an error encrypting the Payload");
            return;
        }else{
            Logger::debug("Crypto:encryptPacket - Successfully Initialized Context");
        }

        /* Initialise the encryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits */
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, this->cypherkey, iv)){
            Logger::debug("Crypto:encryptPacket - There Was An Error Initializing The Encryption Procedure");
            return;
        }else{
            Logger::debug("Crypto:encryptPacket - Successfully Initialized The Encryption Procedure");
        }

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)payload, (int) strlen(payload))){
            Logger::debug("Crypto:encryptPacket - There Was An Error Updating Encryption Variables");
            return;
        }else{
            Logger::debug("Crypto:encryptPacket - Successfully Updated Encryption Variables");

        }

        ciphertext_len = len;

        /* Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
            Logger::debug("Crypto:encryptPacket - There Was An Error Finalizing Encryption Variables");
            return;
        }else{
            Logger::debug("Crypto:encryptPacket - Successfully Finalized Encryption Variables");
        }

        ciphertext_len += len;

        Logger::debug("Crypto:encryptPacket - CipherText Length: " + to_string(ciphertext_len));
        Logger::debugl("CipherText: ");
        Logger::debugr(ciphertext, ciphertext_len);

        memcpy(payload, iv, 16);
        payload = payload + 16;
        memcpy(payload, ciphertext, ciphertext_len);
        payload[ciphertext_len] = '\0';

        Logger::debug("Crypto:encryptPacket - Setting Length To: " + to_string(ciphertext_len + 16));
        tls->length = (ciphertext_len + 16);

        Logger::debugl("CipherText (copied to payload): >");
        payload = payload - 16;
        Logger::debugl(payload);
        Logger::debug("<");


        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return;

    }



}
