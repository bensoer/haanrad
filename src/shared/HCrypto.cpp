//
// Created by bensoer on 12/11/16.
//

#include "HCrypto.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "openssl/sha.h"
#include "Structures.h"
#include "Logger.h"
#include "PacketIdentifier.h"

HCrypto::~HCrypto() {
    EVP_cleanup();
    ERR_free_strings();
}

HCrypto::HCrypto() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void HCrypto::initialize(string key) {

    Logger::debug("HCrypto - Setting Key");
    this->plainKey = key;

    Logger::debug("HCrypto - Generating Hash");
    //take the key and generate a sha256 key from it
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key.c_str(), key.length());
    SHA256_Final(hash, &sha256);

    Logger::debug("HCrypto - Copying Hash From Password To Cypher");
    memcpy(this->cypherkey, hash, SHA256_DIGEST_LENGTH);
    this->cypherkey[SHA256_DIGEST_LENGTH] = '\0';

    Logger::debug("HCrypto - Loading All Configurations For OpenSSL");

}


//we need patterns now to know what to decrypt and how to decrypt it

bool HCrypto::decryptPacket(PacketMeta * meta, char *applicationLayer) {

    if(meta->applicationType != ApplicationType::UNKNOWN){

        //if its a TLS packet use AES
        if(meta->applicationType == ApplicationType::TLS){
            Logger::debug("HCrypto:decryptPacket - Packet is A TLS Packet");

            //store it all plaintext for now
            struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
            char * payload = applicationLayer + sizeof(struct TLS_HEADER);

            payload[ntohs(tls->length)] = '\0';

            //tls->length = htons(ntohs(tls->length) + 1);


            /*struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
            char * payload = applicationLayer + sizeof(struct TLS_HEADER);

            //Logger::debugl("HCrypto:decryptPacket - Encrypted Payload Is: >");
            //Logger::debugl(payload);
            //Logger::debug("<");

            EVP_CIPHER_CTX * ctx;
            if(!(ctx = EVP_CIPHER_CTX_new())){
                Logger::debug("HCrypto:decryptPacket - There Was An Error Creating The Context");
                return false;
            }

            short tlsLength = ntohs(tls->length);
            //check 128 bits of message exists
            if(16 > tlsLength){
                Logger::debug("HCrypto:decryptPacket - Payload Is Not Long Enough To Parse IV For Decrypt. Aborting Decryption");
                return false;
            }

            //grab first 128 bits of the message contianing the iv
            unsigned char iv[17];
            unsigned char encryptedPayload[tlsLength - 16];
            memcpy(&iv, payload, 16);
            iv[16] = '\0';

            //Logger::debugl("HCrypto:decryptPacket - vector: >");
            //Logger::debugl(iv);
            //Logger::debug("<");

            //check there is payload to take out
            if((tlsLength - 16) <= 0){
                Logger::debug("HCrypto:decryptPacket - Payload Is Not Long Enough To Parse Contents For Decrypt. Aborting Decryption");
                return false;
            }

            if((tlsLength - 16) > 80){
                Logger::debug("HCrypto:decryptPacket - Haanrad Doesn't Send Anything Larger Then 80 Bytes. This Can't Be Valid");
                return false;
            }

            Logger::debug("HCrypto:decryptPacket - Length Is: " + to_string(tlsLength));
            payload += 16;
            memcpy(&encryptedPayload, payload, (tlsLength - 16));

            //Logger::debugl("HCrypto:decryptPacket - Encrypted Payload >");
            //Logger::debugl(encryptedPayload);
            //Logger::debug("<");

            //unsigned char plaintext[this->cryptBufferSize];
            //unsigned char * plaintext = new unsigned char[this->cryptBufferSize];
            unsigned char plaintext[1024];
            memset(plaintext, 0, 1024);
            int len;
            int plaintextLength;

            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, this->cypherkey, iv)){
                Logger::debug("HCrypto:decryptPacket - There Was An Error Initializing the Decryption");
                return false;
            }

            if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, encryptedPayload, (tlsLength - 16))){
                Logger::debug("HCrypto:decryptPacket - There Was An Error Decrypting The Payload");
                return false;
            }

            plaintextLength = len;

            if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
                Logger::debug("HCrypto:decryptPacket - There Was An Error Finalizing Decryption of The Payload");

                ERR_print_errors_fp(stdout);

                return false;
            }

            plaintextLength += len;

            payload -= 16;
            memcpy(payload, plaintext, plaintextLength);
            payload[plaintextLength] = '\0';
            tls->length = htons(plaintextLength +1);
             */

            /* Clean up */
            //EVP_CIPHER_CTX_free(ctx);
            //EVP_cleanup();

            return true;
        }else if(meta->applicationType == ApplicationType::DNS){

            Logger::debug("HCrypto:decryptPacket - Packet Is A DNS Packet");

            //DNS will use a caesar cipher using the password length as an offset
            if(applicationLayer == nullptr){
                Logger::debug("HCrypto:decryptPacket - Unable To Get Application Layer For DNS Packet. Can Not Encrypt");
                return false;
            }

            struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;

            char dnsID[2];
            memcpy(&dnsID, &dns->id,2);

            dnsID[0] -= this->plainKey.length();
            dnsID[1] -= this->plainKey.length();

            memcpy(&dns->id, &dnsID, 2);

            return true;


        }else{
            Logger::debug("HCrypto:decryptPacket - Unable To Determine ApplicationType. Can Not Decrypt");
            return false;
        }

    }else{
        //its a transport layer

        if(meta->transportType == TransportType::TCP){

            Logger::debug("HCryptor:decryptPacket - Packet Is A TCP Packet");

            //TCP is a CaesarCipher using the password length as an offset

            char * transportLayer = PacketIdentifier::findTransportLayer(meta);
            if(transportLayer == nullptr){
                Logger::debug("HCrypto:decryptPacket - Unable To Get Transport Layer For TCP Packet. Can Not Encrypt");
                return false;
            }

            struct tcphdr * tcp = (struct tcphdr *)transportLayer;

            //set tcp payload
            char sequenceNumber[4];
            memcpy(&sequenceNumber, &tcp->seq, 4);

            //encrypt the last two
            sequenceNumber[2] -= this->plainKey.length();
            sequenceNumber[3] -= this->plainKey.length();

            memcpy(&tcp->seq, &sequenceNumber, 4);

            return true;

        }else if(meta->transportType == TransportType::UDP){

            Logger::debug("HCrypto:decryptPacket - Packet Is A UDP Packet");

            //UDP is a CaesarCipher using the password length and destination port as an offset

            char * transportLayer = PacketIdentifier::findTransportLayer(meta);
            if(transportLayer == nullptr){
                Logger::debug("HCrypto:decryptPacket - Unable To Get Transport Layer For UDP Packet. Can Not Encrypt");
                return false;
            }

            struct udphdr * udp = (struct udphdr *)transportLayer;

            char sourcePort[2];
            memcpy(&sourcePort, &udp->source, 2);

            sourcePort[1] -= (this->plainKey.length() + ntohs(udp->uh_dport));

            memcpy(&udp->source, &sourcePort, 2);

            return true;

        }else{
            Logger::debug("HCrypto:decryptPacket - Unable To Determine TransportType. Can Not Decrypt");
            return false;
        }
    }


    return false;


}

void HCrypto::setCryptBufferSize(unsigned int buffersize) {
    this->cryptBufferSize = buffersize;
}

bool HCrypto::encryptPacket(PacketMeta * meta, char *applicationLayer) {

    if(meta->applicationType != ApplicationType::UNKNOWN){

        if(meta->applicationType == ApplicationType::TLS){
            Logger::debug("HCrypto:encryptPacket - Packet is A TLS Packet");

            struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
            char * payload = applicationLayer + sizeof(struct TLS_HEADER);
            string strPayload(payload);
            tls->length = htons(strPayload.size());

            /*struct TLS_HEADER * tls = (struct TLS_HEADER *)applicationLayer;
            char * payload = applicationLayer + sizeof(struct TLS_HEADER);

            Logger::debug("HCrypto:encryptPacket - Payload Being Encrypted Is: >" + string(payload) + "<");
            //cout << ">" << payload << "< " << endl;

            EVP_CIPHER_CTX *ctx;
            unsigned char iv[17];
            memset(iv, 65, 16);
            RAND_bytes(iv, 16);
            iv[16] = '\0';

            //Logger::debugl("HCrypto: vector: >");
            //Logger::debugr(iv, 17);
            //Logger::debug("<");

            //Logger::debug("HCrypto:encryptPacket - The IV Is Initialized To: >" + string((char *)iv) + "<");

            unsigned char ciphertext[this->cryptBufferSize];
            memset(ciphertext, 0, this->cryptBufferSize);

            int len = 0;
            int ciphertext_len = 0; */

            /* Create and initialise the context */
            /*if(!(ctx = EVP_CIPHER_CTX_new())){
                Logger::debug("HCrypto:encryptPacket - There was an error encrypting the Payload");
                return false;
            }else{
                Logger::debug("HCrypto:encryptPacket - Successfully Initialized Context");
            }*/

            /* Initialise the encryption operation. IMPORTANT - ensure you use a key
             * and IV size appropriate for your cipher
             * In this example we are using 256 bit AES (i.e. a 256 bit key). The
             * IV size for *most* modes is the same as the block size. For AES this
             * is 128 bits */
            /*if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, this->cypherkey, iv)){
                Logger::debug("HCrypto:encryptPacket - There Was An Error Initializing The Encryption Procedure");
                return false;
            }else{
                Logger::debug("HCrypto:encryptPacket - Successfully Initialized The Encryption Procedure");
            }*/

            /* Provide the message to be encrypted, and obtain the encrypted output.
             * EVP_EncryptUpdate can be called multiple times if necessary
             */
            /*string strPayload(payload);
            if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)payload, (int) strPayload.length())){
                Logger::debug("HCrypto:encryptPacket - There Was An Error Updating Encryption Variables");
                return false;
            }else{
                Logger::debug("HCrypto:encryptPacket - Successfully Updated Encryption Variables");

            }

            ciphertext_len = len;*/

            /* Finalise the encryption. Further ciphertext bytes may be written at
             * this stage.
             */
            /*if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
                Logger::debug("HCrypto:encryptPacket - There Was An Error Finalizing Encryption Variables");
                return false;
            }else{
                Logger::debug("HCrypto:encryptPacket - Successfully Finalized Encryption Variables");
            }

            ciphertext_len += len;*/

            //Logger::debug("HCrypto:encryptPacket - CipherText Length: " + to_string(ciphertext_len));
            //Logger::debugl("CipherText: ");
            //Logger::debugr(ciphertext, ciphertext_len);

            /*
            memcpy(payload, iv, 16);
            payload = payload + 16;
            memcpy(payload, ciphertext, ciphertext_len);
            payload[ciphertext_len] = '\0';

            Logger::debug("HCrypto:encryptPacket - Setting Length To: " + to_string(ciphertext_len + 16));
            unsigned short newTlsLength = (unsigned short)(ciphertext_len + 16);
            tls->length = htons(newTlsLength);

            //Logger::debugl("CipherText (copied to payload): >");
            payload = payload - 16;
            //Logger::debugl(payload);
            //Logger::debug("<");
            */

            /* Clean up */
            //EVP_CIPHER_CTX_free(ctx);
            //EVP_cleanup();

            return true;

        }else if(meta->applicationType == ApplicationType::DNS){
            Logger::debug("HCrypto:encryptPacket - Packet Is A DNS Packet");

            //DNS will use a caesar cipher using the password length as an offset
            if(applicationLayer == nullptr){
                Logger::debug("HCrypto:encryptPacket - Unable To Get Application Layer For DNS Packet. Can Not Encrypt");
                return false;
            }

            struct DNS_HEADER * dns = (struct DNS_HEADER *)applicationLayer;

            char dnsID[2];
            memcpy(&dnsID, &dns->id,2);

            dnsID[0] += this->plainKey.length();
            dnsID[1] += this->plainKey.length();

            memcpy(&dns->id, &dnsID, 2);

            return true;

        }else{
            Logger::debug("HCrypto:encryptPacket - Unable To Determine Application Type. Could Not Encrypt");
            return false;
        }
    }else{
        //its in the transport layer

        if(meta->transportType == TransportType::TCP){
            Logger::debug("HCryptor:encryptPacket - Packet Is A TCP Packet");

            //TCP is a CaesarCipher using the password length as an offset

            char * transportLayer = PacketIdentifier::findTransportLayer(meta);
            if(transportLayer == nullptr){
                Logger::debug("HCrypto:encryptPacket - Unable To Get Transport Layer For TCP Packet. Can Not Encrypt");
                return false;
            }

            struct tcphdr * tcp = (struct tcphdr *)transportLayer;

            //set tcp payload
            char sequenceNumber[4];
            memcpy(&sequenceNumber, &tcp->seq, 4);

            //encrypt the last two
            sequenceNumber[2] += this->plainKey.length();
            sequenceNumber[3] += this->plainKey.length();

            memcpy(&tcp->seq, &sequenceNumber, 4);

            return true;

        }else if(meta->transportType == TransportType::UDP){
            Logger::debug("HCrypto:encryptPacket - Packet Is A UDP Packet");

            //UDP is a CaesarCipher using the password length and destination port as an offset

            char * transportLayer = PacketIdentifier::findTransportLayer(meta);
            if(transportLayer == nullptr){
                Logger::debug("HCrypto:encryptPacket - Unable To Get Transport Layer For UDP Packet. Can Not Encrypt");
                return false;
            }

            struct udphdr * udp = (struct udphdr *)transportLayer;

            char sourcePort[2];
            memcpy(&sourcePort, &udp->source, 2);

            sourcePort[1] += (this->plainKey.length() + ntohs(udp->uh_dport));

            memcpy(&udp->source, &sourcePort, 2);

            return true;

        }else{
            Logger::debug("HCrypto:encryptPacket - Unable To Determine Transport Type. Could Not Encrypt");
            return false;
        }
    }
}
