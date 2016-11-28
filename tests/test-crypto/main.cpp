//
// Created by bensoer on 15/11/16.
//

#include <cstring>
#include <iostream>
#include "../../src/shared/HCrypto.h"
#include "../../src/shared/PacketIdentifier.h"
#include "../../src/shared/utils/Structures.h"
#include "../../src/shared/utils/Logger.h"
#include "../../src/shared/Authenticator.h"
#include <netinet/tcp.h>

using namespace std;

int main(int argc, char * argv[]){


    Logger::setDebug(true);

    Logger::debug("Creating Fake PAcket");
    PacketMeta * meta = new PacketMeta();
    meta->ipType = NetworkType::IPv4;
    meta->transportType = TransportType::TCP;
    meta->applicationType = ApplicationType::TLS;

    string message =  "{HAAN1jdklsajdklsa";

    struct iphdr * ip = (struct iphdr *)meta->packet;
    ip->ihl = 5;
    struct tcphdr * tcp = (struct tcphdr *)(meta->packet + 20); // 20 byte default header ( 4 * 5)
    tcp->doff = 5;
    char * applicationLayer = (meta->packet + 20 + sizeof(tcphdr));
    struct TLS_HEADER * tls = (struct TLS_HEADER *)(meta->packet + 20 + sizeof(tcphdr));

    tls->contentType=23;
    tls->type = 771;
    tls->length = htons(1);

    char * payload = meta->packet + 20 + sizeof(tcphdr) + sizeof(TLS_HEADER);

    memcpy(payload, message.c_str(), message.size());

    Authenticator::setPassword("password");
    Authenticator::addAuthSignature(meta);

    Logger::debug("Creating Crypto Handler");
    HCrypto * crypto = new HCrypto();
    crypto->initialize("password");
    Logger::debug("Now Encrypting");
    crypto->encryptPacket(meta, applicationLayer);
    Logger::debug("Now Decrypting");
    crypto->decryptPacket(meta, applicationLayer);
    Logger::debug("Printing Results");
    cout << ">" << string(payload) << "<" << endl;

    return 0;
}