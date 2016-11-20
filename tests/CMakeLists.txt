cmake_minimum_required(VERSION 3.6)
project(haanrad)

set(PROC_DISTORT_FILES test-processdistorter/main.cpp
        ../src/haanrad/ProcessDistorter.h ../src/haanrad/ProcessDistorter.cpp
        ../src/shared/Logger.h ../src/shared/Logger.cpp)
add_executable(test-processdistorter ${PROC_DISTORT_FILES})

set(NETWORK_MONITOR_FILES test-networkmonitor/main.cpp
        ../src/haanrad/NetworkMonitor.h ../src/haanrad/NetworkMonitor.cpp
        ../src/shared/Logger.h ../src/shared/Logger.cpp
        ../src/haanrad/TrafficAnalyzer.h ../src/haanrad/TrafficAnalyzer.cpp
        ../src/shared/Authenticator.h ../src/shared/Authenticator.cpp
        ../src/shared/PacketIdentifier.cpp ../src/shared/PacketIdentifier.h
        ../src/shared/HCrypto.cpp ../src/shared/HCrypto.h)
add_executable(test-networkmonitor ${NETWORK_MONITOR_FILES})

set(CRYPTO_FILES
        test-crypto/main.cpp
        ../src/shared/HCrypto.h ../src/shared/HCrypto.cpp
        ../src/shared/PacketIdentifier.h ../src/shared/PacketIdentifier.cpp
        ../src/haanrad/PacketMeta.h ../src/haanrad/PacketMeta.cpp
        ../src/shared/Logger.h ../src/shared/Logger.cpp)
add_executable(test-crypto ${CRYPTO_FILES})
