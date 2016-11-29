cmake_minimum_required(VERSION 3.6)
project(haanrad)

set(PROC_DISTORT_FILES test-processdistorter/main.cpp
        ../src/haanrad/ProcessDistorter.h ../src/haanrad/ProcessDistorter.cpp
        ../src/shared/utils/Logger.h ../src/shared/utils/Logger.cpp
        ../src/haanrad/Time.h ../src/haanrad/Time.cpp)
add_executable(test-processdistorter ${PROC_DISTORT_FILES})

set(NETWORK_MONITOR_FILES test-networkmonitor/main.cpp
        ../src/haanrad/networkmonitor/NetworkMonitor.h ../src/haanrad/networkmonitor/NetworkMonitor.cpp
        ../src/shared/utils/Logger.h ../src/shared/utils/Logger.cpp
        ../src/haanrad/TrafficAnalyzer.h ../src/haanrad/TrafficAnalyzer.cpp
        ../src/shared/Authenticator.h ../src/shared/Authenticator.cpp
        ../src/shared/PacketIdentifier.cpp ../src/shared/PacketIdentifier.h
        ../src/shared/HCrypto.cpp ../src/shared/HCrypto.h
        ../src/haanrad/SystemState.cpp ../src/haanrad/SystemState.h
        ../src/shared/proc/ProcDev.h ../src/shared/proc/ProcDev.cpp
        ../src/shared/proc/ProcHelper.h ../src/shared/proc/ProcHelper.cpp
        ../src/shared/proc/ProcStat.h ../src/shared/proc/ProcStat.cpp
        ../src/haanrad/Time.h ../src/haanrad/Time.cpp)
add_executable(test-networkmonitor ${NETWORK_MONITOR_FILES})

set(CRYPTO_FILES
        test-crypto/main.cpp
        ../src/shared/HCrypto.h ../src/shared/HCrypto.cpp
        ../src/shared/PacketIdentifier.h ../src/shared/PacketIdentifier.cpp
        ../src/shared/PacketMeta.h ../src/shared/PacketMeta.cpp
        ../src/shared/utils/Logger.h ../src/shared/utils/Logger.cpp
        ../src/haanrad/SystemState.cpp ../src/haanrad/SystemState.h
        ../src/shared/proc/ProcDev.h ../src/shared/proc/ProcDev.cpp
        ../src/shared/proc/ProcHelper.h ../src/shared/proc/ProcHelper.cpp
        ../src/shared/proc/ProcStat.h ../src/shared/proc/ProcStat.cpp
        ../src/shared/Authenticator.h ../src/shared/Authenticator.cpp)
add_executable(test-crypto ${CRYPTO_FILES})

set(SYSSTATE_FILES
        test-systemstate/main.cpp
        ../src/shared/utils/Logger.h ../src/shared/utils/Logger.cpp
        ../src/haanrad/SystemState.h ../src/haanrad/SystemState.cpp
        ../src/shared/proc/ProcDev.h ../src/shared/proc/ProcDev.cpp
        ../src/shared/proc/ProcHelper.h ../src/shared/proc/ProcHelper.cpp
        ../src/shared/proc/ProcStat.h ../src/shared/proc/ProcStat.cpp
        ../src/haanrad/Time.h ../src/haanrad/Time.cpp)
add_executable(test-systemstate ${SYSSTATE_FILES})
