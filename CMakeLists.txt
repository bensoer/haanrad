cmake_minimum_required(VERSION 3.6)
project(haanrad)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lcrypto -lpcap -lrt -pthread")
# set the bin folder location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(HAANRAD_FILES
        src/haanrad/main.cpp
        src/haanrad/TrafficAnalyzer.cpp src/haanrad/TrafficAnalyzer.h
        src/haanrad/ProcessDistorter.cpp src/haanrad/ProcessDistorter.h
        src/haanrad/networkmonitor/NetworkMonitor.cpp src/haanrad/networkmonitor/NetworkMonitor.h
        src/haanrad/covertsocket/CovertSocket.cpp src/haanrad/covertsocket/CovertSocket.h
        src/haanrad/SystemState.cpp src/haanrad/SystemState.h
        src/haanrad/Time.cpp src/haanrad/Time.h
        src/haanrad/networkmonitor/NetworkMonitorThread.cpp src/haanrad/networkmonitor/NetworkMonitorThread.h
        src/shared/utils/Logger.cpp src/shared/utils/Logger.h
        src/shared/proc/ProcHelper.cpp src/shared/proc/ProcHelper.h
        src/shared/proc/ProcDev.cpp src/shared/proc/ProcDev.h
        src/shared/Authenticator.cpp src/shared/Authenticator.h
        src/shared/PacketMeta.cpp src/shared/PacketMeta.h
        src/shared/utils/Structures.h
        src/shared/PacketIdentifier.cpp src/shared/PacketIdentifier.h
        src/shared/HCrypto.cpp src/shared/HCrypto.h
        src/shared/utils/argparcer.h
        src/haanrad/covertsocket/CovertSocketThread.cpp src/haanrad/covertsocket/CovertSocketThread.h
        src/haanrad/covertsocket/CovertSocketQueue.cpp src/haanrad/covertsocket/CovertSocketQueue.h
        src/haanrad/executor/Executor.cpp src/haanrad/executor/Executor.h
        src/haanrad/executor/ExecutorQueue.cpp src/haanrad/executor/ExecutorQueue.h
        src/haanrad/filesystemmanager/FileSystemManager.cpp src/haanrad/filesystemmanager/FileSystemManager.h
        src/haanrad/filesystemmanager/FileSystemManagerQueue.cpp src/haanrad/filesystemmanager/FileSystemManagerQueue.h
        src/haanrad/filesystemmanager/FileSystemManagerThread.cpp src/haanrad/filesystemmanager/FileSystemManagerThread.h
        src/haanrad/Time.h src/haanrad/Time.cpp)
add_executable(haanrad ${HAANRAD_FILES})

set(CLIENT_FILES
        src/client/main.cpp src/client/CommHandler.cpp
        src/client/CommHandler.h src/client/MessageQueue.cpp
        src/client/MessageQueue.h src/client/Message.cpp
        src/client/Message.h src/shared/utils/Logger.cpp src/shared/utils/Logger.h
        src/shared/proc/ProcHelper.cpp src/shared/proc/ProcHelper.h src/shared/proc/ProcStat.cpp
        src/shared/proc/ProcStat.h src/shared/Authenticator.cpp src/shared/Authenticator.h
        src/shared/HCrypto.cpp src/shared/HCrypto.h
        src/shared/PacketIdentifier.cpp src/shared/PacketIdentifier.h
        src/haanrad/SystemState.cpp src/haanrad/SystemState.h src/client/LocalFileManager.cpp src/client/LocalFileManager.h)
add_executable(client ${CLIENT_FILES})


add_subdirectory(./tests)