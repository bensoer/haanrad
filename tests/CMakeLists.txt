cmake_minimum_required(VERSION 3.6)
project(haanrad)

set(PROC_DISTORT_FILES test-processdistorter/main.cpp
        ../src/haanrad/ProcessDistorter.h ../src/haanrad/ProcessDistorter.cpp
        ../src/shared/Logger.h ../src/shared/Logger.cpp)
add_executable(test-processdistorter ${PROC_DISTORT_FILES})

set(NETWORK_MONITOR_FILES test-networkmonitor/main.cpp
        ../src/haanrad/NetworkMonitor.h ../src/haanrad/NetworkMonitor.cpp
        ../src/shared/Logger.h ../src/shared/Logger.cpp)
add_executable(test-networkmonitor ${NETWORK_MONITOR_FILES})
