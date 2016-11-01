cmake_minimum_required(VERSION 3.6)
project(haanrad)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# set the bin folder location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(HAANRAD_FILES src/haanrad/main.cpp src/haanrad/TrafficAnalyzer.cpp src/haanrad/TrafficAnalyzer.h src/haanrad/ProcessDistorter.cpp src/haanrad/ProcessDistorter.h src/haanrad/NetworkMonitor.cpp src/haanrad/NetworkMonitor.h src/haanrad/CovertSocket.cpp src/haanrad/CovertSocket.h src/haanrad/SystemState.cpp src/haanrad/SystemState.h src/haanrad/Time.cpp src/haanrad/Time.h src/haanrad/NetworkMonitorThread.cpp src/haanrad/NetworkMonitorThread.h)
add_executable(haanrad ${HAANRAD_FILES})

set(CLIENT_FILES src/client/main.cpp)
add_executable(client ${CLIENT_FILES})