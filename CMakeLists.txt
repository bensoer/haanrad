cmake_minimum_required(VERSION 3.6)
project(haanrad)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# set the bin folder location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(HAANRAD_FILES src/haanrad/main.cpp)
add_executable(haanrad ${HAANRAD_FILES})

set(CLIENT_FILES src/client/main.cpp)
add_executable(client ${CLIENT_FILES})