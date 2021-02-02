cmake_minimum_required(VERSION 2.8.9)
project(security_wall)

#Can manually add the sources using the set command as follows:
#set(SOURCES src/mainapp.cpp src/Student.cpp)

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.cpp")

add_executable(testMode ${SOURCES})
add_library(security_wall SHARED ${SOURCES})

set_property(TARGET testMode PROPERTY CXX_STANDARD 20)
set_property(TARGET security_wall PROPERTY CXX_STANDARD 20)
