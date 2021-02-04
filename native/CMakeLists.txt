cmake_minimum_required(VERSION 2.8.9)
project(security_wall)

file(GLOB SOURCES "src/*.cpp")

add_executable(testMode ${SOURCES})
add_library(security_wall SHARED ${SOURCES})

target_link_libraries(testMode android log)
target_link_libraries(security_wall android log)

set_property(TARGET testMode PROPERTY CXX_STANDARD 17)
set_property(TARGET security_wall PROPERTY CXX_STANDARD 17)

find_package(tmpfile REQUIRED CONFIG)
target_link_libraries(security_wall tmpfile::tmpfile)
target_link_libraries(testMode tmpfile::tmpfile)
