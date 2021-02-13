cmake_minimum_required(VERSION 2.8.9)
project(security_wall)

file(GLOB SOURCES "src/*.cpp")

#add_definitions(-DDEBUG)
add_library(security_wall SHARED ${SOURCES})
target_link_libraries(security_wall android log)
set_property(TARGET security_wall PROPERTY CXX_STANDARD 17)
find_package(tmpfile REQUIRED CONFIG)
target_link_libraries(security_wall tmpfile::tmpfile)
