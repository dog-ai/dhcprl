cmake_minimum_required(VERSION 3.2)
project(dhcprl)

option(COVERALLS "Turn on coveralls support" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
        ${PROJECT_SOURCE_DIR}/cmake/coveralls)

if (COVERALLS)
    include(Coveralls)
    coveralls_turn_on_coverage()
    coveralls_setup("src/" ON "${PROJECT_SOURCE_DIR}/cmake/coveralls")
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        src/dhcprl.c)

add_executable(dhcprl ${SOURCE_FILES})