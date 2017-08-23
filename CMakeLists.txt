cmake_minimum_required(VERSION 3.2)
project(dhcprl)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")

set(SOURCE_FILES
        src/dhcprld.c include/dhcprld.h
        src/dhcp.c src/dhcp.h
        src/unix.c src/unix.h)
add_executable(dhcprld ${SOURCE_FILES})

enable_testing()
add_executable(test_dhcprl ${PROJECT_SOURCE_DIR}/test/test_dhcprl.c)
add_test(test_dhcprl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_dhcprl)

option(COVERALLS "Turn on coveralls support" OFF)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
        ${PROJECT_SOURCE_DIR}/cmake/coveralls)
if (COVERALLS)
    include(Coveralls)
    coveralls_turn_on_coverage()
    coveralls_setup("src/" ON "${PROJECT_SOURCE_DIR}/cmake/coveralls")
endif ()