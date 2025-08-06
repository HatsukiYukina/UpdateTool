cmake_minimum_required(VERSION 3.31)
project(catclientupdatetool C)

set(CMAKE_C_STANDARD 11)

add_executable(catclientupdatetool main.c)
add_library(cJSON STATIC cJSON.c)

target_link_libraries(catclientupdatetool
        cJSON
        urlmon
        shlwapi
        crypt32
        comctl32
        user32
        gdi32)