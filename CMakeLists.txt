cmake_minimum_required(VERSION 3.31)
project(catclientupdatetool CXX)

set(CMAKE_CXX_STANDARD 17)
add_executable(catclientupdatetool main.cpp)
add_library(cJSON STATIC cJSON.cpp)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR})

file(GLOB IMGUI_SOURCES
        ${IMGUI_DIR}/*.cpp
        ${IMGUI_DIR}/imgui_impl_win32.cpp
        ${IMGUI_DIR}/imgui_impl_opengl3.cpp
)

include_directories(
        ${IMGUI_DIR}
)

target_link_libraries(catclientupdatetool
        cJSON
        urlmon
        shlwapi
        crypt32
        comctl32
        user32
        gdi32
        opengl32)