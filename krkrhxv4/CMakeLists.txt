cmake_minimum_required(VERSION 3.20.0)
project(krkrhxv4 VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(
    "/source-charset:utf-8"
    "$<$<CONFIG:Release>:/GF>"
    "$<$<CONFIG:Release>:/Oy>"
    "$<$<CONFIG:Release>:/GL>"
    "$<$<CONFIG:Release>:/GS->"
)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/cx/cx.cpp
    src/crypto/crypto.cpp
    src/xp3/xp3.cpp
    src/console/console.cpp
)
target_include_directories(${PROJECT_NAME} PUBLIC
    src
    src/console
)

find_package(ZLIB REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    ZLIB::ZLIB
)