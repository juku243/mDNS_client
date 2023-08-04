cmake_minimum_required(VERSION 3.15)
project(mDNS_client)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory("submodules/mdns")

include_directories("submodules/mdns")

set(INC
)

set(SRC
    "src/main.cpp"
)

add_executable(mDNS_client ${SRC} ${INC})

target_link_libraries(mDNS_client PRIVATE mdns)