cmake_minimum_required(VERSION 3.15)
project(mDNS_client)

set(CMAKE_CXX_STANDARD 11)

include_directories("submodules/mdns_cpp")

link_directories("submodules/mdns_cpp")

set(INC
)

set(SRC
    "src/main.cpp"
)

add_executable(mDNS_client ${SRC} ${INC})