cmake_minimum_required(VERSION 2.6)
project(avsocks)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

find_package(Boost REQUIRED thread program_options regex)
find_package(OpenSSL REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})


add_executable(avsocks main.cpp)
target_link_libraries(avsocks ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})

install(TARGETS avsocks RUNTIME DESTINATION bin)
