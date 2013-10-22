add_definitions(-std=c++11)
if(${APPLE})
	add_definitions(-stdlib=libc++)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lc++")
endif()

project(avsocks)
cmake_minimum_required(VERSION 2.8)

find_package(Boost REQUIRED system coroutine context)
include_directories(${Boost_INCLUDE_DIRS})

aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})

