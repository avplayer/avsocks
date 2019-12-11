cmake_minimum_required(VERSION 2.6)
project(avsocks)

set(CMAKE_INSTALL_PREFIX /usr)

##################################################
# Common for all avplayer projects
######
include(CheckCXXCompilerFlag)
# check_cxx_compiler_flag(-std=c++11 HAS_CXX11)sd-
if (HAS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ")
endif()

check_cxx_compiler_flag(-fvisibility=hidden HAS_VISIBILITY)
if (HAS_VISIBILITY)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden ")
endif()

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fvisibility=hidden")

if(MSVC)
set (CMAKE_CONFIGURATION_TYPES "Release;Debug")
set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
		CMAKE_CXX_FLAGS_MinSizeRel
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
		CMAKE_C_FLAGS_MinSizeRel
   )

foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/W3" "/W1" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj /MP")

#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}  /ignore:4099 /NODEFAULTLIB:libcmt.lib ")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER}  /SAFESEH:NO ")

endif(MSVC)

#################################################


if(WIN32)
add_definitions(-DOPENSSL_NO_ENGINE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOPENSSL_NO_ENGINE -DOPENSSL_NO_COMP")
include_directories(third_party/openssl/include)
add_subdirectory(third_party/openssl)
else()
find_package(OpenSSL REQUIRED)
endif()

#################################################


option(USE_STATIC "static link to boost" ON)

if(USE_STATIC)
	set(Boost_USE_STATIC_LIBS        ON)
	set(Boost_USE_STATIC_RUNTIME    ON)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)


find_package(Boost 1.47 REQUIRED system program_options regex filesystem)
find_package(Threads)
find_package(systemd)

include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})
link_directories(${Boost_LIBRARY_DIR})
include_directories(${Boost_INCLUDE_DIR})

if(WIN32)
	add_definitions(-DDISABLE_SYSTEMD)
endif()

add_executable(avsocks
	src/avauth.hpp src/gfwlist.hpp
	src/avsession.hpp  src/main.cpp
	src/cert.hpp       src/pch.hpp      src/splice.hpp
)

if(SYSTEMD_FOUND)
	target_link_libraries(avsocks ${SYSTEMD_LIBRARIES})
	target_compile_definitions(avsocks PRIVATE -DHAVE_SYSTEMD)
endif()

target_link_libraries(avsocks ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS avsocks RUNTIME DESTINATION bin)

install(FILES avsocks.service DESTINATION lib/systemd/system)
install(FILES avsocks.socket DESTINATION lib/systemd/system)
