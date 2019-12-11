# - Find systemd libraries
# This module finds the systemd libraries

# This code sets the following variables:
#
#  SYSTEMD_FOUND           	  - have the systemd libs been found
#  SYSTEMD_LIBRARIES           - path to the systemd library
#  SYSTEMD_INCLUDE_DIRS        - path to where sd-daemon.h is found
#

#=============================================================================
# Copyright 2014 microcai
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# * Neither the names of Kitware, Inc., the Insight Software Consortium,
# nor the names of their contributors may be used to endorse or promote
# products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# # A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#=============================================================================
# (To distribute this file outside of CMake, substitute the full
#  License text for the above reference.)

# Use the Python interpreter to find the libs.
# check for systemd
if(SYSTEMD_INCLUDE_DIR)
  set(SYSTEMD_FIND_QUIETLY TRUE)
endif()

find_library(SYSTEMD_LIBRARY NAMES systemd)
find_path(SYSTEMD_INCLUDE_DIR systemd/sd-daemon.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SYSTEMD REQUIRED_VARS SYSTEMD_LIBRARY SYSTEMD_INCLUDE_DIR)
mark_as_advanced(SYSTEMD_LIBRARY SYSTEMD_INCLUDE_DIR)
set(SYSTEMD_LIBRARIES ${SYSTEMD_LIBRARY})
