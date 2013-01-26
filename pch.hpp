
#pragma once

// for pre-compiled header

#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <map>

#include <boost/version.hpp>
#include <boost/concept_check.hpp>

#include <boost/regex.hpp>

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/format.hpp>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>



namespace asio = boost::asio;
namespace ip = asio::ip;
namespace ssl = asio::ssl;
namespace po = boost::program_options;
namespace fs = boost::filesystem;
using boost::make_shared;
