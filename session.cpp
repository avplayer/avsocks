#include "session.h"
#include <boost/asio/spawn.hpp>

namespace asio = boost::asio;
using asio::ip::tcp;

namespace avsocks {
session::session(tcp::socket socket)
	: socket_(std::move(socket))
	, strand_(socket_.get_io_service())
{

}

void session::start()
{
	auto self = shared_from_this();
	asio::spawn(strand_,
				[this, self]
				(asio::yield_context yield)
	{
		//TODO handshake
	});
}

}
