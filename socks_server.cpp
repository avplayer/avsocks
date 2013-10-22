#include "session.h"
#include "socks_server.h"
#include <boost/make_shared.hpp>
#include <boost/asio/spawn.hpp>

namespace asio = boost::asio;
using asio::ip::tcp;

namespace avsocks {

socks_server::socks_server(asio::io_service &io_service, tcp::endpoint endpoint)
	: io_service_(io_service)
	, acceptor_(io_service_, endpoint)
{

}

void socks_server::start()
{
	asio::spawn(io_service_,
				[this]
				(asio::yield_context yield)
	{
		tcp::socket socket(io_service_);
		for(;;)
		{
			boost::system::error_code ec;
			acceptor_.async_accept(socket, yield[ec]);
			if(!ec)
			{
				boost::make_shared<session>(std::move(socket))->start();
			}
		}
	});
}

} // namespace avsocks
