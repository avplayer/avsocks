#pragma once
#include <boost/asio.hpp>

namespace avsocks {

class socks_server
{
public:
	socks_server(boost::asio::io_service& io_service, boost::asio::ip::tcp::endpoint endpoint);

	void start();

private:
	boost::asio::io_service& io_service_;
	boost::asio::ip::tcp::acceptor acceptor_;
};

} // namespace avsocks
