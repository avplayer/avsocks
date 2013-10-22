#include <iostream>
#include <boost/asio.hpp>
#include "socks_server.h"

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace std;

int main()
{
	asio::io_service io;
	tcp::endpoint endpoint(tcp::v4(), 4567);
	avsocks::socks_server server(io, endpoint);
	server.start();
	io.run();
	return 0;
}

