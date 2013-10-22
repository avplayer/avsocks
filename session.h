#pragma once
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

namespace avsocks {

class session
		: public boost::enable_shared_from_this<session>
{
public:
	session(boost::asio::ip::tcp::socket socket);

	void start();

private:
	boost::asio::ip::tcp::socket socket_;
	boost::asio::strand strand_;
};
}
