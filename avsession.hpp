/*
 * avsession.hpp , 真正的代理服务器代码.
 *
 * Copyright (c) 2010-2013  microcai
 */

#pragma once

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
namespace asio = boost::asio;
namespace ip = boost::asio::ip;
	
#define ASIO_READ_PLACEHOLDERS asio::placeholders::error, asio::placeholders::bytes_transferred
#define ASIO_WRITE_PLACEHOLDERS asio::placeholders::error,asio::placeholders::bytes_transferred

#define BOOST_SHARED_THIS(classname) boost::enable_shared_from_this<classname<Towner,S1,S2> >::shared_from_this()

/**
 * 真正的执行 proxy 任务的类，是个模板，这样就可以支持 SSL 和 raw socket.
 * 起码使用 owner 技术，确保 avclient 类不被析构掉.
 * 喜欢上 C++ 这种确定析构的语言了吧，来吧，和 C++签订契约，成为cpper吧.
 *
 * 握手完成后，最后的接力任务交给 splice 完成.
 */
template < class Towner, class S1, class S2 >
class avsession
	:public  boost::enable_shared_from_this<avsession<Towner,S1,S2> >,
	 private boost::noncopyable
{

public:
	avsession(boost::shared_ptr<Towner> _owner, S1& _s1, S2& _s2)
	:s1(_s1),s2(_s2),owner(_owner){}

	void start(){
		// 读取第一个数据包，以确定客户端需要链接的目的地.
 		s1.async_read_some(
 			s1readbuf.prepare(64),
 			boost::bind(&avsession::handle_socks5_read,boost::enable_shared_from_this<avsession<Towner,S1,S2> >::shared_from_this(),ASIO_READ_PLACEHOLDERS)
 		);
	}

private:
	void handle_socks5_read(const boost::system::error_code & ec, std::size_t bytes_transferred){
		s1readbuf.commit(bytes_transferred);
		const uint8_t* buffer = asio::buffer_cast<const uint8_t*>(s1readbuf.data());
		if(ec)
			return;

		for(int count =  buffer[1] ; count ; count--)
		{
			// 协议支持情况
			switch(buffer[1+count])
 			{
 			case 2: // 用户名/密码 认证 TODO 
// 				g_socket_send(socket,"\005\002",2,0,0);
// 				g_socket_add_watch(socket,G_IO_IN,5,(GSocketSourceFunc)get_socks5_username,session);
 				s1readbuf.consume(s1readbuf.size());
				return ;
 			case 0: // 没认证，很好
 				s1.async_write_some(asio::buffer("\005\000",2),
					boost::bind(&avsession::handle_write,BOOST_SHARED_THIS(avsession),ASIO_WRITE_PLACEHOLDERS)
				);
				s1readbuf.consume(bytes_transferred);
				s1.async_read_some(s1readbuf.prepare(5),
					boost::bind(&avsession::handle_read_socks5_magic,BOOST_SHARED_THIS(avsession),ASIO_READ_PLACEHOLDERS)
				);
  				return ;
 			}
		}
	}

	void handle_write(const boost::system::error_code & ec, std::size_t bytes_transferred){}

	void handle_read_socks5_magic(const boost::system::error_code & ec, std::size_t bytes_transferred){
		if( ec || bytes_transferred < 5){
			std::cout << ec.message() << std::endl;
			return;
		}			
		s1readbuf.commit(bytes_transferred);
		const uint8_t* buffer = asio::buffer_cast<const uint8_t*>(s1readbuf.data());


		if(buffer[0]==5 && buffer[1] == 1)
		{
			int type = buffer[3];
			switch(type)
			{
			case 1: // IPv4
// 				g_socket_receive(socket,buffer,4,0,0);
// 				// 继续读6个字节.
// 				g_socket_add_watch(socket,G_IO_IN,3,(GSocketSourceFunc)get_socks5_iphost,session);
				break;
			case 3: // DNS 地址.
				{
					if (s1readbuf.size() < 5)
						break;
					int dnshost_len = buffer[4]+2;
					s1readbuf.consume(s1readbuf.size());
					s1.async_read_some(s1readbuf.prepare(dnshost_len),
						boost::bind(&avsession::handle_read_socks5_dnshost,BOOST_SHARED_THIS(avsession),ASIO_READ_PLACEHOLDERS)
					);
				}
 				break;
			}
		}
	}

	void handle_read_socks5_dnshost(const boost::system::error_code & ec, std::size_t bytes_transferred){
		if(ec)
			return;
		s1readbuf.commit(bytes_transferred);
		const char* buffer = asio::buffer_cast<const char*>(s1readbuf.data());

		std::string		host;
		host.assign(buffer,s1readbuf.size()-2);
		int port = ntohs( *(uint16_t*)(buffer+ s1readbuf.size()-2));
		// 好的，目的地址和端口都获得了，执行DNS解析，链接，etc工作.

 		ip::tcp::resolver::query query(host,boost::lexical_cast<std::string>(port));
 		boost::shared_ptr<ip::tcp::resolver> resolver(new ip::tcp::resolver(s1.get_io_service()));
 		resolver->async_resolve(query,
 			boost::bind(&avsession::handle_resolve_remote,BOOST_SHARED_THIS(avsession),resolver,asio::placeholders::error,asio::placeholders::iterator)
 		);
	}

	void handle_resolve_remote(boost::shared_ptr<ip::tcp::resolver> resolver, const boost::system::error_code& ec, ip::tcp::resolver::iterator iterator){
		if(ec){
			// 想客户放回 DNS 没找到， socks5 里是啥代号来着的？ TODO
		}else{
			// 链接到服务器.
			s2.async_connect(*iterator,
				boost::bind(&avsession::handle_remote_connected,BOOST_SHARED_THIS(avsession),asio::placeholders::error)
			);
		}
	}

	void handle_remote_connected(const boost::system::error_code& ec){
		if(ec){
			
		}else
		{
			// 向 client 返回链接成功信息.
			s1.async_write_some(asio::buffer("\005\000\000\001\000\000\000\000\000\000",10),
				boost::bind(&avsession::handle_write_socks5_ok,BOOST_SHARED_THIS(avsession),ASIO_WRITE_PLACEHOLDERS)
			);
			
		}
	}

	void handle_write_socks5_ok(const boost::system::error_code & ec, std::size_t bytes_transferred){
		// 开始 splice !
					// splice过去, 协议的解析神码的都交给服务器来做就是了.
		boost::shared_ptr<avsocks::splice<Towner,S1,S2> >
			splice(new avsocks::splice<Towner,S1,S2>(owner,s1,s2));
		splice->start();
	}

private:
	asio::streambuf				s1readbuf;
	S1&							s1; // 两个 socket
	S2&							s2; // 两个 socket
	boost::shared_ptr<Towner>	owner; // 确保 owner 不被析构掉.
};

#undef  ASIO_READ_PLACEHOLDERS
#undef  ASIO_WRITE_PLACEHOLDERS
#undef  BOOST_SHARED_THIS
