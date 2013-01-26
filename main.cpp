// 通过使用 SYMBOL_HIDDEN 让这个类不要导出，减少ELF文件体积.
#if defined _WIN32 || defined __CYGWIN__
	#define SYMBOL_HIDDEN
#else
	#if __GNUC__ >= 4 || defined __clang__ 
	#define SYMBOL_HIDDEN  __attribute__ ((visibility ("hidden")))
	#else
	#define SYMBOL_HIDDEN
	#endif
#endif

// 头文件定义.
#include <iostream>
#include <boost/version.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
using boost::make_shared;
#include <boost/bind.hpp>
#include <boost/asio.hpp>
namespace asio = boost::asio;
namespace ip = asio::ip;
#include <boost/asio/ssl.hpp>
namespace ssl = asio::ssl;

#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <boost/lexical_cast.hpp>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <boost/foreach.hpp>
#include <map>

#include "sd-daemon.h"

#include "splice.hpp"
#include "avsession.hpp"
#include "gfwlist.hpp"

typedef boost::shared_ptr< asio::ip::tcp::socket > socketptr;
typedef asio::ip::tcp::resolver dnsresolver;
typedef asio::ip::tcp::endpoint	hostaddress;

static asio::io_service	io_service;
// 用来连接avsocks服务器的地址!
static hostaddress avserver_address;



// avclient类定义, 每一个客户(可能是socks5或加密ssl)连接, 都将创建一个avclient
// 对象, 在avclient中, 根据连接的对象是socks5或加密ssl, 自动启动不同的工作.
// 如果是socks5连接, 则将启动avsession; 如果是ssl, 则转发数据到远程server中.
//
// Fuck墙的工程流程大致如下图所示:
//   
//                   +---------------+     |     +-------------+
//   browser/app --> | socks5 -> ssl | ----|---> | ssl -> sock |--> website/server
//                   +---------------+     |     +-------------+
//                                        GFW
//   
class avclient
	: public boost::enable_shared_from_this<avclient>
	, private boost::noncopyable
{
public:
	typedef boost::shared_ptr<avclient>	avclientptr;
	
	std::map<std::string, std::string>& config;

public:
	// avclient构造析构函数.
	avclient(asio::io_service& _io_service, std::map<std::string, std::string>& config, 
		gfwlist& gfwlistfile, socketptr socket, hostaddress avserveraddr);

	// 创建一个avclient对象, 并进入工作.
	static void new_avclient(asio::io_service& _io_service, std::map<std::string, std::string>& config,
		gfwlist& gfwlistfile, socketptr socket, hostaddress avserveraddr = avserver_address);

	// 启动avclient工作.
	void start();

private:

	// 检查连接类型, 是否为ssl或socks5连接, 方法: 通过读取第一个数据包来确定客户端的类型.
	void typedetect(const boost::system::error_code & ec) SYMBOL_HIDDEN;
	// ssl握手.
	void handle_ssl_handshake(const boost::system::error_code & ec) SYMBOL_HIDDEN;
	// 连接远程代理服务器回调.
	void handle_avserver_connected(const boost::system::error_code & ec) SYMBOL_HIDDEN;
	// 设置证书和私钥信息.
	void setup_ssl_cert() SYMBOL_HIDDEN;
	void start_ssl_handshake();
	void detect_ifgfwed(const boost::system::error_code & ec, std::size_t bytes_transferred, int state);
	void start_socks5_helper();
	void handle_socks5_auth(const boost::system::error_code & ec, std::size_t bytes_transferred, int state);
	void socks5_send_request();

private:

	enum {
		AVCLIENT_TYPE_SOCKS5, // 工作在client模式，意味着直接将数据SSL转发给远程的avsocks服务器.
		AVCLIENT_TYPE_SERVER, // 工作在server模式，意味着需要将SSL读取的数据直接转发给远程主机.
	} m_type;

	asio::io_service&	io_service;
	gfwlist&			m_gfwlistfile;
	hostaddress			m_avsocks_serveraddress;
	socketptr			m_socket_client;
	ip::tcp::socket		m_socket_server;
	ssl::context		m_sslctx;
	boost::shared_ptr<ssl::stream<asio::ip::tcp::socket&> > m_sslstream;
	// 浏览器想要连接的目标.
	std::string			host;
	int					port;
};


// 下面是avclient的具体实现.


avclient::avclient(asio::io_service& _io_service, std::map<std::string, std::string>& config, 
	gfwlist& gfwlistfile, socketptr socket, hostaddress avserveraddr)
	: io_service(_io_service)
	, m_socket_client(socket)
	, m_avsocks_serveraddress(avserveraddr)
#if BOOST_VERSION >= 104300
	, m_sslctx(ssl::context::sslv23)
#else
	, m_sslctx(_io_service, ssl::context::sslv23)
#endif
	, m_socket_server(_io_service)
	, config(config)
	, m_gfwlistfile(gfwlistfile)
{}

void avclient::start()
{
	// 首先读取第一个字节，来确定工作在server状态还是client状态.
	// server状态很明显，第一个接收的包是 SSL 握手的.
	// 所以，先读取第一个数据.
	m_socket_client->async_read_some(asio::null_buffers(),
		boost::bind(&avclient::typedetect, shared_from_this(), asio::placeholders::error));
}

void avclient::typedetect(const boost::system::error_code& ec)
{
	boost::uint8_t buffer[64]={0};
#if BOOST_VERSION >= 104300
	int fd = m_socket_client->native_handle();// native_handle();
#else
	int fd = m_socket_client->native();
#endif

	// 使用 msg_peek, 这样读取的数据并不会从接收缓冲区删除.
#ifdef WIN32
	recv(fd, (char*)buffer, sizeof(buffer), MSG_PEEK);
#else
	recv(fd, buffer, sizeof(buffer), MSG_PEEK|MSG_NOSIGNAL|MSG_DONTWAIT);
#endif // WIN32

	// 检查 socks5.
	if(buffer[0] == 0x05 || buffer[0] == 'G')
	{
		m_type = AVCLIENT_TYPE_SOCKS5;
		// 检测到 socks5 协议！，进入 client 模式，向 server 端发起SSL连接.
		std::cout << "client mode" << std::endl;
		// 检查是否被墙.
		m_socket_client->async_read_some(boost::asio::null_buffers(),
			boost::bind(&avclient::detect_ifgfwed, shared_from_this(), 
				asio::placeholders::error, asio::placeholders::bytes_transferred, 0));

	}
	else//TODO: 检查 HTTP 协议.
	{
		// 否则就是 ssl handshake 了.
		m_type = AVCLIENT_TYPE_SERVER;
		
		start_ssl_handshake();
	}
}

void avclient::start_socks5_helper()
{
	m_sslstream.reset(new ssl::stream<ip::tcp::socket&>(m_socket_server, m_sslctx));
	// 异步发起到 vps server的连接，并开始读取client的第一个请求，依
	// 据请求来判定是 socks5 还是 HTTP 还是透明代理.
	m_socket_server.async_connect(m_avsocks_serveraddress,
		boost::bind(&avclient::handle_avserver_connected, shared_from_this(), asio::placeholders::error));
}


void avclient::detect_ifgfwed(const boost::system::error_code& ec, std::size_t bytes_transferred, int state)
{
	// 出错了就没了.
	if(ec) 
		return;
	
	boost::uint8_t buffer[300]={0};
	boost::system::error_code ec_;
	std::size_t n;
	// 这里是状态机.
	switch(state) {
		case 0: // 读取客户端认证方式列表.
			// 读取版本号和支持的认证数.
			asio::read(*m_socket_client, asio::buffer(buffer, 2), ec_); 
			// 读取支持的认证方法.
			asio::read(*m_socket_client, asio::buffer(buffer, buffer[1]), ec_); 
			// 告诉客户端，不需要认证.
			asio::async_write(*m_socket_client, asio::buffer("\x05\x00", 2),
				boost::bind(&avclient::detect_ifgfwed, shared_from_this(), _1, _2, 1));
			break;
			
		case 1: // 读取客户端请求.
			m_socket_client->async_read_some(asio::null_buffers(),
				boost::bind(&avclient::detect_ifgfwed, shared_from_this(), _1, _2, 2));
			break;
			
		case 2: //
			n = m_socket_client->read_some(boost::asio::buffer(buffer), ec_);
			
			// 只支持CONNECT
			if(!(buffer[0]==5 && buffer[1] == 1))
			{
				std::cerr << "only suppport CONNECT now" << std::endl;
				return;
			}
			
			switch(buffer[3])
			{
				case 0x01:// IPv4.
				{
					boost::uint32_t addr = ntohl(*(boost::uint32_t*)(buffer+4));
					struct in_addr ia;
					ia.s_addr = addr;
					host = inet_ntoa(ia);
					port = ntohs(*(boost::uint16_t*)(buffer+8));
				}	
				break;
				case 0x03:
				{
					std::size_t dlen = buffer[4];
					host.assign(buffer+5, buffer+5+dlen);
					port = ntohs( *(boost::uint16_t*)(buffer+5+dlen));
					if( config["gfwlist"] == "on" && m_gfwlistfile.is_gfwed(host, port) ) 
					{
						std::cout << "哎哟，撞墙了" << std::endl;
						start_socks5_helper();
						return;
					}
				}
				break;
			}
			
			boost::shared_ptr<avsession<avclient, asio::ip::tcp::socket,ip::tcp::socket> >
				session(new avsession<avclient, asio::ip::tcp::socket, ip::tcp::socket> (shared_from_this(), *m_socket_client, m_socket_server));
			session->start(host, port);
			break;
	}
	
}

void avclient::start_ssl_handshake()
{
	// 设置 SSL 证书等等.
	setup_ssl_cert();
	// 把 client 的socket打入SSL模式.
	m_sslstream.reset(new ssl::stream<ip::tcp::socket&>(*m_socket_client, m_sslctx));
	// 执行 SSL 握手.
	m_sslstream->async_handshake(ssl::stream_base::server,
		boost::bind(&avclient::handle_ssl_handshake, shared_from_this(), asio::placeholders::error));
}


void avclient::handle_avserver_connected(const boost::system::error_code& ec)
{
	if (!ec)
	{
		// 执行 ssl handshake.
		m_sslstream->async_handshake(ssl::stream_base::client,
			boost::bind(&avclient::handle_ssl_handshake, shared_from_this(), asio::placeholders::error));
	}
	else
	{
		std::cout << ec.message() << std::endl;
	}
}

void avclient::socks5_send_request()
{
	boost::uint8_t buffer[512];
	std::size_t len = 0;
	buffer[len++] = 5;
	buffer[len++] = 1;		// CONNECT.
	buffer[len++] = 0;		// RSV.
	buffer[len++] = 3;		// ATYP:DOMAIN.
	buffer[len++] = host.size();
	std::copy(host.begin(), host.end(), buffer + len);
	len += host.size();
	*(boost::uint16_t*)(buffer+len) = htons(port);
	len += 2;
	m_sslstream->async_write_some(asio::buffer(buffer, len), 
		boost::bind(&avclient::handle_socks5_auth, shared_from_this(), _1, _2, 4));
}


void avclient::handle_socks5_auth(const boost::system::error_code& ec, std::size_t bytes_transferred, int state)
{
	if(ec)
		return;
	switch(state) 
	{
		case 0: // 发送完验证方式.
		{
			m_sslstream->async_read_some(asio::null_buffers(), 
				boost::bind(&avclient::handle_socks5_auth, shared_from_this(), _1, _2, 1));
		}
		break;
		case 1: // 看看服务器需要什么方式.
		{
			boost::uint8_t buffer[256];
			boost::system::error_code ec_;
			// 理论上来说，应该是读取到两个字节.
			m_sslstream->read_some(asio::buffer(buffer, 256), ec_);
			
			if(buffer[0] == 0x05)
			{
				// 服务器说不要认证.
				if(buffer[1] == 0x00)
				{
					socks5_send_request();
				}
				// 服务器需要认证.
				else if(buffer[1] == 0x02 && ! config["auth"].empty())
				{
					boost::uint8_t data[1024];
					std::size_t pos = 0; 
					data[pos++] = 5;
					std::vector<std::string> user_pass;
					boost::split(user_pass, config["auth"], boost::is_any_of(":"));
					if(user_pass.size() == 2)
					{
						data[pos++] = user_pass[0].size();
						std::copy(user_pass[0].begin(), user_pass[0].end(), data+pos);
						pos += user_pass[0].size();
						data[pos++] = user_pass[1].size();
						std::copy(user_pass[1].begin(), user_pass[1].end(), data+pos);
						pos += user_pass[1].size();
						m_sslstream->async_write_some(asio::buffer(data, pos), 
							boost::bind(&avclient::handle_socks5_auth, shared_from_this(), _1, _2, 2));
					}
				}
			}
		}
		break;
		case 2: // 开始读取认证结果.
		{
			m_sslstream->async_read_some(asio::null_buffers(),
				boost::bind(&avclient::handle_socks5_auth, shared_from_this(), _1, _2, 3));
		}
		break;
		case 3: // 读取认证的结果.
		{
			boost::uint8_t buffer[2];
			boost::system::error_code ec_;
			std::size_t n;
			n = m_sslstream->read_some(asio::buffer(buffer), ec_);
			if( n == 2 && buffer[0] == 5 && buffer[1] == 0)
			{
				socks5_send_request();
			}
		}
		case 4: // 已经将请求发送给服务器，开始对接.
		{
			boost::shared_ptr<avsocks::splice<avclient,ip::tcp::socket,ssl::stream<asio::ip::tcp::socket&> > >
				splice(new avsocks::splice<avclient, ip::tcp::socket, ssl::stream<asio::ip::tcp::socket&> > (shared_from_this(), *m_socket_client, *m_sslstream));
			splice->start();
		}
		break;
	}
}


void avclient::handle_ssl_handshake(const boost::system::error_code& ec)
{
	if(!ec)
	{
		if(m_type == AVCLIENT_TYPE_SERVER)
		{
			// 客户端已经被授权了，那么，开始处理吧，支持 SOCKS5 协议哦!
			boost::shared_ptr<avsession<avclient, ssl::stream<asio::ip::tcp::socket&>,ip::tcp::socket> >
				session(new avsession<avclient, ssl::stream<asio::ip::tcp::socket&>, ip::tcp::socket> (shared_from_this(), *m_sslstream, m_socket_server));
			session->start();
		}
		else
		{
			if( config["auth"].empty() )
			{
				m_sslstream->async_write_some(asio::buffer("\x05\x01\x00"), 
					boost::bind(&avclient::handle_socks5_auth, shared_from_this(), _1, _2, 0));
			}
			else
			{
				m_sslstream->async_write_some(asio::buffer("\x05\x02\x00\x02"),
					boost::bind(&avclient::handle_socks5_auth, shared_from_this(), _1, _2, 0));
			}
			// splice过去, 协议的解析神码的都交给服务器来做就是了.
// 			boost::shared_ptr<avsocks::splice<avclient,ip::tcp::socket,ssl::stream<asio::ip::tcp::socket&> > >
// 				splice(new avsocks::splice<avclient, ip::tcp::socket, ssl::stream<asio::ip::tcp::socket&> > (shared_from_this(), *m_socket_client, *m_sslstream));
// 			splice->start();
		}
	}
	else
	{
		std::cout << ec.message() << std::endl;
	}
}

#include "cert.hpp"	// 引入证书和私钥数据.

void avclient::setup_ssl_cert()
{
	m_sslctx.set_verify_mode(ssl::context::verify_none);
	m_sslctx.set_options(ssl::context::default_workarounds|ssl::context::no_sslv2);

	SSL_CTX *CTX;

#if BOOST_VERSION >= 104600
	CTX = m_sslctx.native_handle();
#else
	CTX = m_sslctx.impl();
#endif

	X509 *cert = NULL;
	RSA *rsa = NULL;
	BIO *bio = NULL;

	bio = BIO_new_mem_buf(server_crt,sizeof(server_crt));
	cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
	SSL_CTX_use_certificate(CTX, cert);
	BIO_free_all(bio);

	bio = BIO_new_mem_buf(server_key,sizeof(server_key));
	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, 0, NULL);
	SSL_CTX_use_RSAPrivateKey(CTX, rsa);
	BIO_free_all(bio);
}


void avclient::new_avclient(asio::io_service& io_service, std::map<std::string, std::string>& config,
	gfwlist& gfwlistfile, socketptr socket, hostaddress avserveraddr/* = avserver_address*/)
{
	// 先构造一个对象.
	avclientptr p(new avclient(io_service, config, gfwlistfile, socket, avserveraddr));
	// 立刻开始工作.
	p->start();
}


// 一个简单的accept服务器, 用于不停的异步接受客户端的连接, 连接可能是socks5连接或ssl加密数据连接.
static
void do_accept(ip::tcp::acceptor &accepter, std::map<std::string, std::string>& config, 
			   gfwlist& gfwlistfile, socketptr avsocketclient, const boost::system::error_code &ec)
{
	// socket对象
	if(!ec)
	{
		// 使得这个avsocketclient构造一个avclient对象, 并start进入工作.
		avclient::new_avclient(io_service, config, gfwlistfile, avsocketclient);
	}

	// 创建新的socket, 进入侦听, .
	avsocketclient.reset(new ip::tcp::socket(accepter.get_io_service()));
	accepter.async_accept(*avsocketclient,
		boost::bind(&do_accept, boost::ref(accepter), 
			boost::ref(config), boost::ref(gfwlistfile), 
				avsocketclient, asio::placeholders::error));
}


int main(int argc, char **argv)
{
	std::string avserverport;
	std::string localport;
	std::string avserveraddress; // = "avsocks.avplayer.org";//"fysj.com"
	bool is_ipv6 = false;
	std::map<std::string, std::string> config;

	po::options_description desc("avsocks options");
	desc.add_options()
		( "version,v",																			"output version" )
		( "help,h",																				"produce help message" )
		( "port,p",		po::value<std::string>(&avserverport)->default_value("4567"),			"server port" )
		( "avserver",	po::value<std::string>(&avserveraddress)->default_value("localhost"),	"avsocks server address" )
		( "listen,l",	po::value<std::string>(&localport)->default_value("4567"),				"local listen port" )
		( "ipv6,6",		po::value<bool>(&is_ipv6)->default_value(false),						"is ipv6" )
		( "daemon,d",																			"go into daemon mode" )
		( "auth",		po::value<std::string>(&config["auth"]),								"username:password pair" )
		( "authfile",	po::value<std::string>(&config["authfile"]),							"a file consist of username password pair" )
		( "gfwlist",	po::value<std::string>(&config["gfwlist"])->default_value("on"),		"enable gfwlist [on|off]")
	;

	po::variables_map vm;
	
	// 读取配置文件, 优先级为: 临时配置 > 用户配置 > 系统配置.
	std::vector<fs::path> config_files;
	config_files.push_back ( "/etc/avsocks.conf" ); // 系统配置文件.

	if ( getenv ( "HOME" ) )
		config_files.push_back ( fs::path ( getenv ( "HOME" ) ) / ".avsocks.conf" ); // 用户配置文件.

	config_files.push_back ( "avsocks.conf" ); // 临时配置文件.
	BOOST_FOREACH ( fs::path config_file, config_files ) {
		if ( fs::exists ( config_file ) ) {
			po::store ( po::parse_config_file<char> ( config_file.string().c_str(), desc ), vm );
		}
	}
	
	po::store(po::parse_command_line(argc, argv, desc), vm);
	
	po::notify(vm);
    
	if (vm.count("help"))
	{
		std::cerr <<  desc <<  std::endl;
		return 1;
	}
	if (vm.count("version"))
	{
		std::cout << "avsocks version " << "0.1" << std::endl;
	}

	// 解析 avsocks 服务器地址.
	avserver_address = *dnsresolver(io_service).resolve(dnsresolver::query(avserveraddress, avserverport));

	gfwlist  gfwlistfile(io_service);
	
	if(config["gfwlist"] == "on")
	{
		gfwlistfile.async_check_and_update();
	}
	// 不论是 server还是client，都是使用的监听模式嘛。所以创建个 accepter 就可以了.
	asio::ip::tcp::acceptor acceptor(io_service);
#ifdef __linux__

	if ( sd_listen_fds ( 0 ) > 0 ) {
		ip::tcp::socket::native_handle_type fd = sd_listen_fds ( 1 ) + SD_LISTEN_FDS_START;

		if ( sd_is_socket ( fd, AF_INET6, SOCK_STREAM, 1 ) ) { // ipv6 协议.
			std::cout << "v6" << std::endl;
			acceptor.assign ( asio::ip::tcp::v6(), fd );
		} else if ( sd_is_socket ( fd, AF_INET, SOCK_STREAM, 1 ) ) { // ipv4 协议.
			std::cout << "v4" << std::endl;
			acceptor.assign ( asio::ip::tcp::v4(), fd );
		} else {
			std::cerr << "invalid socket passed by systemd" << std::endl;
			return 1;
		}
	}else
#endif // windows 下自带 fallback 过去就是用这个了.
	{
		ip::tcp::endpoint endpoint(is_ipv6 ? ip::tcp::v6() : ip::tcp::v4(), boost::lexical_cast<int>(localport));
		acceptor.open( endpoint.protocol());
		acceptor.bind( endpoint);
		acceptor.listen();
	}
    
	{
		socketptr avsocketclient(new asio::ip::tcp::socket(acceptor.get_io_service()));
		acceptor.async_accept(*avsocketclient,
			boost::bind(&do_accept, boost::ref(acceptor), 
				boost::ref(config), boost::ref(gfwlistfile), 
				avsocketclient, asio::placeholders::error));
	}

#ifndef WIN32
	if(vm.count("daemon")>0)
		daemon(0, 0);
#endif // WIN32

	asio::signal_set signal_set(io_service);
	signal_set.add(SIGINT);
	signal_set.add(SIGTERM);
	signal_set.add(SIGHUP);
	signal_set.async_wait(boost::bind(&asio::io_service::stop, boost::ref(io_service)));
	
	return io_service.run() > 0 ? 0 : 1;
}
