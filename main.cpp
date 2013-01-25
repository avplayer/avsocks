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

public:
	// avclient构造析构函数.
	avclient(asio::io_service& _io_service, socketptr socket, hostaddress avserveraddr);

	// 创建一个avclient对象, 并进入工作.
	static void new_avclient(asio::io_service& _io_service,
		socketptr socket, hostaddress avserveraddr = avserver_address);

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

private:

	enum {
		AVCLIENT_TYPE_SOCKS5, // 工作在client模式，意味着直接将数据SSL转发给远程的avsocks服务器.
		AVCLIENT_TYPE_SERVER, // 工作在server模式，意味着需要将SSL读取的数据直接转发给远程主机.
	} m_type;

	asio::io_service&	io_service;
	hostaddress			m_avsocks_serveraddress;
	socketptr			m_socket_client;
	ip::tcp::socket		m_socket_server;
	ssl::context		m_sslctx;
	boost::shared_ptr<ssl::stream<asio::ip::tcp::socket&> > m_sslstream;
};


// 下面是avclient的具体实现.

avclient::avclient(asio::io_service& _io_service, socketptr socket, hostaddress avserveraddr)
	: io_service(_io_service)
	, m_socket_client(socket)
	, m_avsocks_serveraddress(avserveraddr)
#if BOOST_VERSION >= 104300
	, m_sslctx(ssl::context::sslv23)
#else
	, m_sslctx(_io_service, ssl::context::sslv23)
#endif
	, m_socket_server(_io_service)
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
		m_sslstream.reset(new ssl::stream<ip::tcp::socket&>(m_socket_server, m_sslctx));
		// 异步发起到 vps server的连接，并开始读取client的第一个请求，依
		// 据请求来判定是 socks5 还是 HTTP 还是透明代理.
		m_socket_server.async_connect(m_avsocks_serveraddress,
			boost::bind(&avclient::handle_avserver_connected, shared_from_this(), asio::placeholders::error));
	}
	else//TODO: 检查 HTTP 协议.
	{
		// 否则就是 ssl handshake 了.
		m_type = AVCLIENT_TYPE_SERVER;

		// 设置 SSL 证书等等.
		setup_ssl_cert();
		// 把 client 的socket打入SSL模式.
		m_sslstream.reset(new ssl::stream<ip::tcp::socket&>(*m_socket_client, m_sslctx));
		// 执行 SSL 握手.
		m_sslstream->async_handshake(ssl::stream_base::server,
			boost::bind(&avclient::handle_ssl_handshake, shared_from_this(), asio::placeholders::error));
	}
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
			// splice过去, 协议的解析神码的都交给服务器来做就是了.
			boost::shared_ptr<avsocks::splice<avclient,ip::tcp::socket,ssl::stream<asio::ip::tcp::socket&> > >
				splice(new avsocks::splice<avclient, ip::tcp::socket, ssl::stream<asio::ip::tcp::socket&> > (shared_from_this(), *m_socket_client, *m_sslstream));
			splice->start();
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

void avclient::new_avclient(asio::io_service& io_service,
	socketptr socket, hostaddress avserveraddr/* = avserver_address*/)
{
	// 先构造一个对象.
	avclientptr p(new avclient(io_service, socket, avserveraddr));
	// 立刻开始工作.
	p->start();
}


// 一个简单的accept服务器, 用于不停的异步接受客户端的连接, 连接可能是socks5连接或ssl加密数据连接.
static
void do_accept(ip::tcp::acceptor &accepter, socketptr avsocketclient, const boost::system::error_code &ec)
{
	// socket对象
	if(!ec)
	{
		// 使得这个avsocketclient构造一个avclient对象, 并start进入工作.
		avclient::new_avclient(io_service, avsocketclient);
	}

	// 创建新的socket, 进入侦听, .
	avsocketclient.reset(new ip::tcp::socket(accepter.get_io_service()));
	accepter.async_accept(*avsocketclient,
		boost::bind(&do_accept, boost::ref(accepter), avsocketclient, asio::placeholders::error));
}


int main(int argc, char **argv)
{
	std::string avserverport;
	std::string localport;
	std::string avserveraddress; // = "avsocks.avplayer.org";//"fysj.com"
	bool is_ipv6 = false;
	std::string authtoken;

	po::options_description desc("avsocks options");
	desc.add_options()
		( "version,v",																			"output version" )
		( "help,h",																				"produce help message" )
		( "port,p",		po::value<std::string>(&avserverport)->default_value("4567"),			"server port" )
		( "avserver",	po::value<std::string>(&avserveraddress)->default_value("localhost"),	"avsocks server address" )
		( "listen,l",	po::value<std::string>(&localport)->default_value("4567"),				"local listen port" )
		( "ipv6,6",		po::value<bool>(&is_ipv6)->default_value(false),						"is ipv6" )
		( "daemon,d",																			"go into daemon mode" )
		( "auth",		po::value<std::string>(&authtoken),										"username:password pair" )
	;

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
    
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
			boost::bind(&do_accept, boost::ref(acceptor), avsocketclient, asio::placeholders::error));
	}

#ifndef WIN32
	if(vm.count("daemon")>0)
		daemon(0, 0);
#endif // WIN32

	return io_service.run() > 0 ? 0 : 1;
}
