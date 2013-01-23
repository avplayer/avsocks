#if defined _WIN32 || defined __CYGWIN__
	#define SYMBOL_HIDDEN
#else
	#if __GNUC__ >= 4 || defined __clang__ 
	#define SYMBOL_HIDDEN  __attribute__ ((visibility ("hidden")))
	#else
	#define SYMBOL_HIDDEN
	#endif
#endif

#include <iostream>
#include <boost/version.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
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

#include "splice.hpp"
#include "avsession.hpp"

typedef boost::shared_ptr< asio::ip::tcp::socket > socketptr;
typedef asio::ip::tcp::resolver dnsresolver;
typedef asio::ip::tcp::endpoint	hostaddress;

static asio::io_service	io_service;
// 用来连接avsocks服务器的地址!
static hostaddress	avserver_address;


/**
 * 通过使用 SYMBOL_HIDDEN 让这个类不要导出，减少ELF文件体积.
 **/
class avclient :
	public boost::enable_shared_from_this<avclient>,
	private boost::noncopyable
{
public:
	typedef boost::shared_ptr<avclient>	avclientptr;

	static avclientptr new_avclient(asio::io_service& _io_service, socketptr socket, hostaddress avserveraddr = avserver_address);
	avclient(asio::io_service& _io_service, socketptr socket, hostaddress avserveraddr);
	void start();
    ~avclient(){
		std::cout << "avclient deleted" << std::endl;
	}
private:
	void typedetect(const boost::system::error_code & ec) SYMBOL_HIDDEN;
	void handle_ssl_handshake(const boost::system::error_code & ec) SYMBOL_HIDDEN;
	void handle_avserver_connected(const boost::system::error_code & ec) SYMBOL_HIDDEN;
    void setup_ssl_cert() SYMBOL_HIDDEN;
private:

	enum {
		AVCLIENT_TYPE_SOCKS5, //工作在client模式，意味着直接将数据SSL转发给远程的avsocks服务器.
		AVCLIENT_TYPE_SERVER, //工作在server模式，意味着需要将SSL读取的数据直接转发给远程主机.
	}					m_type;
	asio::io_service&	io_service;
	hostaddress			m_avsocks_serveraddress;
	socketptr			m_socket_client;
	ip::tcp::socket		m_socket_server;
	ssl::context		m_sslctx;
	boost::shared_ptr< ssl::stream<asio::ip::tcp::socket&> >
						m_sslstream;
};

avclient::avclient(asio::io_service& _io_service, socketptr socket, hostaddress avserveraddr)
	:io_service(_io_service),m_socket_client(socket),m_avsocks_serveraddress(avserveraddr),
	m_sslctx(ssl::context::sslv23),
	m_socket_server(_io_service)
{
	m_sslctx.set_verify_mode(ssl::context::verify_none);
}

void avclient::start()
{
	//首先读取第一个字节，来确定工作在server状态还是client状态.
	//server状态很明显，第一个接收的包是 SSL 握手的.
	//所以，先读取第一个数据.
	m_socket_client->async_read_some(asio::null_buffers(),
		boost::bind(&avclient::typedetect,shared_from_this(),asio::placeholders::error));
}

//通过读取第一个数据包来确定客户端的类型
void avclient::typedetect(const boost::system::error_code& ec)
{
	uint8_t buffer[64]={0};
	int fd = m_socket_client->native_handle();
	//使用 msg_peek, 这样读取的数据并不会从接收缓冲区删除.
	recv(fd,buffer,sizeof(buffer),MSG_PEEK|MSG_NOSIGNAL|MSG_DONTWAIT);

	//检查 socks5
	if(buffer[0]==0x05 || buffer[0] == 'G'){
		m_type = AVCLIENT_TYPE_SOCKS5;
		// 检测到 socks5 协议！，进入 client 模式，向 server 端发起SSL连接.
		std::cout << "client mode" << std::endl;
		m_sslstream.reset(new ssl::stream<ip::tcp::socket&>(m_socket_server, m_sslctx));
		//异步发起到 vps server的连接，并开始读取client的第一个请求，依据请求来判定是 socks5 还是 HTTP 还是透明代理.
		m_socket_server.async_connect(m_avsocks_serveraddress,boost::bind(&avclient::handle_avserver_connected,shared_from_this(),asio::placeholders::error));
	}
	//TODO 检查 HTTP 协议.
	else{	//否则就是 ssl handshake 了.
		m_type = AVCLIENT_TYPE_SERVER;

		// 设置 SSL 证书等等.
		setup_ssl_cert();
		// 把 client 的socket打入SSL模式.
		m_sslstream.reset(new ssl::stream<ip::tcp::socket&>(*m_socket_client, m_sslctx));
		// 执行 SSL 握手.
		m_sslstream->async_handshake(ssl::stream_base::server,
			boost::bind(&avclient::handle_ssl_handshake,shared_from_this(),asio::placeholders::error)
		);
	}
}

void avclient::handle_avserver_connected ( const boost::system::error_code& ec )
{
	if ( !ec ) {
		//执行 ssl handshake
		m_sslstream->async_handshake ( ssl::stream_base::client, boost::bind ( &avclient::handle_ssl_handshake, shared_from_this(), asio::placeholders::error ) );
	} else {
		std::cout << ec.message() << std::endl;
	}
}

void avclient::handle_ssl_handshake(const boost::system::error_code& ec)
{
	if(!ec){
		if(m_type == AVCLIENT_TYPE_SERVER){
			//客户端已经被授权了，那么，开始处理吧，支持 SOCKS5 协议哦!

			boost::shared_ptr<avsession<avclient,ssl::stream<asio::ip::tcp::socket&>,ip::tcp::socket> >
				session( new avsession<avclient,ssl::stream<asio::ip::tcp::socket&>,ip::tcp::socket>(shared_from_this(), *m_sslstream, m_socket_server));
			session->start();
		}else{
			// splice过去, 协议的解析神码的都交给服务器来做就是了.
			boost::shared_ptr<avsocks::splice<avclient,ip::tcp::socket,ssl::stream<asio::ip::tcp::socket&> > >
				splice(new avsocks::splice<avclient,ip::tcp::socket,ssl::stream<asio::ip::tcp::socket&> >(shared_from_this(),*m_socket_client,*m_sslstream));
			splice->start();
		}
		//m_sslstream->write_some( asio::buffer("mabi",5) );//,[](const boost::system::error_code& ec){});
	}else{
		std::cout << ec.message() << std::endl;
	}
}

static void do_accept(ip::tcp::acceptor &accepter,socketptr avsocketclient, const boost::system::error_code& ec)
{
	// socket对象
	if(!ec)
		avclient::new_avclient(io_service,avsocketclient);
	
	avsocketclient.reset(new ip::tcp::socket(accepter.get_io_service()));

	accepter.async_accept(*avsocketclient,boost::bind(&do_accept,boost::ref(accepter),avsocketclient,asio::placeholders::error));
}

int main(int argc, char **argv)
{
    std::string avserverport = "4567";
    std::string avserveraddress = "localhost";// = "avsocks.avplayer.org";//"fysj.com"

	po::options_description desc("avsocks options");
	desc.add_options()
	    ( "version,v",												"output version" )
		( "help,h",													"produce help message" )
		( "port,p",		po::value<std::string>(&avserverport),		"server port" )
		( "avserver",	po::value<std::string>(&avserveraddress),	"avsocks server address" )
		;

	po::variables_map vm;
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

	//解析 avsocks 服务器地址.
	avserver_address = * dnsresolver(io_service).resolve(dnsresolver::query(avserveraddress,avserverport));
	
	//不论是 server还是client，都是使用的监听模式嘛。所以创建个 accepter 就可以了.
	asio::ip::tcp::acceptor accepter(io_service,asio::ip::tcp::endpoint(asio::ip::tcp::v6(), boost::lexical_cast<int>(avserverport)));

	{socketptr avsocketclient(new asio::ip::tcp::socket(accepter.get_io_service()));
	accepter.async_accept(*avsocketclient,boost::bind(&do_accept,boost::ref(accepter),avsocketclient,asio::placeholders::error));}

	return io_service.run()>0?0:1;
}

#include "cert.hpp"

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

avclient::avclientptr avclient::new_avclient(asio::io_service& io_service, socketptr socket, hostaddress avserveraddr)
{
	//先构造一个对象.
	avclientptr p(new avclient(io_service,socket,avserveraddr));
	//立刻开始工作.
	p->start();
	return p;
}
