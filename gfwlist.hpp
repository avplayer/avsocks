
/**
 * gfwlist.hpp 自动更新下载 gfwlist.txt 文件，并执行 gfw 匹配
 *
 * copyright (C)  2013 microcai
 **/

#pragma once

#include "pch.hpp"

namespace urdl{

class SYMBOL_HIDDEN https : protected boost::noncopyable{
public:
	typedef boost::function< void(const boost::system::error_code & , boost::asio::streambuf & body) >	completedhander;
// 	template< class Handle>
	https(asio::io_service& _io_service, std::string url, completedhander handler)
		:io_service(_io_service),
		m_sslctx(ssl::context::sslv23),
		resolver(_io_service),
		m_handler(handler)
		{
		method = "GET";
		std::size_t dem =  url.find("://");
		if( url.substr(0,dem) == "https"){
			port = 443;
		}
		std::size_t dem_query = url.find("/",dem+3);
		host = url.substr(dem +3,dem_query - dem -3);
		query = url.substr(dem_query,std::string::npos);

		m_sslctx.set_verify_mode(ssl::context::verify_none);

		m_sslstream.reset(new sslsocket(io_service,m_sslctx));
		ip::tcp::resolver::query query(host,boost::lexical_cast<std::string>(port));
		resolver.async_resolve(query,boost::bind(&https::resolved, this, asio::placeholders::error, asio::placeholders::iterator));
		//asio::async_connect(*m_sslstream.lowest_layer(), );
	}
private:
	void resolved(const boost::system::error_code& ec, ip::tcp::resolver::iterator it){
		if(!ec){
			asio::async_connect(m_sslstream->lowest_layer(), it, boost::bind(&https::connected, this, asio::placeholders::error));
		}else m_handler(ec, m_response_body);
	}

	void connected(const boost::system::error_code& ec){
		if(!ec){
			m_sslstream->async_handshake(ssl::stream_base::client, boost::bind(&https::hande_handshake, this, asio::placeholders::error));
		}else m_handler(ec, m_response_body);
	}

	void hande_handshake(const boost::system::error_code& ec){
		if(!ec)
		{
			// 发送 GET
			std::string httpheader = boost::str(
				boost::format("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n")
				% query % host
			);
			asio::async_write(*m_sslstream, asio::buffer(httpheader.c_str(), httpheader.length()), boost::bind(&https::handle_write_header, this, asio::placeholders::error));
		}else m_handler(ec, m_response_body);
	}

	void handle_write_header(const boost::system::error_code& ec){
		if(!ec){
			// 读取response
			asio::async_read_until(*m_sslstream, m_response_header, std::string("\r\n\r\n"),
				boost::bind(&https::handle_read_header, this, asio::placeholders::error, asio::placeholders::bytes_transferred)
			);
		}else m_handler(ec, m_response_body);
	}

	void handle_read_header(const boost::system::error_code& ec, std::size_t bytes_transferred){
		if(!ec){
			std::istream	stream(&m_response_header);
			std::string v1,v2,v3;
			stream >> v1 >> v2 >> v3;
			if(v2 == "200"){
				asio::async_read(*m_sslstream, m_response_body.prepare(16384),
					boost::bind(&https::handle_read_body, this, asio::placeholders::error, asio::placeholders::bytes_transferred)
				);
			}else m_handler(asio::error::make_error_code(asio::error::network_reset), m_response_body);
		}else m_handler(ec, m_response_body);
	}

	void handle_read_body(const boost::system::error_code& ec, std::size_t bytes_transferred){

		if(!ec){
			m_response_body.commit(bytes_transferred);
			asio::async_read(*m_sslstream, m_response_body.prepare(16384),
				boost::bind(&https::handle_read_body, this, asio::placeholders::error, asio::placeholders::bytes_transferred)
			);
		}else if(ec == asio::error::eof){
			// now its full, call the callback hander
			boost::system::error_code noerror;
			m_handler(noerror, m_response_body);
		}else m_handler(ec, m_response_body);
	}

	typedef asio::ssl::stream<ip::tcp::socket>	sslsocket;

	asio::io_service& 	io_service;
	ip::tcp::resolver	resolver;
	ssl::context		m_sslctx;
	std::string			host;
	std::string 		query;
	std::string			method;
	int 				port;
	boost::scoped_ptr<sslsocket>	m_sslstream;
	asio::streambuf		m_response_header;
	asio::streambuf		m_response_body;
	completedhander		m_handler;
};

}

class gfwlist : protected boost::noncopyable{
public:
	// 默认构造文件.
	gfwlist(asio::io_service & _io_service):io_service(_io_service){
#ifndef _WIN32
		if(getenv("HOME"))
			m_cached_gfwlist = fs::path(getenv("HOME")) / ".cache" / "gfwlist.txt";
		else
			m_cached_gfwlist = fs::path("/etc/cache/gfwlist.txt");
#else
		m_cached_gfwlist = fs::path(getenv("USERPROFILE")) / ".avsocks" / "gfwlist.txt";
#endif
	}

	// 在 $HOME/.cache/gfwlist.txt 保存一份缓存的 GFWLIST 文件，如果时间超过一天就重新下载.
	void async_check_and_update(){
		bool do_download = false;
		if(fs::exists(m_cached_gfwlist) && fs::is_regular_file(m_cached_gfwlist)){
			// 检查日期.
			std::time_t current_time;
			std::time_t last_write_time =  fs::last_write_time(m_cached_gfwlist);
			std::time(&current_time);

			if( current_time - last_write_time > 24*3600){
				do_download = true;
			}
		}else if(fs::exists(m_cached_gfwlist) && !fs::is_regular_file(m_cached_gfwlist)){
			fs::remove(m_cached_gfwlist);
			do_download = true;
		}else{
			if(!fs::exists(m_cached_gfwlist.parent_path()))
				fs::create_directory(m_cached_gfwlist.parent_path());
			do_download = true;
		}

		if ( do_download ) {
			// 下载文件吧，下载文件大丈夫.
			m_https.reset(
				new urdl::https(io_service, "https://raw.github.com/avplayer/avsocks/master/gfwlist.txt",
					boost::bind(&gfwlist::handle_downloaded, this, _1, _2))
			);
		}else{
			// load from file
			std::ifstream inf(m_cached_gfwlist.c_str());
			while(!inf.eof()){
				std::string line;
				std::getline(inf,line);
				m_content_lines.push_back(line);
			}
		}
	}

	// 该函数的作用就是检查 gfwlist.txt 判定是否被河蟹.
	bool is_gfwed(const std::string host, unsigned int port = 80) const{
		BOOST_FOREACH(const std::string &l, m_content_lines)
		{
			if( l[0] == '!' || l.empty())
				continue;
			if( is_matched(host,port, l))
				return true;
		}
		return false;
	}

private:
	std::string get_domain(const std::string & rule) const {
		std::size_t pos = rule.find("/");
		if( pos != std::string::npos){
			return rule.substr(0,pos);
		}
		return rule;
	}
	
	bool is_domain_match(const std::string &host, const std::string& domain) const {
		bool ret = host.find(domain.c_str())!=std::string::npos;
		return ret;
	}

	bool is_matched(const std::string& host, unsigned int port, const std::string& rule) const {
		if(rule[0]=='|' && rule[1]=='|'){ // 整个域名匹配.
			return is_domain_match(host, get_domain(rule.substr(2)));
		}else if(rule[0]=='@' && rule[1]=='@'){
			// 反过来
			return false;
		}else if(rule.substr(0,8) == "|http://"){
			if( port != 80)
				return false;
			return is_domain_match(host, get_domain(rule.substr(8)));
		}else if(rule.substr(0,9) == "|https://"){
			if( port != 443)
				return false;
			return is_domain_match(host, get_domain(rule.substr(9)));
		}else if(rule.substr(0,9) == "/^https?:")
		{
			if(port == 443)
				return false;
		}else if(rule[0]=='/' || rule.substr(0,2) == "!-"){
			// url 模式暂时不支持
			return false;
		}else { // free style 了. 只匹配 80 端口
			if( port != 80)
				return false;
			return is_domain_match(host, get_domain(rule));
		}
		return false;
	}

private:
	void handle_downloaded(const boost::system::error_code & ec, asio::streambuf & content){
		if(!ec){			
			// download completed
			base64_decode(content);
			// save to file
			std::ofstream outf(m_cached_gfwlist.c_str());
			BOOST_FOREACH(const std::string &l, m_content_lines)
			{
				outf << l << std::endl;
			}
		}else{
			// TODO 重试.
			std::cout << ec.message() << std::endl;
		}
		m_https.reset();
	}

	// BASE64 解码.
	void base64_decode(asio::streambuf & m_content_base64){
		using namespace boost::archive::iterators;
		// convert base64 characters to binary values
		typedef	transform_width< binary_from_base64<std::string::iterator>, 8, 6, char> base64Iterator;

        const char * data = asio::buffer_cast<const char *>( m_content_base64.data() );

		std::string str(data,asio::buffer_size(m_content_base64.data()));
		boost::replace_all(str,"\n","");
		boost::replace_all(str,"\r","");

		std::string decoded( base64Iterator(str.begin()) , base64Iterator(str.end()));

		boost::split(m_content_lines,decoded,boost::is_any_of("\n"));
	}

private:
	asio::io_service&			io_service;
	fs::path		 			m_cached_gfwlist;
	std::vector<std::string>	m_content_lines;
	boost::scoped_ptr<urdl::https> m_https;
};
