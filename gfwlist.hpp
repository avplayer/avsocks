
/**
 * gfwlist.hpp 自动更新下载 gfwlist.txt 文件，并执行 gfw 匹配
 *
 * copyright (C)  2013 microcai
 **/

#pragma once

#include <ctime>
#include <fstream>

#include <boost/noncopyable.hpp>
#include <boost/regex.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
namespace asio = boost::asio;
#include <boost/filesystem.hpp>
#include <boost/concept_check.hpp>
namespace fs = boost::filesystem;
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <urdl/read_stream.hpp>
#include <urdl/http.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>


class gfwlist : protected boost::noncopyable{
public:
	// 默认构造文件.
	gfwlist(asio::io_service & _io_service):io_service(_io_service), m_urdl(io_service){
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
				m_urdl.set_option(urdl::http::user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0"));
 				m_urdl.async_open(//"file:///home/cai/projects/misc/gfwlist.txt",
 								   "https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt",
 				   boost::bind( &gfwlist::googlecode_connected, this, asio::placeholders::error )
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
	bool is_gfwed(std::string host, unsigned int port = 80) const{
		boost::replace_all(host, ".", "\\.");
		boost::regex	regex(host);
		BOOST_FOREACH(const std::string &l, m_content)
		{
			if( l[0] == '!' || l.empty())
				continue;
			if( boost::regex_search(l,regex))
				return true;
		}
		return false;
	}
private:
	void googlecode_connected(const boost::system::error_code & ec){
		if(!ec){
			// 读取直到下载完成吧！
			m_urdl.async_read_some( m_content_base64.prepare ( 16384 ), boost::bind ( &gfwlist::handle_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred ) );
		}else{
			std::cout << ec.message() << std::endl;
		}
	}

	void handle_read(const boost::system::error_code & ec, std::size_t readed){
		if(!ec){
			m_content_base64.commit(readed);
			m_urdl.async_read_some( m_content_base64.prepare( 16384 ), boost::bind( &gfwlist::handle_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred ) );
		}else if( ec == asio::error::eof ){
			// download completed
			base64_decode();
			// save to file
			std::ofstream outf(m_cached_gfwlist.c_str());
			BOOST_FOREACH(const std::string &l, m_content)
			{
				outf << l;
			}
		}else{
			// TODO 重试.
			std::cout << ec.message() << std::endl;
		}
	}

	// BASE64 解码.
	void base64_decode(){
		using namespace boost::archive::iterators;
		// convert base64 characters to binary values
		typedef	transform_width< binary_from_base64<std::string::iterator>, 8, 6, char> base64Iterator;

        const char * data = asio::buffer_cast<const char *>( m_content_base64.data() );

		std::string str(data,asio::buffer_size(m_content_base64.data()));
		boost::replace_all(str,"\n","");

		std::string decoded( base64Iterator(str.begin()) , base64Iterator(str.end()));

		boost::split(m_content_lines,decoded,boost::is_any_of("\n"));
	}

private:
	asio::io_service&			io_service;
	fs::path		 			m_cached_gfwlist;
	urdl::read_stream			m_urdl;
	asio::streambuf				m_content_base64;
	std::vector<std::string>	m_content_lines;
};
