
/**
 * gfwlist.hpp 自动更新下载 gfwlist.txt 文件，并执行 gfw 匹配
 *
 * copyright (C)  2013 microcai
 **/

#pragma once

#include <ctime>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
namespace asio = boost::asio;
#include <boost/filesystem.hpp>
#include <boost/concept_check.hpp>
namespace fs = boost::filesystem;

#include <urdl/read_stream.hpp>
#include <urdl/http.hpp>

class gfwlist{
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
		if(do_download){
			// 下载文件吧，下载文件大丈夫~
			
				m_urdl.async_open( "", boost::bind( &gfwlist::googlecode_connected, this, asio::placeholders::error ) );
			}
	}

	void googlecode_connected(const boost::system::error_code & ec){
		if(!ec){
			// 读取直到下载完成吧！
			m_urdl.async_read_some( m_content.prepare ( 16384 ), boost::bind ( &gfwlist::handle_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred ) );
		}
	}

	void handle_read(const boost::system::error_code & ec, std::size_t readed){
		if(!ec){
			m_content.commit(readed);
			m_urdl.async_read_some( m_content.prepare ( 16384 ), boost::bind ( &gfwlist::handle_read, this, asio::placeholders::error, asio::placeholders::bytes_transferred ) );
		}else if(ec == asio::error::eof){
			// download completed
		}

	}

private:
	asio::io_service&	io_service;
	fs::path		 	m_cached_gfwlist;
	urdl::read_stream	m_urdl;
	asio::streambuf		m_content;
};
