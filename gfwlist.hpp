
/**
 * gfwlist.hpp 自动更新下载 gfwlist.txt 文件，并执行 gfw 匹配
 *
 * copyright (C)  2013 microcai
 **/

#pragma once

#include <ctime>
#include <boost/asio.hpp>
namespace asio = boost::asio;
#include <boost/filesystem.hpp>
#include <boost/concept_check.hpp>
namespace fs = boost::filesystem;

class gfwlist{
public:
	// 默认构造文件.
	gfwlist(asio::io_service & _io_service):io_service(_io_service){
#ifndef _WIN32
		m_cached_gfwlist = fs::path(getenv("HOME")) / ".cache" / "gfwlist.txt";
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
			// 下载文件.
		}
	}

private:
	asio::io_service & io_service;
	fs::path		 m_cached_gfwlist;
};
