/*
 * avsession.hpp , 真正的代理服务器代码.
 *
 * Copyright (c) 2010-2013  microcai
 */

#pragma once

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

/**
 * 真正的执行 proxy 任务的类，是个模板，这样就可以支持 SSL 和 raw socket.
 * 起码使用 owner 技术，确保 avclient 类不被析构掉.
 * 喜欢上 C++ 这种确定析构的语言了吧，来吧，和 C++签订契约，成为cpper吧.
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

	}

private:
	S1&							s1; // 两个 socket
	S2&							s2; // 两个 socket
	boost::shared_ptr<Towner>	owner; // 确保 owner 不被析构掉.
};
