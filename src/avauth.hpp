/*
 * avauth.hpp , 认证
 *
 * Copyright (c) 2010-2013  hyq
 */

#pragma once
#include <fstream>
#include <map>

class avauth
{
public:
	avauth(std::string authfile)
	: m_file(authfile) 
	{ load(); }
	
	void load()
	{ 
		m_usermap.clear();
		std::fstream input(m_file.c_str(), std::fstream::in);
		std::string user,pass;
		while(input >> user >> pass)
		{
			m_usermap[user] = pass;
		}
	}
	
	bool auth(std::string& user, std::string& pass)
	{ return m_usermap[user] == pass; }
	
private:
	std::string m_file;
	std::map<std::string, std::string> m_usermap;
};