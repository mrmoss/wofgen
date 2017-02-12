#ifndef PARSER_HPP
#define PARSER_HPP

#include <string>

struct wof_t
{
	std::string proto;
	std::string l_ip;
	std::string l_mask;
	std::string l_port;
	std::string dir;
	std::string f_ip;
	std::string f_mask;
	std::string f_port;
	std::string action;
	bool V6;
};

void wof_parse_line(std::string line,std::string& output,
	std::string& def_out,std::string& def_in);

bool wof_is_any_ip(const std::string& ip,const std::string& mask,const bool V6);

bool wof_is_exact_ip(const std::string& mask,const bool V6);

#endif