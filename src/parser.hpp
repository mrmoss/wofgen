#ifndef WOF_PARSER_HPP
#define WOF_PARSER_HPP

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

#endif