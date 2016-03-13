#ifndef PARSER_UTIL_HPP
#define PARSER_UTIL_HPP

#include <string>

std::string parse_to_symbol(std::string& str,const std::string& symbol);
std::string parse_block(std::string& str);
std::string parse_string(std::string& str);
std::string parse_uint(std::string& str);
std::string parse_hex(std::string& str);
std::string parse_symbol(std::string& str);
std::string parse_symbol_throw(std::string& str,const std::string& symbol,const std::string& after="");
std::string parse_proto(std::string& str);
std::string parse_any(std::string& str,const std::string& value);
void error_empty_ip(std::string& str,const std::string& ip,const std::string& ver,const std::string& err="");
std::string parse_octet(std::string& str);
std::string parse_hextet(std::string& str);
std::string parse_ipv4(std::string& str,bool& was_any,const std::string& err="");
void ipv6_invalid(const std::string& ip);
std::string parse_ipv6(std::string& str,bool& was_any,const std::string& err="");
std::string parse_ip(std::string& str,bool& was_any,bool& v6,const std::string& err="");
std::string parse_subnet_mask(std::string& str,const bool was_any,const bool v6);
std::string parse_port(std::string& str);
std::string parse_dir(std::string& str,const std::string& err);
std::string parse_action(std::string& str,const std::string& err);
bool parse_def(std::string& str,std::string& def_out,std::string& def_in);

#endif