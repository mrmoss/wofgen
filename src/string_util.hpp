#ifndef STRING_UTIL_HPP
#define STRING_UTIL_HPP

#include <string>
#include <vector>

int ishexdigit(int c);
std::vector<std::string> split(std::string str,const std::string& delimeter);
std::string strip_start(std::string str);
std::string strip_end(std::string str);
std::string strip(std::string str);
std::string strip_all(std::string str);
std::string to_lower(std::string str);
int to_int(const std::string& str);

#endif