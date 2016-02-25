#ifndef STRING_UTIL_HPP
#define STRING_UTIL_HPP

#include <string>

inline std::string trim(std::string str)
{
	while(str.size()>0&&isspace(str[0])!=0)
		str=str.substr(1,str.size()-1);
	while(str.size()>0&&isspace(str[str.size()-1])!=0)
		str=str.substr(0,str.size()-1);
	return str;
}

inline std::string strip(std::string str)
{
	for(size_t ii=0;ii<str.size();++ii)
		if(isspace(str[ii])!=0)
			str.erase(ii--,1);
	return str;
}

inline std::string to_lower(std::string str)
{
	std::transform(str.begin(),str.end(),str.begin(),tolower);
	return str;
}

#endif