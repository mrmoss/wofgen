#ifndef STRING_UTIL_HPP
#define STRING_UTIL_HPP

#include <string>
#include <vector>

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
	for(size_t ii=0;ii<str.size();++ii)
		str[ii]=tolower(str[ii]);
	return str;
}

inline std::vector<std::string> split(std::string str,const std::string& delimeter)
{
	std::vector<std::string> tokens;
	std::string temp;

	if(str.size()<=0||delimeter.size()<=0)
		return tokens;

	while(str.size()>=delimeter.size())
	{
		if(str.substr(0,delimeter.size())==delimeter)
		{
			tokens.push_back(temp);
			str=str.substr(delimeter.size(),str.size()-delimeter.size());
			temp="";
			continue;
		}

		temp+=str[0];
		str=str.substr(1,str.size()-1);
	}

	tokens.push_back(temp);
	return tokens;
}

#endif