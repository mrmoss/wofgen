#include "string_util.hpp"

#include <sstream>
#include <stdexcept>

int ishexdigit(int c)
{
	return (isdigit(c)!=0||(isalpha(c)!=0&&tolower(c)>='a'&&tolower(c)<='f'));
}

std::vector<std::string> split(std::string str,const std::string& delimeter)
{
	std::vector<std::string> tokens;
	std::string temp;
	if(str.size()<=0||delimeter.size()<=0)
	{
		tokens.push_back(str);
		return tokens;
	}
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

std::string strip_start(std::string str)
{
	while(str.size()>0&&(isspace(str[0])!=0||str[0]<0))
		str=str.substr(1,str.size());
	return str;
}

std::string strip_end(std::string str)
{
	while(str.size()>0&&(isspace(str[str.size()-1])!=0||str[str.size()-1]<0))
		str=str.substr(0,str.size()-1);
	return str;
}

std::string strip(std::string str)
{
	return strip_end(strip_start(str));
}

std::string strip_all(std::string str)
{
	for(size_t ii=0;ii<str.size();++ii)
		if(isspace(str[ii])!=0||str[ii]<0)
			str.erase(ii--,1);
	return str;
}

std::string to_lower(std::string str)
{
	for(size_t ii=0;ii<str.size();++ii)
		str[ii]=tolower(str[ii]);
	return str;
}

int to_int(const std::string& str)
{
	std::istringstream istr(str);
	int x;
	if(str.substr(0,2)=="0x")
	{
		if(!(istr>>std::hex>>x))
			throw std::runtime_error("\""+str+"\" is not an integer.");
	}
	else
	{
		if(!(istr>>x))
			throw std::runtime_error("\""+str+"\" is not an integer.");
	}
	return x;
}