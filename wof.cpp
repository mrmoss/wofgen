#include <cctype>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

extern std::string pre_rules();

extern std::string gen_rule(const std::string& proto,
	const std::string& l_ip,const std::string& l_mask,const std::string& l_port,
	const std::string& dir,
	const std::string& f_ip,const std::string& f_mask,const std::string& f_port,
	const std::string& action,
	const bool V6);

static inline int ishexdigit(int c)
{
	return (isdigit(c)!=0||(isalpha(c)!=0&&tolower(c)>='a'&&tolower(c)<='f'));
}

static inline std::vector<std::string> split(std::string str,const std::string& delimeter)
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

static inline std::string strip_start(std::string str)
{
	while(str.size()>0&&isspace(str[0])!=0)
		str.erase(0,1);
	return str;
}

static inline std::string strip_end(std::string str)
{
	while(str.size()>0&&isspace(str[str.size()-1])!=0)
		str.erase(str.size()-1,1);
	return str;
}

static inline std::string strip(std::string str)
{
	return strip_end(strip_start(str));
}

static inline std::string strip_all(std::string str)
{
	for(size_t ii=0;ii<str.size();++ii)
		if(isspace(str[ii])!=0)
			str.erase(ii--,1);
	return str;
}

static inline std::string to_lower(std::string str)
{
	for(size_t ii=0;ii<str.size();++ii)
		str[ii]=tolower(str[ii]);
	return str;
}

static inline std::string parse_to_symbol(std::string& str,const std::string& symbol)
{
	str=strip_start(str);
	std::string token;
	while(str.size()>0&&str.substr(0,1)!=symbol)
	{
		token+=str[0];
		str.erase(0,1);
	}
	return token;
}

static inline std::string parse_block(std::string& str)
{
	str=strip_start(str);
	std::string token;
	while(str.size()>0&&isspace(str[0])==0)
	{
		token+=str[0];
		str.erase(0,1);
	}
	return token;
}

static inline std::string parse_string(std::string& str)
{
	str=strip_start(str);
	std::string token;
	while(str.size()>0&&isalnum(str[0])!=0)
	{
		token+=str[0];
		str.erase(0,1);
	}
	return token;
}

static inline std::string parse_uint(std::string& str)
{
	str=strip_start(str);
	std::string token;
	while(str.size()>0&&isdigit(str[0])!=0)
	{
		token+=str[0];
		str.erase(0,1);
	}
	return token;
}

static inline std::string parse_hex(std::string& str)
{
	str=strip_start(str);
	std::string token;
	while(str.size()>0&&ishexdigit(str[0])!=0)
	{
		token+=str[0];
		str.erase(0,1);
	}
	return token;
}

static inline int to_int(const std::string& str)
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

static inline std::string parse_symbol(std::string& str)
{
	str=strip_start(str);
	if(str.size()>0&&ispunct(str[0])!=0)
	{
		std::string symbol(str.substr(0,1));
		str.erase(0,1);
		return symbol;
	}
	return "";
}

static inline std::string parse_symbol_throw(std::string& str,const std::string& symbol,const std::string& after="")
{
	std::string err="Expected \""+symbol+"\"";
	if(after.size()>0)
		err+=" after \""+after+"\"";
	if(str.size()>0&&isspace(str[0])==0&&str.substr(0,1)!=symbol)
		throw std::runtime_error(err+" but got \""+str[0]+"\".");
	std::string got(parse_symbol(str));
	if(got=="")
		throw std::runtime_error(err+".");
	if(got!=symbol)
		throw std::runtime_error(err+" but got \""+got+"\".");
	return got;
}

static inline std::string parse_proto(std::string& str)
{
	std::string proto=parse_block(str);
	if(to_lower(proto)!="tcp"&&to_lower(proto)!="udp")
		throw std::runtime_error("Unknown proto \""+proto+"\" (expected \"tcp\" or \"udp\").");
	return to_lower(proto);
}

static inline std::string parse_any(std::string& str,const std::string& value)
{
	if(to_lower(str.substr(0,3))=="any")
	{
		str.erase(0,3);
		return value;
	}
	return "";
}

static inline void error_empty_ip(std::string& str,const std::string& ip,const std::string& ver,const std::string& err="")
{
	if(ip!="")
		return;
	std::string next=parse_block(str).substr(0,1);
	if(next==""&&err.size()>0)
		throw std::runtime_error("Expected IP address "+err+".");
	else if(next=="")
		throw std::runtime_error("Expected IP address.");
	else
		throw std::runtime_error("Invalid symbol \""+next+"\" in IPv"+ver+" address.");
}

static inline std::string parse_octet(std::string& str)
{
	std::string octet(parse_uint(str));
	if(octet=="")
		return "";
	if(to_int(octet)>255)
		throw std::runtime_error("Invalid octet "+octet+".");
	return octet;
}

static inline std::string parse_hextet(std::string& str)
{
	std::string hextet(parse_hex(str));
	if(hextet=="")
		return "";
	if(hextet.size()>4||to_int("0x"+hextet)>65535)
		throw std::runtime_error("Invalid hextet "+hextet+".");
	return hextet;
}

static inline std::string parse_ipv4(std::string& str,bool& was_any,const std::string& err="")
{
	std::string ip=parse_any(str,"0.0.0.0");
	was_any=true;
	if(ip=="")
	{
		was_any=false;
		for(int ii=0;ii<4;++ii)
		{
			std::string octet(parse_octet(str));
			if(octet=="")
			{
				if(ip=="")
					break;
				throw std::runtime_error("Invalid IPv4 address \""+ip+"\".");
			}
			ip+=octet;
			if(ii<3)
				ip+=parse_symbol_throw(str,".");
		}
	}
	error_empty_ip(str,ip,"4",err);
	return ip;
}

static inline void ipv6_invalid(const std::string& ip)
{
	throw std::runtime_error("Invalid IPv6 address \""+ip+"\".");
}

static inline std::string parse_ipv6(std::string& str,bool& was_any,const std::string& err="")
{
	std::string ip=parse_any(str,"::");
	was_any=true;
	if(ip=="")
	{
		was_any=false;
		ip=parse_to_symbol(str,"]");
		if(ip.size()>0)
		{
			ip=strip_all(to_lower(ip));

			for(size_t ii=0;ii<ip.size();++ii)
				if(!ishexdigit(ip[ii])&&ip[ii]!=':')
					ipv6_invalid(ip);
		}
		std::vector<std::string> hextets(split(ip,":"));
		size_t empties=0;
		size_t hextet_count=0;
		for(size_t ii=0;ii<hextets.size();++ii)
			if(hextets[ii]=="")
				++empties;
			else if(hextets[ii]!="")
				++hextet_count;
		if(empties>3||(empties==3&&hextet_count>0))
			ipv6_invalid(ip);
		if((hextet_count<8&&empties<=0)||hextet_count>8)
			ipv6_invalid(ip);
		ip="";
		for(size_t ii=0;ii<hextets.size();++ii)
		{
			if(hextets[ii].size()>0)
				ip+=hextets[ii]=parse_hextet(hextets[ii]);
			if(ii+1<hextets.size())
				ip+=":";
		}

		if(empties>1&&ip.find("::",0)==std::string::npos)
			ipv6_invalid(ip);
	}
	error_empty_ip(str,ip,"6",err);
	parse_symbol_throw(str,"]",ip);
	return ip;
}

static inline std::string parse_ip(std::string& str,bool& was_any,bool& v6,const std::string& err="")
{
	std::string ip(parse_symbol(str));
	str=strip_start(str);
	if(ip=="[")
	{
		ip=parse_ipv6(str,was_any,err);
		v6=true;
	}
	else if(ip=="")
	{
		ip=parse_ipv4(str,was_any,err);
		v6=false;
	}
	else
	{
		throw std::runtime_error("Unexpected symbol \""+ip+"\".");
	}
	return ip;
}

static inline std::string parse_subnet_mask(std::string& str,const bool was_any,const bool v6)
{
	std::string mask(parse_symbol(str));
	str=strip_start(str);
	if(mask!="/")
	{
		str=mask+str;
		if(was_any)
			return "0";
		if(v6)
			return "128";
		return "32";
	}
	mask=parse_string(str);
	if(mask=="")
		throw std::runtime_error("Expected subnet mask after \"/\".");
	if(v6&&to_int(mask)>128)
		throw std::runtime_error("Invalid IPv6 subnet mask \""+mask+"\".");
	if(!v6&&to_int(mask)>32)
		throw std::runtime_error("Invalid IPv4 subnet mask \""+mask+"\".");
	return mask;
}

static inline std::string parse_port(std::string& str)
{
	std::string port(parse_symbol(str));
	str=strip_start(str);
	if(port!=":")
	{
		str=port+str;
		return "0";
	}
	port=parse_string(str);
	if(port=="")
		throw std::runtime_error("Expected port after \":\".");
	if(to_lower(port)=="any")
		return "0";
	if(to_int(port)>65535)
		throw std::runtime_error("Invalid port \""+port+"\".");
	return port;
}

static inline std::string parse_dir(std::string& str)
{
	str=strip_start(str);
	std::string dir(str.substr(0,2));
	if(dir.size()==2&&ispunct(dir[1])==0)
		dir=dir.substr(0,1);
	if(dir.size()>0&&ispunct(dir[0])==0)
		dir="";
	if(dir=="")
		throw std::runtime_error("Expected \"<\", \"<>\", or \">\" after local address.");
	if(dir!="<>"&&dir.substr(0,1)!="<"&&dir.substr(0,1)!=">")
		throw std::runtime_error("Expected \"<\", \"<>\", or \">\" got \""+dir+"\".");
	if(dir!="<>")
		dir=dir.substr(0,1);
	str.erase(0,dir.size());
	return dir;
}

static inline std::string parse_action(std::string& str)
{
	str=strip_start(str);
	std::string action(parse_string(str));
	if(action=="")
		throw std::runtime_error("Expected action after to IP address.");
	if(to_lower(action)!="pass"&&to_lower(action)!="deny")
		throw std::runtime_error("Expected \"pass\" or \"deny\" got \""+action+"\".");
	return to_lower(action);
}

int main()
{
	size_t lineno=0;
	try
	{
		std::vector<std::string> lines;
		std::string temp;
		while(true)
			if(getline(std::cin,temp))
				lines.push_back(split(strip(temp),"#")[0]);
			else if(std::cin.eof())
				break;
			else
				throw std::runtime_error("Error");

		std::string output(pre_rules()+"\n");
		for(lineno=0;lineno<lines.size();++lineno)
			if(lines[lineno].size()>0)
			{
				bool was_any=false;
				std::string proto(parse_proto(lines[lineno]));
				bool l_v6=false;
				std::string l_ip(parse_ip(lines[lineno],was_any,l_v6,"after proto"));
				std::string l_mask(parse_subnet_mask(lines[lineno],was_any,l_v6));
				std::string l_port(parse_port(lines[lineno]));
				std::string dir(parse_dir(lines[lineno]));
				bool f_v6=false;
				std::string f_ip(parse_ip(lines[lineno],was_any,f_v6,"after direction"));
				if(l_v6!=f_v6)
					throw std::runtime_error("Local \""+l_ip+"\" and foreign \""+f_ip+
						"\" addresses must be of the same version.");
				std::string f_mask(parse_subnet_mask(lines[lineno],was_any,f_v6));
				std::string f_port(parse_port(lines[lineno]));
				std::string action(parse_action(lines[lineno]));
				output+=gen_rule(proto,l_ip,l_mask,l_port,dir,f_ip,
					f_mask,f_port,action,(l_v6||f_v6))+"\n";
			}
		std::cout<<output<<std::flush;
	}
	catch(std::exception& error)
	{
		std::cout<<"Error line "<<lineno+1<<" - "<<error.what()<<std::endl;
		return 1;
	}
	catch(...)
	{
		std::cout<<"Error line "<<lineno+1<<" - Unknown exception."<<std::endl;
		return 1;
	}

	return 0;
}