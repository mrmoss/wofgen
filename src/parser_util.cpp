#include "parser_util.hpp"

#include <stdexcept>
#include "string_util.hpp"
#include <vector>

std::string parse_to_symbol(std::string& str,const std::string& symbol)
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

std::string parse_block(std::string& str)
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

std::string parse_string(std::string& str)
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

std::string parse_uint(std::string& str)
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

std::string parse_hex(std::string& str)
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

std::string parse_symbol(std::string& str)
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

std::string parse_symbol_throw(std::string& str,const std::string& symbol,const std::string& after)
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

std::string parse_proto(std::string& str)
{
	std::string proto=parse_block(str);
	if(to_lower(proto)!="tcp"&&to_lower(proto)!="udp"&&to_lower(proto)!="any")
		throw std::runtime_error("Unknown proto \""+proto+"\" (expected \"tcp\", \"udp\", or \"any\").");
	return to_lower(proto);
}

std::string parse_any(std::string& str,const std::string& value)
{
	if(to_lower(str.substr(0,3))=="any")
	{
		str.erase(0,3);
		return value;
	}
	return "";
}

void error_empty_ip(std::string& str,const std::string& ip,const std::string& ver,const std::string& err)
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

std::string parse_octet(std::string& str)
{
	std::string octet(parse_uint(str));
	if(octet=="")
		return "";
	if(to_int(octet)>255)
		throw std::runtime_error("Invalid octet "+octet+".");
	return octet;
}

std::string parse_hextet(std::string& str)
{
	std::string hextet(parse_hex(str));
	if(hextet=="")
		return "";
	if(hextet.size()>4||to_int("0x"+hextet)>65535)
		throw std::runtime_error("Invalid hextet "+hextet+".");
	return hextet;
}

std::string parse_ipv4(std::string& str,bool& was_any,const std::string& err)
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

void ipv6_invalid(const std::string& ip)
{
	throw std::runtime_error("Invalid IPv6 address \""+ip+"\".");
}

std::string parse_ipv6(std::string& str,bool& was_any,const std::string& err)
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

std::string parse_ip(std::string& str,bool& was_any,bool& v6,const std::string& err)
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

std::string parse_subnet_mask(std::string& str,const bool was_any,const bool v6)
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

std::string parse_port(std::string& str)
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

std::string parse_dir(std::string& str,const std::string& err)
{
	str=strip_start(str);
	std::string dir(str.substr(0,2));
	if(dir.size()==2&&ispunct(dir[1])==0)
		dir=dir.substr(0,1);
	if(dir.size()>0&&ispunct(dir[0])==0)
		dir="";
	if(dir=="")
		throw std::runtime_error("Expected \"<\", \"<>\", or \">\" "+err+".");
	if(dir!="<>"&&dir.substr(0,1)!="<"&&dir.substr(0,1)!=">")
		throw std::runtime_error("Expected \"<\", \"<>\", or \">\" got \""+dir+"\".");
	if(dir!="<>")
		dir=dir.substr(0,1);
	str.erase(0,dir.size());
	return dir;
}

std::string parse_action(std::string& str,const std::string& err)
{
	str=strip_start(str);
	std::string action(parse_string(str));
	if(action=="")
		throw std::runtime_error("Expected action "+err+".");
	if(to_lower(action)!="pass"&&to_lower(action)!="deny")
		throw std::runtime_error("Expected \"pass\" or \"deny\" got \""+action+"\".");
	return to_lower(action);
}

bool parse_def(std::string& str,std::string& def_out,std::string& def_in)
{
	std::string match("default");
	if(str.substr(0,match.size())==match)
	{
		str.erase(0,match.size());
		str=strip_start(str);
		std::string dir(parse_dir(str,"in default rule"));
		std::string action(parse_action(str,"in default rule"));
		if(dir=="<")
			def_in=action;
		else if(dir==">")
			def_out=action;
		else if(dir=="<>")
			def_in=def_out=action;
		return true;
	}
	return false;
}