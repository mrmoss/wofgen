//Windows Dependencies: -lWs2_32

#include "ipaddr.hpp"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include "string_util.hpp"

#if(defined(WIN32)||defined(_WIN32)||defined(__WIN32__)||defined(__CYGWIN__))
	#include <windows.h>
	#include <Winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif

#define MAX_IP_LEN 300

ipaddr_t::ipaddr_t(const std::string& ip):version_m(V4),submask_m(-1)
{
	//initialize
	std::string str(ip);
	bool was_any=false;
	memset(octets_m,0,16);
	memset(submask_arr_m,0,16);

	//lowercase no whitespace
	str=to_lower(strip(str));

	//match a port list
	std::string ports=match_port_list_m(str);
	str.resize(str.size()-ports.size());

	//V6 port lists are strange...if the address was V4, any, wrapped in [], or had a subnet mask, its good...
	bool found_non=false;
	for(size_t ii=0;ii<str.size()&&!found_non;++ii)
		if(str[ii]=='a'||str[ii]=='n'||str[ii]=='y'||str[ii]=='/'||str[ii]=='['||str[ii]==']'||str[ii]=='.')
			found_non=true;

	//if it didn't have the above...then assume it wasn't a port list...
	if(!found_non)
	{
		str+=ports;
		ports="";
	}

	//split on '/' for subnet mask
	std::vector<std::string> parts=split(str,"/");

	//1 or 2 parts (ip or (ip and subnet mask))
	if(parts.size()>=1||parts.size()<=2)
	{
		//set str to ip
		str=parts[0];

		//parse subnet mask
		if(parts.size()==2)
			submask_m=str_to_int(parts[1]);

		//store if any to determine if V4 or V6 later
		if(str=="any")
			was_any=true;

		//specified V6 any
		if(str=="[any]")
			version_m=V6;

		//if not an any or not an ip, bad ip
		if(str!="any"&&str!="[any]"&&!parse_ip_m(str))
			throw std::runtime_error("\""+ip+"\" is not a valid ip address.");

		//no mask specified, assume the full address
		if(submask_m==-1&&version_m==V4)
			submask_m=32;
		else if(submask_m==-1&&version_m==V6)
			submask_m=128;

		//any and subnet mask in V6 range, set V6
		if(submask_m>32&&was_any)
			version_m=V6;

		//invalid subnet mask check
		if((submask_m>32&&version_m==V4)||(submask_m>128&&version_m==V6))
			throw std::runtime_error("/"+to_string(submask_m)+" is not a valid subnet mask.");

		//store array version of subnet mask (unused currently)
		memset(submask_arr_m,0xff,submask_m/8);
		for(int ii=0;ii<submask_m%8;++ii)
			submask_arr_m[submask_m/8]|=(1<<(7-ii));

		//parse port list
		parse_port_list_m(ip,ports);
	}
}

std::string ipaddr_t::str() const
{
	std::string ip;
	ip.resize(MAX_IP_LEN,'\0');
	std::ostringstream ostr;
	bool converted=false;

	#if(defined(WIN32)||defined(_WIN32)||defined(__WIN32__)||defined(__CYGWIN__))
		sockaddr_in ip_addr;
		sockaddr_in6 ip6_addr;
		ip_addr.sin_family=AF_INET;
		ip_addr.sin_port=0;
		ip6_addr.sin6_family=AF_INET6;
		ip6_addr.sin6_port=0;
		ip6_addr.sin6_scope_id=0;
		memcpy(&ip_addr.sin_addr,octets_m,4);
		memcpy(&ip6_addr.sin6_addr,octets_m,16);
		DWORD len=MAX_IP_LEN;
		WSADATA temp;
		WSAStartup(0x0002,&temp);

		if(version_m==V4&&WSAAddressToString((sockaddr*)&ip_addr,sizeof(ip_addr),NULL,(char*)ip.c_str(),&len)==0&&len-1>0)
		{
			ip.resize(len-1);
			converted=true;
		}
		else if(version_m==V6&&WSAAddressToString((sockaddr*)&ip6_addr,sizeof(ip6_addr),NULL,(char*)ip.c_str(),&len)==0&&len-1>0)
		{
			ip.resize(len-1);
			converted=true;
		}
	#else
		if(version_m==V4&&inet_ntop(AF_INET,octets_m,(char*)ip.c_str(),MAX_IP_LEN)!=NULL)
			converted=true;
		else if(version_m==V6&&inet_ntop(AF_INET6,octets_m,(char*)ip.c_str(),MAX_IP_LEN)!=NULL)
			converted=true;
	#endif

	if(!converted)
		throw std::runtime_error("Could not convert ip to a string.");

	ip=trim(ip);

	if(version_m==V6)
		ostr<<'['<<ip<<']';
	else
		ostr<<ip;

	ostr<<"/"<<to_string(submask_m);

	return ostr.str();
}

bool ipaddr_t::parse_ip_m(const std::string& ip)
{
	std::string ip_copy(ip);
	std::string ip_str;
	ip_str.resize(MAX_IP_LEN);

	if(ip_copy.size()>=2&&ip_copy[0]=='['&&ip_copy[ip_copy.size()-1]==']')
	{
		version_m=V6;
		ip_copy=ip_copy.substr(1,ip_copy.size()-2);
	}

	#if(defined(WIN32)||defined(_WIN32)||defined(__WIN32__)||defined(__CYGWIN__))
		sockaddr_in ip_addr;
		sockaddr_in6 ip6_addr;
		int len=MAX_IP_LEN;
		WSADATA temp;
		WSAStartup(0x0002,&temp);

		if(version_m==V4&&WSAStringToAddress((char*)ip_copy.c_str(),AF_INET,NULL,(sockaddr*)&ip_addr,&len)==0)
		{
			version_m=V4;
			memset(octets_m,0,16);
			memcpy(octets_m,&ip_addr.sin_addr,4);
			return validate_m();
		}
		else if((WSAGetLastError()==WSAEINVAL||version_m==V6)&&WSAStringToAddress((char*)ip_copy.c_str(),AF_INET6,NULL,(sockaddr*)&ip6_addr,&len)==0)
		{
			version_m=V6;
			memcpy(octets_m,&ip6_addr.sin6_addr,16);
			return validate_m();
		}
		else if(WSAGetLastError()==WSAEINVAL)
			return false;
		else
			throw std::runtime_error("Windows failed to parse \""+ip+"\".");
	#else
		in_addr ip_addr;
		in6_addr ip6_addr;

		if(version_m==V4&&inet_pton(AF_INET,ip_copy.c_str(),&ip_addr)==1)
		{
			version_m=V4;
			memset(octets_m,0,16);
			memcpy(octets_m,&ip_addr,4);
			return validate_m();
		}
		else if(inet_pton(AF_INET6,ip_copy.c_str(),&ip6_addr)==1)
		{
			version_m=V6;
			memcpy(octets_m,&ip6_addr,16);
			return validate_m();
		}
	#endif

	return false;
}

std::string ipaddr_t::match_port_list_m(const std::string& str)
{
	std::string list;
	if(str.size()==0)
		return list;
	size_t ptr=str.size()-1;

	while(true)
	{
		if(isdigit(str[ptr])!=0||str[ptr]==','||str[ptr]=='-')
		{
			--ptr;
		}
		else
		{
			if(str[ptr]!=':')
				ptr=str.size();
			break;
		}

		if(ptr==0)
		{
			ptr=str.size();
			break;
		}
	}

	list=str.substr(ptr,str.size()-ptr);
	return list;
}

void ipaddr_t::parse_port_list_m(const std::string& ip,std::string ports)
{
	if(ports.size()==0)
		return;

	std::string error_str("\""+ip+"\" has an invalid port list.");
	std::vector<int> port_list_parsed;

	if(ports[0]!=':')
		throw std::runtime_error(error_str);

	ports=ports.substr(1,ports.size());
	std::vector<std::string> port_list=split(ports,",");

	for(size_t ii=0;ii<port_list.size();++ii)
	{
		int start=-1;
		int end=-1;
		int count=sscanf(port_list[ii].c_str(),"%d-%d",&start,&end);

		if(count==1&&start>0&&start<65536)
			port_list_parsed.push_back(start);
		else if(count==2&&start<=end&&start>0&&start<65536&&end>0&&end<65536)
			for(int ii=start;ii<=end;++ii)
				port_list_parsed.push_back(ii);
		else
			throw std::runtime_error(error_str);
	}

	ports_m=port_list_parsed;
}

bool ipaddr_t::validate_m() const
{
	bool broadcast=true;
	for(int ii=0;((version_m==V4&&ii<4)||(version_m==V6&&ii<16))&&broadcast;++ii)
		if((int)octets_m[ii]!=255)
			broadcast=false;
	return !broadcast;
}