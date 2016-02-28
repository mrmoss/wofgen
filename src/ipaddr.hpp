#ifndef IPADDR_HPP
#define IPADDR_HPP

#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include "string_util.hpp"

#if(defined(WIN32)||defined(_WIN32)||defined(__WIN32__)||defined(__CYGWIN__))
	#include <windows.h>
	#include <Winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif

#define MAX_IP_LEN 300

class ipaddr_t
{
	public:
		enum version_t
		{
			V4,
			V6
		};

		ipaddr_t(const std::string& ip):version_m(V4)
		{
			std::string str(ip);
			memset(octets_m,0,16);
			memset(submask_m,0,16);
			str=to_lower(strip(str));
			if(str!="any"&&!parse_ip_m(str))
				throw std::runtime_error("\""+ip+"\" is not a valid ip address.");
		}

		std::string str() const
		{
			std::string ip;
			ip.resize(MAX_IP_LEN);

			if(version_m==V4&&inet_ntop(AF_INET,octets_m,(char*)ip.c_str(),MAX_IP_LEN)!=NULL)
				return ip;
			if(version_m==V6&&inet_ntop(AF_INET6,octets_m,(char*)ip.c_str(),MAX_IP_LEN)!=NULL)
				return ip;

			throw std::runtime_error("Could not convert ip to a string.");
		}

	private:
		uint8_t octets_m[16];
		uint8_t submask_m[16];
		version_t version_m;

		bool parse_ip_m(const std::string& ip)
		{
			std::string ip_str;
			ip_str.resize(MAX_IP_LEN);

			#if(defined(WIN32)||defined(_WIN32)||defined(__WIN32__)||defined(__CYGWIN__))
				sockaddr_in ip_addr;
				sockaddr_in6 ip6_addr;
				int len=MAX_IP_LEN;
				WSADATA temp;
				WSAStartup(0x0002,&temp);

				if(WSAStringToAddress((char*)ip.c_str(),AF_INET,NULL,(sockaddr*)&ip_addr,&len)==0)
				{
					version_m=V4;
					memset(octets_m,0,16);
					for(int ii=0;ii<4;++ii)
						octets_m[ii]=((uint8_t*)&ip_addr.sin_addr)[ii];
					return true;
				}
				else if(WSAGetLastError()==WSAEINVAL&&
					WSAStringToAddress((char*)ip.c_str(),AF_INET6,NULL,(sockaddr*)&ip6_addr,&len)==0)
				{
					version_m=V6;
					memset(octets_m,0,16);
					for(int ii=0;ii<16;++ii)
						octets_m[ii]=((uint8_t*)&ip6_addr.sin6_addr)[ii];
					return true;
				}
				else if(WSAGetLastError()==WSAEINVAL)
					return false;
				else
					throw std::runtime_error("Windows failed to parse \""+ip+"\".");
			#else
				in_addr ip_addr;
				in6_addr ip6_addr;

				if(inet_pton(AF_INET,ip.c_str(),&ip_addr)==1)
				{
					version_m=V4;
					memset(octets_m,0,16);
					for(int ii=0;ii<4;++ii)
						octets_m[ii]=((uint8_t*)&ip_addr)[ii];
					return true;
				}
				else if(inet_pton(AF_INET6,ip.c_str(),&ip6_addr)==1)
				{
					version_m=V6;
					memset(octets_m,0,16);
					for(int ii=0;ii<16;++ii)
						octets_m[ii]=((uint8_t*)&ip6_addr)[ii];
					return true;
				}
			#endif

			return false;
		}

		void submask_from_int_m(const int mask)
		{
			memset(submask_m,0xff,mask/8);
			for(int ii=0;ii<mask%8;++ii)
				submask_m[mask/8]|=(1<<(7-ii));
		}
};

#endif
