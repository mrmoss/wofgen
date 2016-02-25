#ifndef IPADDR_HPP
#define IPADDR_HPP

#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include "string_util.hpp"

#include <iostream>

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

			if(str!="any"&&!from_ipv4_m(str))//&&!from_ipv6_m(str))
				throw std::runtime_error("\""+ip+"\" is not a valid address.");
		}

	private:
		uint8_t octets_m[16];
		uint8_t submask_m[16];
		version_t version_m;

		bool from_ipv4_m(const std::string& ip)
		{
			int octets[4];
			int submask=32;
			int copied=sscanf(ip.c_str(),"%d.%d.%d.%d/%d",
				octets+0,octets+1,octets+2,octets+3,&submask);

			if(copied!=4&&copied!=5)
				return false;
			for(int ii=0;ii<4;++ii)
				if(octets[ii]>255||octets[ii]<0)
					return false;
			if(submask<0||submask>32)
				return false;

			std::ostringstream ostr;

			for(int ii=0;ii<4;++ii)
			{
				ostr<<octets[ii];
				if(ii<3)
					ostr<<".";
			}
			if(copied==5)
				ostr<<"/"<<submask;
			if(ostr.str()!=ip)
				return false;

			submask_from_int_m(submask);

			for(int ii=0;ii<4;++ii)
				octets_m[ii]=(uint8_t)octets[ii];

			version_m=V4;
			return true;
		}

		void submask_from_int_m(const int mask)
		{
			memset(submask_m,0xff,mask/8);
			for(int ii=0;ii<mask%8;++ii)
				submask_m[mask/8]|=(1<<(7-ii));
		}
};

#endif