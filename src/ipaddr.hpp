//Windows Dependencies: -lWs2_32

#ifndef IPADDR_HPP
#define IPADDR_HPP

#include <stdint.h>
#include <string>

class ipaddr_t
{
	public:
		enum version_t
		{
			V4,
			V6
		};

		ipaddr_t(const std::string& ip);
		std::string str() const;

	private:
		uint8_t octets_m[16];
		uint8_t submask_arr_m[16];
		version_t version_m;
		int submask_m;

		bool parse_ip_m(const std::string& ip);
		bool validate_m() const;
};

#endif
