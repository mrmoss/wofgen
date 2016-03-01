#include <iostream>
#include "ipaddr.hpp"
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc,char* argv[])
{
	try
	{
		std::vector<std::string> pass_tests;
			pass_tests.push_back("192.168.1.1/7");
			pass_tests.push_back("192.168.1.1/7:1,200,1024,65535");
			pass_tests.push_back("192.168.1.1/7:1");
			pass_tests.push_back("192.168.1.1/7:200");
			pass_tests.push_back("192.168.1.1/7:1024");
			pass_tests.push_back("192.168.1.1/7:65535");

			pass_tests.push_back("1:22:333:aaaa::c:d:e");
			pass_tests.push_back("1:22:333:aaaa::c:d:e:1,200,1024,65535");
			pass_tests.push_back("1:22:333:aaaa::c:d:e:1");
			pass_tests.push_back("1:22:333:aaaa::c:d:e:200");
			pass_tests.push_back("1:22:333:aaaa::c:d:e:1024");
			pass_tests.push_back("1:22:333:aaaa::c:d:e:65535");

			pass_tests.push_back("::e");
			pass_tests.push_back("::e:1");
			pass_tests.push_back("::e:200");
			pass_tests.push_back("::e:1024");

			pass_tests.push_back("any");
			pass_tests.push_back("any:1,200,1024,65535");
			pass_tests.push_back("any:1");
			pass_tests.push_back("any:200");
			pass_tests.push_back("any:1024");
			pass_tests.push_back("any:65535");

			pass_tests.push_back("::1");
			pass_tests.push_back("::1:1");
			pass_tests.push_back("::1:200");
			pass_tests.push_back("::1:1024");

			pass_tests.push_back("[::1]");
			pass_tests.push_back("[::1]:1,200,1024,65535");
			pass_tests.push_back("[::1]:1");
			pass_tests.push_back("[::1]:200");
			pass_tests.push_back("[::1]:1024");
			pass_tests.push_back("[::1]:65535");

			pass_tests.push_back("any/38");
			pass_tests.push_back("any/38:1,200,1024,65535");
			pass_tests.push_back("any/38:1");
			pass_tests.push_back("any/38:200");
			pass_tests.push_back("any/38:1024");
			pass_tests.push_back("any/38:65535");

			pass_tests.push_back("[any]");
			pass_tests.push_back("[any]:1,200,1024,65535");
			pass_tests.push_back("[any]:1");
			pass_tests.push_back("[any]:200");
			pass_tests.push_back("[any]:1024");
			pass_tests.push_back("[any]:65535");

			pass_tests.push_back("[any]/38");
			pass_tests.push_back("[any]/38:1,200,1024,65535");
			pass_tests.push_back("[any]/38:1");
			pass_tests.push_back("[any]/38:200");
			pass_tests.push_back("[any]/38:1024");
			pass_tests.push_back("[any]/38:65535");

			pass_tests.push_back("[any]/20");
			pass_tests.push_back("[any]/20:1,200,1024,65535");
			pass_tests.push_back("[any]/20:1");
			pass_tests.push_back("[any]/20:200");
			pass_tests.push_back("[any]/20:1024");
			pass_tests.push_back("[any]/20:65535");

			pass_tests.push_back("[::1]/24");
			pass_tests.push_back("[::1]/24:1,200,1024,65535");
			pass_tests.push_back("[::1]/24:1");
			pass_tests.push_back("[::1]/24:200");
			pass_tests.push_back("[::1]/24:1024");
			pass_tests.push_back("[::1]/24:65535");

			pass_tests.push_back("::1/24");
			pass_tests.push_back("::1/24:1,200,1024,65535");
			pass_tests.push_back("::1/24:1");
			pass_tests.push_back("::1/24:200");
			pass_tests.push_back("::1/24:1024");
			pass_tests.push_back("::1/24:65535");

			pass_tests.push_back("192.168.1.1");
			pass_tests.push_back("192.168.1.1:1,200,1024,65535");
			pass_tests.push_back("192.168.1.1:1");
			pass_tests.push_back("192.168.1.1:200");
			pass_tests.push_back("192.168.1.1:1024");
			pass_tests.push_back("192.168.1.1:65535");
			pass_tests.push_back("0.0.0.0");
			pass_tests.push_back("0.0.0.0:1,200,1024,65535");
			pass_tests.push_back("0.0.0.0:1");
			pass_tests.push_back("0.0.0.0:200");
			pass_tests.push_back("0.0.0.0:1024");
			pass_tests.push_back("0.0.0.0:65535");

		std::vector<std::string> fail_tests;
			fail_tests.push_back("[any");
			fail_tests.push_back("[any/");
			fail_tests.push_back("[any/30");
			fail_tests.push_back("[any/128");
			fail_tests.push_back("[::1");
			fail_tests.push_back("[::1/");
			fail_tests.push_back("[::1/30");
			fail_tests.push_back("[::1/128");
			fail_tests.push_back("any/");
			fail_tests.push_back("any/200");
			fail_tests.push_back("192.168.1.1/");
			fail_tests.push_back("192.168.1.1/33");
			fail_tests.push_back("192.168.1.1/200");
			fail_tests.push_back("255.255.255.255");
			fail_tests.push_back("255.255.255.255/20");
			fail_tests.push_back("255.255.255.255/32");
			fail_tests.push_back("255.255.255.255/35");
			fail_tests.push_back("[any]/");
			fail_tests.push_back("[any]/129");
			fail_tests.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
			fail_tests.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/30");
			fail_tests.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128");
			fail_tests.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/200");
			fail_tests.push_back("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]");
			fail_tests.push_back("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/30");
			fail_tests.push_back("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/128");
			fail_tests.push_back("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/200");
			fail_tests.push_back("::1::");
			fail_tests.push_back("[::1::]");
			fail_tests.push_back("::e:1,200,1024,65535");
			fail_tests.push_back("::e:65535");
			fail_tests.push_back("::1:1,200,1024,65535");
			fail_tests.push_back("::1:65535");

		for(size_t ii=0;ii<pass_tests.size();++ii)
			std::cout<<"|"<<pass_tests[ii]<<"|\t"<<ipaddr_t(pass_tests[ii]).str()<<std::endl;

		for(size_t ii=0;ii<fail_tests.size();++ii)
		{
			bool passed=false;
			try
			{
				ipaddr_t(fail_tests[ii]).str();
			}
			catch(...)
			{
				passed=true;
			}

			if(!passed)
				throw std::runtime_error("Expected \""+fail_tests[ii]+"\" to fail.");
		}

		std::cout<<"!!!!!!!!!PASSED!!!!!!!!!"<<std::endl;
		return 0;
	}
	catch(std::exception& error)
	{
		std::cout<<"Error - "<<error.what()<<std::endl;
		std::cout<<"!!!!!!!!!FAILED!!!!!!!!!"<<std::endl;
		return 1;
	}
	catch(...)
	{
		std::cout<<"Unknown error occurred."<<std::endl;
		std::cout<<"!!!!!!!!!FAILED!!!!!!!!!"<<std::endl;
		return 1;
	}
}