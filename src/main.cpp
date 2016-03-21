#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "parser.hpp"

extern std::string pre_rules(std::string def_out,std::string def_in);
extern std::string post_rules(std::string def_out,std::string def_in);

void show_help()
{
	std::string name("PROG");
	#if(defined(WOFGEN_IPFW))
		name="ipfw";
	#elif(defined(WOFGEN_IPTABLES))
		name="iptables";
	#elif(defined(WOFGEN_NETSH))
		name="netsh";
	#elif(defined(WOFGEN_PF))
		name="pf";
	#elif(defined(WOFGEN_UFW))
		name="ufw";
	#elif(defined(WOFGEN_WIPFW))
		name="wipfw";
	#endif
	std::cerr<<"  Usage: ./wofgen_"<<name<<" [FILE]"<<std::endl;
	std::cerr<<"  If no rules file is provided, rules will be read from stdin."<<std::endl;
}

int main(int argc,char* argv[])
{
	std::cerr<<"Walls of Fire - Universal firewall configuration generator."<<std::endl;
	std::istream* istr=&std::cin;
	std::ifstream fstr;
	int lineno=0;
	try
	{
		if(argc>1)
		{
			fstr.open(argv[1]);
			if(!fstr)
				throw std::runtime_error("Could not open file \""+std::string(argv[1])+"\".");
			istr=&fstr;
		}
		std::string temp;
		std::string def_out;
		std::string def_in;
		std::string output;
		while(true)
		{
			if(getline(*istr,temp))
			{
				wof_parse_line(temp,output,def_out,def_in);
				++lineno;
			}
			else
			{
				break;
			}
		}
		fstr.close();
		if(def_out.size()==0&&def_in.size()==0&&output.size()==0)
		{
			lineno=-1;
			throw std::runtime_error("No rules found.");
		}
		if(def_out.size()==0)
			def_out="deny";
		if(def_in.size()==0)
			def_in="deny";
		output=pre_rules(def_out,def_in)+output+post_rules(def_out,def_in);
		std::cout<<output<<std::flush;
	}
	catch(std::exception& error)
	{
		if(lineno>=0)
			std::cerr<<"Error line "<<lineno+1<<" - "<<error.what()<<std::endl;
		else
			std::cerr<<"Error - "<<error.what()<<std::endl;
		show_help();
		return 1;
	}
	catch(...)
	{
		if(lineno>=0)
			std::cerr<<"Error line "<<lineno+1<<" - Unknown exception."<<std::endl;
		else
			std::cerr<<"Error - Unknown exception."<<std::endl;
		show_help();
		return 1;
	}

	return 0;
}
