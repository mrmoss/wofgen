#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "parser.hpp"

extern std::string pre_rules(std::string def_out,std::string def_in);
extern std::string post_rules(std::string def_out,std::string def_in);

static inline void show_help()
{
	std::string name("PROG");
	#if(defined(WOF_IPFW))
		name="ipfw";
	#elif(defined(WOF_IPTABLES))
		name="iptables";
	#elif(defined(WOF_NETSH))
		name="netsh";
	#elif(defined(WOF_PF))
		name="pf";
	#elif(defined(WOF_UFW))
		name="ufw";
	#elif(defined(WOF_WIPFW))
		name="wipfw";
	#endif
	std::cerr<<"  Usage: ./wof_"<<name<<" [FILE]"<<std::endl;
	std::cerr<<"  If no rules file is provided, rules will be read from stdin."<<std::endl;
}

int main(int argc,char* argv[])
{
	std::cerr<<"Walls of Fire"<<std::endl;
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
		std::vector<std::string> lines;
		std::string temp;
		while(true)
			if(getline(*istr,temp))
				lines.push_back(temp);
			else
				break;
		fstr.close();
		std::string def_out;
		std::string def_in;
		std::string output;
		for(lineno=0;lineno<(int)lines.size();++lineno)
			wof_parse_line(lines[lineno],output,def_out,def_in);
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
