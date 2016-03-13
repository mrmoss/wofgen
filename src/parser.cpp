#include "parser.hpp"

#include "parser_util.hpp"
#include <sstream>
#include <stdexcept>
#include "string_util.hpp"

extern std::string gen_rule(std::string proto,
	std::string l_ip,std::string l_mask,std::string l_port,
	std::string dir,
	std::string f_ip,std::string f_mask,std::string f_port,
	std::string action,
	bool V6);

void wof_parse_line(std::string line,std::string& output,
	std::string& def_out,std::string& def_in)
{
	line=split(strip(line),"#")[0];

	if(line.size()>0)
	{
		if(!parse_def(line,def_out,def_in))
		{
			bool was_any=false;
			std::string proto(parse_proto(line));
			bool l_v6=false;
			std::string l_ip(parse_ip(line,was_any,l_v6,"after proto"));
			std::string l_mask(parse_subnet_mask(line,was_any,l_v6));
			std::string l_port(parse_port(line));
			std::string dir(parse_dir(line,"after local address"));
			bool f_v6=false;
			std::string f_ip(parse_ip(line,was_any,f_v6,"after direction"));
			if(l_v6!=f_v6)
				throw std::runtime_error("Local \""+l_ip+"\" and foreign \""+f_ip+
					"\" addresses must be of the same version.");
			std::string f_mask(parse_subnet_mask(line,was_any,f_v6));
			std::string f_port(parse_port(line));
			std::string action(parse_action(line,"after to IP address"));
			if(dir=="<>")
			{
				output+=gen_rule(proto,l_ip,l_mask,l_port,"<",f_ip,
					f_mask,f_port,action,(l_v6||f_v6))+"\n";
				output+=gen_rule(proto,l_ip,l_mask,l_port,">",f_ip,
					f_mask,f_port,action,(l_v6||f_v6))+"\n";
			}
			else
			{
				output+=gen_rule(proto,l_ip,l_mask,l_port,dir,f_ip,
					f_mask,f_port,action,(l_v6||f_v6))+"\n";
			}
		}
		if(line.size()>0)
			throw std::runtime_error("Unknown string \""+line+"\".");
	}
}