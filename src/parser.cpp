#include "parser.hpp"

#include "parser_util.hpp"
#include <sstream>
#include <stdexcept>
#include "string_util.hpp"

extern std::string gen_rule(wof_t wof);

void wof_parse_line(std::string line,std::string& output,
	std::string& def_out,std::string& def_in)
{
	line=strip(split(strip(line),"#")[0]);

	if(line.size()>0)
	{
		if(!parse_def(line,def_out,def_in))
		{
			wof_t wof;
			bool was_any=false;
			wof.proto=parse_proto(line);
			bool l_v6=false;
			wof.l_ip=parse_ip(line,was_any,l_v6,"after proto");
			wof.l_mask=parse_subnet_mask(line,was_any,l_v6);
			wof.l_port=parse_port(line);
			wof.dir=parse_dir(line,"after local address");
			bool f_v6=false;
			wof.f_ip=parse_ip(line,was_any,f_v6,"after direction");
			if(l_v6!=f_v6)
				throw std::runtime_error("Local \""+wof.l_ip+
					"\" and foreign \""+wof.f_ip+
					"\" addresses must be of the same version.");
			wof.f_mask=parse_subnet_mask(line,was_any,f_v6);
			wof.f_port=parse_port(line);
			wof.action=parse_action(line,"after to IP address");
			wof.V6=(l_v6||f_v6);
			if(wof.proto=="any"||wof.proto=="tcp")
			{
				wof_t proto_copy=wof;
				proto_copy.proto="tcp";
				if(wof.dir=="<>"||wof.dir=="<")
				{
					wof_t dir_copy=proto_copy;
					dir_copy.dir="<";
					output+=gen_rule(dir_copy)+"\n";
				}
				if(wof.dir=="<>"||wof.dir==">")
				{
					wof_t dir_copy=proto_copy;
					dir_copy.dir=">";
					output+=gen_rule(dir_copy)+"\n";
				}
			}
			if(wof.proto=="any"||wof.proto=="udp")
			{
				wof_t proto_copy=wof;
				proto_copy.proto="udp";
				if(wof.dir=="<>"||wof.dir=="<")
				{
					wof_t dir_copy=proto_copy;
					dir_copy.dir="<";
					output+=gen_rule(dir_copy)+"\n";
				}
				if(wof.dir=="<>"||wof.dir==">")
				{
					wof_t dir_copy=proto_copy;
					dir_copy.dir=">";
					output+=gen_rule(dir_copy)+"\n";
				}
			}
		}
		if(line.size()>0)
			throw std::runtime_error("Unknown string \""+line+"\".");
	}
}