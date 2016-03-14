#include "parser.hpp"
#include <string>

std::string pre_rules(std::string def_out,std::string def_in)
{
	std::string pre;
	pre+="ufw --force disable\n";
	pre+="ufw --force reset\n";
	pre+="ufw logging on\n";
	pre+="ufw default "+def_out+" outgoing\n";
	pre+="ufw default "+def_in+" incoming\n";
	return pre;
}

std::string post_rules(std::string def_out,std::string def_in)
{
	return "ufw --force enable\n";
}

std::string gen_rule(wof_t wof)
{
	std::string rule;
	rule+="ufw ";
	if(wof.action=="deny")
		rule+="block";
	else
		rule+="allow";
	std::string dir_str=" out";
	if(wof.dir=="<")
	{
		dir_str=" in ";
		std::swap(wof.l_ip,wof.f_ip);
		std::swap(wof.l_mask,wof.f_mask);
		std::swap(wof.l_port,wof.f_port);
	}
	rule+=dir_str;
	rule+=" proto "+wof.proto;
	rule+=" from "+wof.l_ip+"/"+wof.l_mask;
	if(wof.l_port!="0")
		rule+=" port "+wof.l_port;
	rule+=" to "+wof.f_ip+"/"+wof.f_mask;
	if(wof.f_port!="0")
		rule+=" port "+wof.f_port;

	return rule;
}