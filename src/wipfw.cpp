#include "parser.hpp"
#include <string>

std::string pre_rules(std::string def_out,std::string def_in)
{
	std::string pre;
	pre+="-q -f flush\n";
	pre+="-q add check-state\n";
	pre+="-q add allow ip from any to any via lo0\n";
	if(def_out=="pass")
		pre+="-q add allow all from any to any out keep-state\n";
	if(def_in=="pass")
		pre+="-q add allow all from any to any in keep-state\n";
	return pre;
}

std::string post_rules(std::string def_out,std::string def_in)
{
	return "-q add deny log ip from any to any\n";
}

std::string gen_rule(wof_t wof)
{
	if(wof_is_any_ip(wof.l_ip,wof.l_mask,wof.V6))
		wof.l_ip="any";
	if(wof_is_any_ip(wof.f_ip,wof.f_mask,wof.V6))
		wof.f_ip="any";
	if(wof.l_mask!="0"&&!wof_is_exact_ip(wof.l_mask,wof.V6))
		wof.l_ip+="/"+wof.l_mask;
	if(wof.f_mask!="0"&&!wof_is_exact_ip(wof.f_mask,wof.V6))
		wof.f_ip+="/"+wof.f_mask;

	std::string rule;
	rule+="-q add ";
	if(wof.action=="deny")
		rule+="deny";
	else
		rule+="allow";
	rule+=" log ";
	std::string dir_str=" out";
	if(wof.dir=="<")
	{
		dir_str=" in ";
		std::swap(wof.l_ip,wof.f_ip);
		std::swap(wof.l_mask,wof.f_mask);
		std::swap(wof.l_port,wof.f_port);
	}
	rule+=wof.proto;
	rule+=" from "+wof.l_ip;
	if(wof.l_port!="0")
		rule+=" "+wof.l_port;
	rule+=" to "+wof.f_ip;
	if(wof.f_port!="0")
		rule+=" "+wof.f_port;
	rule+=dir_str;
	rule+=" keep-state";

	return rule;
}