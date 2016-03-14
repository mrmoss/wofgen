#include "parser.hpp"
#include <string>

std::string pre_rules(std::string def_out,std::string def_in)
{
	if(def_out=="deny")
		def_out="block";
	else
		def_out="pass ";
	if(def_in=="deny")
		def_in="block";
	else
		def_in="pass ";
	std::string pre;
	pre+="set skip on lo0\n";
	pre+=def_out+" out log all\n";
	pre+=def_in+" in  log all\n";
	return pre;
}

std::string post_rules(std::string def_out,std::string def_in)
{
	return "";
}

std::string gen_rule(wof_t wof)
{
	std::string rule;
	if(wof.action=="deny")
		rule+="block";
	else
		rule+="pass ";
	std::string dir_str=" out";
	if(wof.dir=="<")
	{
		dir_str=" in ";
		std::swap(wof.l_ip,wof.f_ip);
		std::swap(wof.l_mask,wof.f_mask);
		std::swap(wof.l_port,wof.f_port);
	}
	rule+=dir_str;
	rule+=" log quick ";
	if(wof.V6)
		rule+="inet6 ";
	else
		rule+="inet  ";
	rule+="proto "+wof.proto;
	rule+=" from "+wof.l_ip+"/"+wof.l_mask;
	if(wof.l_port!="0")
		rule+=" port "+wof.l_port;
	rule+=" to "+wof.f_ip+"/"+wof.f_mask;
	if(wof.f_port!="0")
		rule+=" port "+wof.f_port;

	return rule;
}