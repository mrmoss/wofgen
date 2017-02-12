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
	pre+="#Usually goes in: /etc/ipf/ipf.conf\n";
	pre+="#You may need to enable the firewall service: svcadm enable ipfilter\n";
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
	if(wof_is_any_ip(wof.l_ip,wof.l_mask,wof.V6))
		wof.l_ip="any";
	if(wof_is_any_ip(wof.f_ip,wof.f_mask,wof.V6))
		wof.f_ip="any";
	if(wof.l_mask!="0"&&!wof_is_exact_ip(wof.l_mask,wof.V6))
		wof.l_ip+="/"+wof.l_mask;
	if(wof.f_mask!="0"&&!wof_is_exact_ip(wof.f_mask,wof.V6))
		wof.f_ip+="/"+wof.f_mask;

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
	rule+="proto "+wof.proto;

	if(wof.l_ip!="any"||wof.l_port!="0")
		rule+=" from";
	if(wof.l_ip!="any")
		rule+=" "+wof.l_ip;
	if(wof.l_port!="0")
		rule+=" port="+wof.l_port;

	if(wof.f_ip!="any"||wof.f_port!="0")
		rule+=" to";
	if(wof.f_ip!="any")
		rule+=" "+wof.f_ip;
	if(wof.f_port!="0")
		rule+=" port="+wof.f_port;
	rule+=" keep state";

	return rule;
}