#include "parser.hpp"
#include <sstream>
#include <string>

static std::string to_string(const size_t val)
{
	std::ostringstream ostr;
	ostr<<val;
	return ostr.str();
}

static size_t rule_num=0;

std::string pre_rules(std::string def_out,std::string def_in)
{
	if(def_out=="deny")
		def_out="block";
	else
		def_out="allow";
	if(def_in=="deny")
		def_in="block";
	else
		def_in="allow";
	std::string pre;
	pre+="netsh advfirewall firewall set rule name=all profile=any new enable=no\n";
	pre+="netsh advfirewall firewall delete rule profile=any name=all\n";
	pre+="netsh advfirewall set allprofiles state on\n";
	pre+="netsh advfirewall set allprofiles firewallpolicy "+def_in+"inbound,"+def_out+"outbound\n";
	pre+="netsh advfirewall set allprofiles logging filename \"C:\\wof.log\"\n";
	return pre;
}

std::string post_rules(std::string def_out,std::string def_in)
{
	rule_num=0;
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
	rule+="netsh advfirewall firewall add rule profile=any ";
	rule+="name=\""+to_string(rule_num++)+"\"";
	if(wof.dir=="<")
		rule+=" dir=in ";
	else
		rule+=" dir=out";
	if(wof.action=="deny")
		rule+=" action=block";
	else
		rule+=" action=allow";
	rule+=" protocol="+wof.proto;
	if(wof.l_ip!="any")
		rule+=" localip="+wof.l_ip;
	if(wof.f_ip!="any")
		rule+=" remoteip="+wof.f_ip;
	if(wof.l_port!="0")
		rule+=" localport="+wof.l_port;
	if(wof.f_port!="0")
		rule+=" remoteport="+wof.f_port;
	return rule;
}
