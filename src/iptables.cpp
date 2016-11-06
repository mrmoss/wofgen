#include "parser.hpp"
#include <string>

std::string pre_rules(std::string def_out,std::string def_in)
{
	if(def_out=="deny")
		def_out="DROP";
	else
		def_out="ACCEPT";
	if(def_in=="deny")
		def_in="DROP";
	else
		def_in="ACCEPT";
	std::string pre;
	pre+="iptables -F\n";
	pre+="ip6tables -F\n";
	pre+="iptables -X\n";
	pre+="ip6tables -X\n";
	pre+="iptables -P FORWARD DROP\n";
	pre+="ip6tables -P FORWARD DROP\n";
	pre+="iptables -P OUTPUT "+def_out+"\n";
	pre+="ip6tables -P OUTPUT "+def_out+"\n";
	pre+="iptables -P INPUT "+def_in+"\n";
	pre+="ip6tables -P INPUT "+def_in+"\n";
	pre+="iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n";
	pre+="ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n";
	pre+="iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT\n";
	pre+="ip6tables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT\n";
	pre+="iptables -A INPUT -i lo -j ACCEPT\n";
	pre+="ip6tables -A INPUT -i lo -j ACCEPT\n";
	pre+="iptables -A OUTPUT -o lo -j ACCEPT\n";
	pre+="ip6tables -A OUTPUT -o lo -j ACCEPT\n";
	return pre;
}

std::string post_rules(std::string def_out,std::string def_in)
{
	if(def_out=="deny")
		def_out="DROP";
	else
		def_out="ACCEPT";
	if(def_in=="deny")
		def_in="DROP";
	else
		def_in="ACCEPT";
	std::string post;
	post+="iptables -N LOG_OUT\n";
	post+="ip6tables -N LOG_OUT\n";
	post+="iptables -N LOG_IN\n";
	post+="ip6tables -N LOG_IN\n";
	post+="iptables -A OUTPUT -j LOG_OUT\n";
	post+="ip6tables -A OUTPUT -j LOG_OUT\n";
	post+="iptables -A INPUT -j LOG_IN\n";
	post+="ip6tables -A INPUT -j LOG_IN\n";
	post+="iptables -A LOG_OUT -m limit --limit 2/min -j LOG --log-prefix \"iptables-out: \" --log-level 4\n";
	post+="ip6tables -A LOG_OUT -m limit --limit 2/min -j LOG --log-prefix \"ip6tables-out: \" --log-level 4\n";
	post+="iptables -A LOG_IN -m limit --limit 2/min -j LOG --log-prefix \"iptables-in: \" --log-level 4\n";
	post+="ip6tables -A LOG_IN -m limit --limit 2/min -j LOG --log-prefix \"ip6tables-in: \" --log-level 4\n";
	post+="iptables -A LOG_OUT -j "+def_out+"\n";
	post+="ip6tables -A LOG_OUT -j "+def_out+"\n";
	post+="iptables -A LOG_IN -j "+def_in+"\n";
	post+="ip6tables -A LOG_IN -j "+def_in+"\n";
	return post;
}

std::string gen_rule(wof_t wof)
{
	std::string rule;
	if(wof.V6)
		rule+="ip6tables";
	else
		rule+="iptables";
	rule+=" --append ";
	std::string dir_str="OUTPUT";
	std::string l_letter="s";
	std::string f_letter="d";
	if(wof.dir=="<")
	{
		dir_str="INPUT ";
		std::swap(l_letter,f_letter);
	}
	rule+=dir_str;
	rule+=" -p "+wof.proto;
	rule+=" -" +l_letter+" "    +wof.l_ip+"/"+wof.l_mask;

	if(wof.l_port!="0")
		rule+=" --"+l_letter+"port "+wof.l_port;
	rule+=" -" +f_letter+" "    +wof.f_ip+"/"+wof.f_mask;
	if(wof.f_port!="0")
		rule+=" --"+f_letter+"port "+wof.f_port;
	rule+=" --jump ";
	if(wof.action=="deny")
		rule+="DROP";
	else
		rule+="ACCEPT";
	return rule;
}