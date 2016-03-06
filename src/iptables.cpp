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

std::string gen_rule(std::string proto,
	std::string l_ip,std::string l_mask,std::string l_port,
	std::string dir,
	std::string f_ip,std::string f_mask,std::string f_port,
	std::string action,
	bool V6)
{
	std::string rule;
	if(V6)
		rule+="ip6tables";
	else
		rule+="iptables";
	rule+=" --append ";
	std::string dir_str="OUTPUT";
	std::string l_letter="s";
	std::string f_letter="d";
	if(dir=="<")
	{
		dir_str="INPUT ";
		std::swap(l_letter,f_letter);
	}
	rule+=dir_str;
	rule+=" -p "+proto;
	rule+=" -" +l_letter+" "    +l_ip+"/"+l_mask;

	if(l_port!="0")
		rule+=" --"+l_letter+"port "+l_port;
	rule+=" -" +f_letter+" "    +f_ip+"/"+f_mask;
	if(f_port!="0")
		rule+=" --"+f_letter+"port "+f_port;
	rule+=" --jump ";
	if(action=="deny")
		rule+="DROP";
	else
		rule+="ACCEPT";
	return rule;
}