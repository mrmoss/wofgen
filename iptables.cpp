#include <string>

std::string pre_rules()
{
	std::string pre;
	pre+="iptables -F\n";
	pre+="iptables -X\n";
	pre+="\n";
	pre+="iptables -P INPUT DROP\n";
	pre+="iptables -P FORWARD DROP\n";
	pre+="iptables -P OUTPUT DROP\n";
	pre+="\n";
	pre+="iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n";
	return pre;
}

std::string gen_rule(const std::string& proto,
	const std::string& l_ip,const std::string& l_mask,const std::string& l_port,
	const std::string& dir,
	const std::string& f_ip,const std::string& f_mask,const std::string& f_port,
	const std::string& action,
	const bool V6)
{

	if(dir=="<>")
	{
		std::string rules;
		rules+=gen_rule(proto,l_ip,l_mask,l_port,"<",f_ip,f_mask,f_port,action,V6);
		rules+="\n";
		rules+=gen_rule(proto,l_ip,l_mask,l_port,">",f_ip,f_mask,f_port,action,V6);
		return rules;
	}

	std::string rule;
	if(V6)
		rule+="ip6tables";
	else
		rule+="iptables";
	rule+=" --append ";
	std::string l_letter="s";
	std::string f_letter="d";
	if(dir=="<")
	{
		rule+="INPUT ";
		std::swap(l_letter,f_letter);
	}
	else
		rule+="OUTPUT";
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

//iptables --append INPUT  -p tcp -d any --dport 20 -s any --sport any --jump ACCEPT