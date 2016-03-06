#include <string>

std::string pre_rules()
{
	std::string pre;
	pre+="-q -f flush\n";
	pre+="-q add check-state\n";
	pre+="-q add allow ip from any to any via lo0\n";
	return pre;
}

std::string post_rules()
{
	return "-q add deny log ip from any to any\n";
}

std::string gen_rule(std::string proto,
	std::string l_ip,std::string l_mask,std::string l_port,
	std::string dir,
	std::string f_ip,std::string f_mask,std::string f_port,
	std::string action,
	bool V6)
{
	std::string rule;
	rule+="-q add ";
	if(action=="deny")
		rule+="deny";
	else
		rule+="allow";
	rule+=" log ";
	std::string dir_str=" out";
	if(dir=="<")
	{
		dir_str=" in ";
		std::swap(l_ip,f_ip);
		std::swap(l_mask,f_mask);
		std::swap(l_port,f_port);
	}
	rule+=proto;
	rule+=" from "+l_ip+"/"+l_mask;
	if(l_port!="0")
		rule+=" "+l_port;
	rule+=" to "+f_ip+"/"+f_mask;
	if(f_port!="0")
		rule+=" "+f_port;
	rule+=dir_str;
	rule+=" keep-state";

	return rule;
}