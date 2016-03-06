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

std::string gen_rule(std::string proto,
	std::string l_ip,std::string l_mask,std::string l_port,
	std::string dir,
	std::string f_ip,std::string f_mask,std::string f_port,
	std::string action,
	bool V6)
{
	std::string rule;
	rule+="ufw ";
	if(action=="deny")
		rule+="block";
	else
		rule+="allow";
	std::string dir_str=" out";
	if(dir=="<")
	{
		dir_str=" in ";
		std::swap(l_ip,f_ip);
		std::swap(l_mask,f_mask);
		std::swap(l_port,f_port);
	}
	rule+=dir_str;
	rule+=" proto "+proto;
	rule+=" from "+l_ip+"/"+l_mask;
	if(l_port!="0")
		rule+=" port "+l_port;
	rule+=" to "+f_ip+"/"+f_mask;
	if(f_port!="0")
		rule+=" port "+f_port;

	return rule;
}