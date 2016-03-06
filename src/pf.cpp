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
	pre+=def_in+" out log all\n";
	pre+=def_out+" in  log all\n";
	return pre;
}

std::string post_rules(std::string def_out,std::string def_in)
{
	return "";
}

std::string gen_rule(std::string proto,
	std::string l_ip,std::string l_mask,std::string l_port,
	std::string dir,
	std::string f_ip,std::string f_mask,std::string f_port,
	std::string action,
	bool V6)
{
	std::string rule;
	if(action=="deny")
		rule+="block";
	else
		rule+="pass ";
	std::string dir_str=" out";
	if(dir=="<")
	{
		dir_str=" in ";
		std::swap(l_ip,f_ip);
		std::swap(l_mask,f_mask);
		std::swap(l_port,f_port);
	}
	rule+=dir_str;
	rule+=" log ";
	if(V6)
		rule+="inet6 ";
	else
		rule+="inet  ";
	rule+="proto "+proto;
	rule+=" from "+l_ip+"/"+l_mask;
	if(l_port!="0")
		rule+=" port "+l_port;
	rule+=" to "+f_ip+"/"+f_mask;
	if(f_port!="0")
		rule+=" port "+f_port;

	return rule;
}