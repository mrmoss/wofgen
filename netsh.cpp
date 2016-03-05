#include <sstream>
#include <string>

static std::string to_string(const size_t val)
{
	std::ostringstream ostr;
	ostr<<val;
	return ostr.str();
}

static size_t rule_num=0;

std::string pre_rules()
{
	std::string pre;
	pre+="netsh advfirewall set all state on\n";
	pre+="netsh advfirewall set all firewallpolicy blockinboundalways,blockoutbound\n";
	pre+="netsh firewall set logging %homepath%\\wof_log.txt 4096 enable enable\n";
	pre+="netsh firewall set notifications enable all\n";
	pre+="netsh advfirewall firewall set rule name=all new enable=no\n";
	return pre;
}

std::string gen_rule(const std::string& proto,
	const std::string& l_ip,const std::string& l_mask,const std::string& l_port,
	const std::string& dir,
	const std::string& f_ip,const std::string& f_mask,const std::string& f_port,
	const std::string& action,
	const bool V6)
{
	std::string rule;
	rule+="netsh advfirewall firewall add rule";
	rule+=" name="+to_string(rule_num);
	if(dir=="<")
		rule+=" dir=in ";
	else
		rule+=" dir=out";
	if(action=="deny")
		rule+=" action=block";
	else
		rule+=" action=allow";
	rule+=" protocol="+proto;
	rule+=" localip="+l_ip+"/"+l_mask;
	rule+=" remoteip="+f_ip+"/"+f_mask;
	if(l_port!="0")
		rule+=" localport="+l_port;
	if(f_port!="0")
		rule+=" remoteport="+f_port;
	return rule;
}
