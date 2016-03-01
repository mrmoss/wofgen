//test str
//'{"defaults":{"in":"deny","out":"deny"},"rules":[{"dir":"out","from":{"address":"192.168.1.1/24","port":200},"to":{"address":"any"},"action":"deny"}]}'|./wof
#include <ctype.h>
#include <fstream>
#include <iostream>
#include "ipaddr.hpp"
#include "json.hpp"
#include <stdexcept>
#include <sstream>
#include <string>
#include "string_util.hpp"

std::string output_str("");

std::string validate_address(json::Value& address)
{
	try
	{
		ipaddr_t addr(address);
		address=addr.str();
	}
	catch(std::exception& error)
	{
		return error.what();
	}
	catch(...)
	{
		return "Unknown error.";
	}

	return "";
}

std::string validate_port(json::Value& port)
{
	try
	{
		int port_int=0;

		if(port.GetType()==json::IntVal)
			port_int=(int)port;
		else if(port.GetType()==json::StringVal)
		{
			if(trim(std::string(port))=="any")
				port_int=0;
			else
				port_int=str_to_int(port);
		}
		else
			return json::Serialize(port);

		if(port_int<0||port_int>65535)
			return to_string(port_int);

		port=port_int;
	}
	catch(...)
	{
		return json::Serialize(port);
	}

	return "";
}

std::string validate_conn(json::Value& conn)
{
	if(!conn.HasKey("address"))
		return "missing required key \"address\" in member ";
	if(!conn.HasKey("port"))
		conn["port"]="any";

	if(conn["address"].GetType()!=json::StringVal)
		return "expected \"address\" to be of type string in member ";

	std::string address(validate_address(conn["address"]));
	if(address.size()>0)
		return "invalid address ("+address+") in member ";

	std::string port(validate_port(conn["port"]));
	if(port.size()>0)
		return "invalid port \""+port+"\" in member ";

	return "";
}

void validate_rule(size_t index,json::Value& rule)
{
	std::string obj_str(json::Serialize(rule));
	std::ostringstream err;
	err<<"Rule "<<index<<" '"<<obj_str<<"' ";
	std::string missing("is missing required key ");
	std::string bad_default("invalid action ");
	std::string expected_obj("expected type object  ");
	std::string bad_to("invalid to ");

	if(!rule.HasKey("dir"))
		throw std::runtime_error(err.str()+missing+"\"dir\".");
	if(!rule.HasKey("action"))
		throw std::runtime_error(err.str()+missing+"\"action\".");
	if(!rule.HasKey("from"))
		throw std::runtime_error(err.str()+missing+"\"from\".");
	if(!rule.HasKey("to"))
		throw std::runtime_error(err.str()+missing+"\"to\".");

	if(rule["from"].GetType()!=json::ObjectVal)
		throw std::runtime_error(err.str()+expected_obj+"\"from\".");
	if(rule["to"].GetType()!=json::ObjectVal)
		throw std::runtime_error(err.str()+expected_obj+"\"to\".");

	std::string from_err=validate_conn(rule["from"]);
	if(from_err.size()>0)
		throw std::runtime_error(err.str()+from_err+"\"from\".");
	std::string to_err=validate_conn(rule["to"]);
	if(to_err.size()>0)
		throw std::runtime_error(err.str()+to_err+"\"to\".");

	std::string action(rule["action"]);
	std::string dir(rule["dir"]);

	std::string from(rule["from"]["address"]);
	from+=":";
	if((int)rule["from"]["port"]==0)
		from+="any";
	else
		from+=to_string((rule["from"])["port"]);

	std::string to(rule["to"]["address"]);
	to+=":";
	if((int)rule["to"]["port"]==0)
		to+="any";
	else
		to+=to_string(rule["to"]["port"]);

	if(action!="deny"&&action!="allow")
		throw std::runtime_error(bad_default+"\""+action+"\".");

	output_str+=action+" "+dir+" "+from+" "+to+"\n";
}

void validate(json::Value& obj)
{
	if(!obj.HasKey("rules")&&obj["rules"].GetType()!=json::ArrayVal)
		throw std::runtime_error("Configuration is missing required array \"rules\".");

	std::string default_in("deny");
	std::string default_out("deny");
	json::Array rules(obj["rules"]);

	if(obj.HasKey("defaults"))
	{
		json::Object defaults(obj["defaults"]);
		if(defaults.HasKey("in"))
			default_in=std::string(defaults["in"]);
		if(defaults.HasKey("out"))
			default_out=std::string(defaults["out"]);
	}

	std::string bad_default("Unknown default in action \"");
	if(default_in!="deny"&&default_in!="allow")
		throw std::runtime_error(bad_default+default_in+"\".");
	if(default_out!="deny"&&default_out!="allow")
		throw std::runtime_error(bad_default+default_out+"\".");

	output_str+="default in "+default_in+"\n";
	output_str+="default out "+default_out+"\n";

	for(size_t ii=0;ii<rules.size();++ii)
		validate_rule(ii,rules[ii]);
}

int main(int argc,char* argv[])
{
	try
	{
		std::string data;
		std::string temp;
		std::istream* istr=&std::cin;
		std::ifstream fstr;

		if(argc==2)
		{
			fstr.open(argv[1]);
			if(!fstr)
				throw std::runtime_error("Could not open file \""+std::string(argv[1])+"\".");
			istr=&fstr;
		}

		while(std::getline(*istr,temp))
			if((temp=trim(temp)).size()>0)
				data+=temp+"\n";

		if(!istr->eof())
			throw std::runtime_error("Error reading from pipe.");
		fstr.close();
		if(data.size()==0)
			throw std::runtime_error("Data is empty.");

		json::Value obj(json::Deserialize(to_lower(data)));
		validate(obj);
		std::cout<<output_str<<std::flush;
	}
	catch(std::exception& error)
	{
		std::cout<<"Error - "<<error.what()<<std::endl;
		return 1;
	}
	catch(...)
	{
		std::cout<<"Unknown error occurred."<<std::endl;
		return 1;
	}

	return 0;
}