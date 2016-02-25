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

void validate_rule(size_t index,const json::Object& rule)
{
	std::string obj_str(json::Serialize(rule));
	std::ostringstream err;
	err<<"Rule "<<index<<" '"<<obj_str<<"' ";
	std::string missing("is missing required key ");
	std::string bad_default("invalid action ");

	if(!rule.HasKey("dir"))
		throw std::runtime_error(err.str()+missing+"\"dir\".");
	if(!rule.HasKey("action"))
		throw std::runtime_error(err.str()+missing+"\"action\".");
	if(!rule.HasKey("from"))
		throw std::runtime_error(err.str()+missing+"\"from\".");
	if(!rule.HasKey("to"))
		throw std::runtime_error(err.str()+missing+"\"to\".");

	std::string action(rule["action"]);
	std::string dir(rule["dir"]);
	std::string from(rule["from"]);
	std::string to(rule["to"]);

	if(action!="deny"&&action!="allow")
		throw std::runtime_error(bad_default+"\""+action+"\".");

	output_str+=action+" "+dir+" "+from+" "+to+"\n";
}

void validate(const json::Object& obj)
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
	ipaddr_t addr("234.245.33.0/26---");
	return 0;

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

		validate(json::Deserialize(data));
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