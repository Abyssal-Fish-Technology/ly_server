#ifndef CONFIG_CLASS_H
#define CONFIG_CLASS_H

#include <Cgicc.h>
#include <cppdb/frontend.h>
#include "boost/regex.hpp"

namespace config{

#define CIDR_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}(/(([12]?[0-9])|(3[0-2])))?$"

// Config - Base class
class Config{
public:
	Config(const std::string& type, cppdb::session* sql);
	virtual ~Config(){}

	virtual bool Process(cgicc::Cgicc& cgi);
	virtual bool Process(int argc, char**argv);

	inline bool is_valid_cidr(const std::string& ip){
		boost::regex pattern(CIDR_PATTERN, boost::regex::nosubs);
		boost::smatch m;
		return regex_match(ip,m,pattern);
	}

	inline bool is_valid_port(const std::string& port) {
		if ( port.size() != strspn(port.c_str(), "0123456789") )
			return false;

		int p = atoi(port.c_str());
		if (p<0 || p>65535)
			return false;

		return true;
	}

	inline bool is_valid_port(int port) {
		if (port<0 || port>65535)
			return false;

		return true;
	}

	inline std::string ipAddSuffix(const std::string& ip){
		if ( ip=="" || ip.find('/')!=std::string::npos )
			return ip;
		else
			return (ip+"/32");
	}

protected:
	virtual void PrintCmdUsage(const std::string& name);
	void stAddUpdateSet(std::string& str, const std::string s);
	void stAddWhere(std::string& str, const std::string s);
	void output_string(const std::string& name, const std::string& value);
	void output_u64(const std::string& name, const unsigned long long value);
	void output_null(const std::string& name);
	void output_float(const std::string& name, const float value);
	bool Executed(const std::string& str = "executed");
	bool Failed(const std::string& str = "failed");

protected:
	cppdb::session* _sql;
	std::string _type;
};

} // namespace config

extern "C" {
	// Implement these functions in sub-class cpps
	config::Config *CreateConfigInstance(const std::string&, cppdb::session*);
	void FreeConfigInstance(config::Config*);
}

#endif // CONFIG_CLASS_H
