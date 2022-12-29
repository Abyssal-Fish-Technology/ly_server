#ifndef CONFIG_INTERNAL_IP_H
#define CONFIG_INTERNAL_IP_H

#include "config_class.h"

namespace config {

/////////////////////////////////////////
class ConfigInternalIp: public Config{
public:
	ConfigInternalIp(const std::string& type, cppdb::session* sql);
	~ConfigInternalIp();

	virtual bool Process(cgicc::Cgicc& cgi);
};

} // namespace config

#endif // CONFIG_INTERNAL_IP_H