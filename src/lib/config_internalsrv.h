#ifndef CONFIG_INTERNAL_SRV_H
#define CONFIG_INTERNAL_SRV_H

#include "config_class.h"

namespace config {

/////////////////////////////////////////
class ConfigInternalSrv: public Config{
public:
	ConfigInternalSrv(const std::string& type, cppdb::session* sql);
	~ConfigInternalSrv();

	virtual bool Process(cgicc::Cgicc& cgi);
};

} // namespace config

#endif // CONFIG_INTERNAL_SRV_H
