#ifndef CONFIG_MO_H
#define CONFIG_MO_H

#include "config_class.h"
#include "config_event.pb.h"
#include "../common/mo_req.h"

namespace config {

/////////////////////////////////////////
class ConfigMo: public Config{
public:
	ConfigMo(const std::string& type, cppdb::session* sql);

	virtual bool Process(cgicc::Cgicc& cgi);

protected:
	unsigned long _id;
	mo::MoReq *_req;
};

} // namespace config

#endif // CONFIG_MO_H