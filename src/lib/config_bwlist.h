#ifndef CONFIG_BWLIST_H
#define CONFIG_BWLIST_H

#include "config_class.h"
#include "config_bwlist.pb.h"

namespace config {

/////////////////////////////////////////
class ConfigBwlist: public Config{
public:
	ConfigBwlist(const std::string& type, cppdb::session* sql);
	~ConfigBwlist();

	virtual bool Process(cgicc::Cgicc& cgi);

protected:
	virtual bool ParseReq(cgicc::Cgicc& cgi);
	virtual bool ValidateRequest();

private:
	bool Add();
	bool Del();
	bool Mod();
	bool Get();

	bool CheckIfExists(config_req::Bwlist *req);

protected:
	google::protobuf::Message *_req;

	enum Op {
	  ADD =1,
	  DEL,
	  MOD,
	  GET,
	} _op;
};

} // namespace config

#endif // CONFIG_BWLIST_H