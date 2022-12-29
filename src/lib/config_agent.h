#ifndef CONFIG_AGENT_H
#define CONFIG_AGENT_H

#include "config_class.h"
#include "config_agent.pb.h"

namespace config {

/////////////////////////////////////////
class ConfigAgent: public Config{
public:
	ConfigAgent(const std::string& type, cppdb::session* sql);
	~ConfigAgent();

	virtual bool Process(cgicc::Cgicc& cgi);

protected:
	virtual bool ParseReq(cgicc::Cgicc& cgi);
	virtual bool ParseReqForDevice(cgicc::Cgicc& cgi);
	virtual bool ParseReqForController(cgicc::Cgicc& cgi);
	virtual bool ValidateRequest();
	virtual bool ValidateRequestForDevice();
	virtual bool ValidateRequestForController();

private:
	bool Add();
	bool Del();
	bool Mod();
	bool Get();

	bool AddDevice();
	bool DelDevice();
	bool ModDevice();
	bool GetDevice();

	bool ModController();
	bool GetController();

	bool CheckAgentAndPort(google::protobuf::Message *_req);

protected:
	google::protobuf::Message *_req;

	enum Op {
	  ADD =1,
	  DEL,
	  MOD,
	  GET,
	} _op;

	bool _isDevice;
	bool _isController;
};

} // namespace config

#endif // CONFIG_AGENT_H