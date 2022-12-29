#ifndef CONFIG_EVENT_H
#define CONFIG_EVENT_H

#include "config_class.h"
#include "config_event.pb.h"

namespace config {

/////////////////////////////////////////
class ConfigEvent: public Config{
public:
	ConfigEvent(const std::string& type, cppdb::session* sql);
	~ConfigEvent();

	virtual bool Process(cgicc::Cgicc& cgi);

protected:
	virtual bool ParseReq(cgicc::Cgicc& cgi);
	virtual bool ValidateRequest();

private:
	bool ProcessEvent();
	bool ProcessType();
	bool ProcessUrlType();
	bool ProcessEventIgnore();
	bool ProcessConfigThreshold(bool out_type=false);
	bool ProcessConfigIPScan(bool out_type=false);
	bool ProcessConfigPortScan(bool out_type=false);
	bool ProcessConfigSrv(bool out_type=false);
	bool ProcessConfigSus(bool out_type=false);
	bool ProcessConfigBlack(bool out_type=false);
	bool ProcessLevel();
	bool ProcessAction();
	bool ProcessConfigAll();
	bool ProcessDataAggre();
	bool ProcessConfigDga(bool out_type=false);
	bool ProcessConfigDns(bool out_type=false);
	bool ProcessConfigDnstunnel(bool out_type=false);
	bool ProcessConfigDnstunAI(bool out_type=false);
	bool ProcessConfigUrlContent(bool out_type=false);
	bool ProcessConfigFrnTrip(bool out_type=false);
	bool ProcessConfigIcmpTun(bool out_type=false);

	bool ParseReqForEvent(cgicc::Cgicc& cgi);
	bool ParseReqForType(cgicc::Cgicc& cgi);
	bool ParseReqForUrlType(cgicc::Cgicc& cgi);
	bool ParseReqForEventIgnore(cgicc::Cgicc& cgi);
	bool ParseReqForConfigThreshold(cgicc::Cgicc& cgi);
	bool ParseReqForConfigIPScan(cgicc::Cgicc& cgi);
	bool ParseReqForConfigPortScan(cgicc::Cgicc& cgi);
	bool ParseReqForConfigSrv(cgicc::Cgicc& cgi);
	bool ParseReqForConfigSus(cgicc::Cgicc& cgi);
	bool ParseReqForConfigBlack(cgicc::Cgicc& cgi);
	bool ParseReqForLevel(cgicc::Cgicc& cgi);
	bool ParseReqForAction(cgicc::Cgicc& cgi);
	bool ParseReqForDataAggre(cgicc::Cgicc& cgi);
	bool ParseReqForConfigDga(cgicc::Cgicc& cgi);
	bool ParseReqForConfigDns(cgicc::Cgicc& cgi);
	bool ParseReqForConfigDnstunnel(cgicc::Cgicc& cgi);
	bool ParseReqForConfigDnstunAI(cgicc::Cgicc& cgi);
	bool ParseReqForConfigUrlContent(cgicc::Cgicc& cgi);
	bool ParseReqForConfigFrnTrip(cgicc::Cgicc& cgi);
	bool ParseReqForConfigIcmpTun(cgicc::Cgicc& cgi);

	bool ValidateEvent();
	bool ValidateType();
	bool ValidateUrlType();
	bool ValidateEventIgnore();
	bool ValidateConfigThreshold();
	bool ValidateConfigIPScan();
	bool ValidateConfigPortScan();
	bool ValidateConfigSrv();
	bool ValidateConfigSus();
	bool ValidateConfigBlack();
	bool ValidateLevel();
	bool ValidateAction();
	bool ValidateConfigAll();
	bool ValidateDataAggre();
	bool ValidateConfigDga();
	bool ValidateConfigDns();
	bool ValidateConfigDnstunnel();
	bool ValidateConfigDnstunAI();
	bool ValidateConfigUrlContent();
	bool ValidateConfigFrnTrip();
	bool ValidateConfigIcmpTun();

protected:
	unsigned long _id;
	google::protobuf::Message *_req;

	enum Target {
	  EVENT,
	  TYPE,
    URL_TYPE,
    EVENT_IGNORE,
	  CONFIG_THRESHOLD,
	  CONFIG_IP_SCAN,
	  CONFIG_PORT_SCAN,
	  CONFIG_SRV,
    CONFIG_SUS,
    CONFIG_BLACK,
	  LEVEL,
	  ACTION,
	  CONFIG_ALL,
	  DATA_AGGRE,
	  CONFIG_DGA,
	  CONFIG_DNS,
	  CONFIG_DNSTUNNEL,
	  CONFIG_DNSTUN_AI,
    CONFIG_URL_CONTENT,
    CONFIG_FRN_TRIP,
    CONFIG_ICMP_TUN,
	} _target;

	enum Op {
	  ADD =1,
	  DEL,
	  MOD,
	  GET,
    DEL_EVENT
	} _op;
};

} // namespace config

#endif // CONFIG_EVENT_H
