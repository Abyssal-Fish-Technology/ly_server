#include "config_event.h"
#include <boost/algorithm/string.hpp>
#include "../common/common.h"
#include "../common/log.h"
#include "../common/strings.h"
#include "../common/ip.h"
#include "../common/csv.hpp"
#include "boost/regex.hpp"
#include <list>
#include <set>


using namespace std;
using namespace config_req;
using namespace boost;

#define VALID_PROTO_PATTERN "^\\d+$"

static u32 white_count = 0;
static vector<u64> ids_;
static vector<set<string> > lip_;
static vector<set<string> > lip6_;
static vector<set<string> > tip_;
static vector<set<string> > tip6_;
static vector<set<string> > tport_;
static vector<set<string> > proto_;
static vector<set<string> > domain_;
enum Weekday {
    SUN = 0,
    MON = 1,
    TUE = 2,
    WED = 3,
    THU = 4,
    FRI = 5,
    SAT = 6
  };

enum Coverrange {
    WITHIN = 0,
    WITHOUT = 1
};

struct Filter_time {
  vector<Weekday> weekday;
  i32 stime_hour;
  i32 stime_min;
  i32 stime_sec;
  i32 etime_hour;
  i32 etime_min;
  i32 etime_sec;
  Coverrange coverrange;
};
static vector<struct Filter_time> time_;
static vector<u64> count_;

// Fucntions used for .so
config::Config *CreateConfigInstance(const std::string& type, cppdb::session* sql) {
	return new config::ConfigEvent(type, sql);
}

void FreeConfigInstance(config::Config *p){
	// delete p;
}

///////////////////////////////////////////////////////////
static std::string transfrom_to_ipseg(const string& ip) {
  size_t pos;
  string ip_range;
  if((pos = ip.find("/")) != std::string::npos) {
    string ip_left = ip.substr(0, pos);
    u32 mask = atoi(ip.substr(pos+1).c_str());
    u32 count = pow(2, 32 - mask) - 1;
    u32 left = ipstr_to_ipnum(ip_left);
    if ((count >> mask) & left) return "";

    string ip_right = ipnum_to_ipstr(left + count);
    ip_range = ip_left + "-" + ip_right;
  } else
    ip_range = ip;
  return ip_range;
}

static std::string transfrom_to_ipseg_v6(const string& ip) {
  size_t pos;
  string ip_range;
  if((pos = ip.find("/")) != std::string::npos) {
    string ip_left = ip.substr(0, pos); 
    u32 mask = atoi(ip.substr(pos+1).c_str());
    struct in6_addr left = ipstr_to_ipnum_v6(ip_left);

    u32 pivot = mask / 32;
    u32 shift = mask % 32;

    if (pivot<4) {
      left.s6_addr32[pivot] += pow(2, shift);
    }
    for (int i = pivot+1; i<4; i++) {
      left.s6_addr32[i] += pow(2, 32);
    }

    string ip_right = ipnum_to_ipstr_v6(left);

    ip_range = ip_left + "-" + ip_right;
  } else 
    ip_range = ip;
  return ip_range;
}

static inline bool is_protonum(const string& proto) {
  regex pattern(VALID_PROTO_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(proto,m,pattern);
}

static inline void set_weekday(struct Filter_time& e, const string& weekday) {
  vector<string> v;
  csv::fill_vector_from_line(v, weekday);

  sort(v.begin(), v.end());
  auto new_end = unique(v.begin(), v.end());
  v.resize( std::distance(v.begin(),new_end) );

  for (auto it=v.begin(); it!=v.end(); it++) {
    int d = atol((*it).c_str());
    if (d>=0&&d<=6)
      e.weekday.push_back(Weekday(d));
  }
}

static inline void set_stime(struct Filter_time& e, const string& stime) {
  vector<string> v;
  csv::fill_vector_from_line(v, stime, ':');

  int hour = 0;
  int minute = 0;
  int sec = 0;

  if (v.size()>0) hour = atol(v[0].c_str());
  if (v.size()>1) minute = atol(v[1].c_str());
  if (v.size()>2) sec = atol(v[2].c_str());

  e.stime_hour = hour;
  e.stime_min = minute;
  e.stime_sec = sec;
}

static inline void set_etime(struct Filter_time& e, const string& etime) {
  vector<string> v;
  csv::fill_vector_from_line(v, etime, ':');

  int hour = 0;
  int minute = 0;
  int sec = 0;

  if (v.size()>0) hour = atol(v[0].c_str());
  if (v.size()>1) minute = atol(v[1].c_str());
  if (v.size()>2) sec = atol(v[2].c_str());

  e.etime_hour = hour;
  e.etime_min = minute;
  e.etime_sec = sec;
}

static inline void set_coverrange(struct Filter_time& e, const string& coverrange) {
  if (coverrange=="within")
    e.coverrange = WITHIN;
  else
    e.coverrange = WITHOUT;
}

static bool check_ip(std::set<string>& ip_list, u32 sip) {
  bool ip_match = false;
  if (ip_list.size() == 0) {
    return true;
  }
  if (sip == 0) {
    return false;
  }
  for(auto it = ip_list.begin();it != ip_list.end();it++) {
    u32 min, max;
    string lip = *it;
    if (lip.empty()) continue;
    size_t pos;
    if (lip[0] == '!') {
      if ((pos = lip.find("-", 1)) != std::string::npos) {
        min = ipstr_to_ipnum(lip.substr(1, pos - 1));
        max = ipstr_to_ipnum(lip.substr(pos + 1));
        if (sip > max || sip < min) {
          ip_match = true;
        } else if (sip >= min && sip <= max) {
          ip_match = false;
          break;
        }
      } else {
        u32 left = ipstr_to_ipnum(lip.substr(1));
        if (sip != left) {
          ip_match = true;
        } else {
          ip_match = false;
          break;
        }
      }
    } else {
      if ((pos = lip.find("-")) != std::string::npos) {
        min = ipstr_to_ipnum(lip.substr(0, pos));
        max = ipstr_to_ipnum(lip.substr(pos + 1));
        if (sip >= min && sip <= max) {
          ip_match = true;
          break;
        }
      } else {
        if (sip == ipstr_to_ipnum(lip)) {
          ip_match = true;
          break;
        }
      }
    }
  }
  return ip_match;
}

static bool check_ip_v6(std::set<string>& ip_list, struct in6_addr sip) {
  bool ip_match = false;
  if (ip_list.size() == 0) {
    return true;
  }   
  if (sip.s6_addr32[0] == 0 && sip.s6_addr32[1] == 0 && sip.s6_addr32[2] == 0 && sip.s6_addr32[3] == 0) {
    return false;
  }
  for(auto it = ip_list.begin();it != ip_list.end();it++) {
    struct in6_addr min, max;
    string lip = *it;
    if (lip.empty()) continue;
    size_t pos;

    if (lip[0] == '!') {
      if ((pos = lip.find("-", 1)) != std::string::npos) {
        min = ipstr_to_ipnum_v6(lip.substr(1, pos - 1));
        max = ipstr_to_ipnum_v6(lip.substr(pos + 1));
        if ((memcmp(&sip, &max, sizeof(struct in6_addr)) > 0) || 
              (memcmp(&sip, &min, sizeof(struct in6_addr)) < 0)) {
          ip_match = true;
        } else if ((memcmp(&sip, &min, sizeof(struct in6_addr)) >= 0) && 
              (memcmp(&sip, &max, sizeof(struct in6_addr)) <= 0)) {
          ip_match = false;
          break;
        }
      } else {
        struct in6_addr  left = ipstr_to_ipnum_v6(lip.substr(1));
        if ((memcmp(&sip, &left, sizeof(struct in6_addr)) != 0)) {
          ip_match = true;
        } else {
          ip_match = false;
          break;
        }
      }
    } else {//lip[0] != '!'
      if ((pos = lip.find("-")) != std::string::npos) {
        min = ipstr_to_ipnum_v6(lip.substr(0, pos));
        max = ipstr_to_ipnum_v6(lip.substr(pos + 1));
        if ((memcmp(&sip, &min, sizeof(struct in6_addr)) >= 0) && 
              (memcmp(&sip, &max, sizeof(struct in6_addr)) <= 0)){
          ip_match = true;
          break;
        }
      } else {
        struct in6_addr  left = ipstr_to_ipnum_v6(lip);
        if ((memcmp(&sip, &left, sizeof(struct in6_addr)) == 0)){
          ip_match = true;
          break;
        }
      }
    }
  }//for
  return ip_match;
}

static bool check_port(std::set<string>& port_list, u16 dport) {
  bool port_match = false;
  if (port_list.size() == 0) return true;
  for(auto it = port_list.begin();it != port_list.end();it++) {
    u16 min, max;
    string port = *it;
    if (port.empty()) continue;
    size_t pos;
    if (port[0] == '!') {
      if ((pos = port.find("-", 1)) != std::string::npos) {
        min = atoi(port.substr(1, pos - 1).c_str());
        max = atoi(port.substr(pos + 1).c_str());
        if (dport > max && dport < min) {
          port_match = true;
        } else if (dport >= min && dport <= max) {
          port_match = false;
          break;
        }
      } else {
        u16 left = atoi(port.substr(1).c_str());
        if (dport != left) {
          port_match = true;
        } else {
          port_match = false;
          break;
        }
      }
    } else {
      if ((pos = port.find("-")) != std::string::npos) {
        min = atoi(port.substr(0, pos).c_str());
        max = atoi(port.substr(pos + 1).c_str());
        if (dport >= min && dport <= max) {
          port_match = true;
          break;
        }
      } else {
        if (dport == atoi(port.c_str())) {
          port_match = true;
          break;
        }
      }
    }
  }
  return port_match;
}

static bool check_proto(std::set<string>& proto_list, const string& proto) {
  bool proto_match = false;
  if (proto_list.size() == 0) return true;
  for(auto it = proto_list.begin();it != proto_list.end();it++) {
    string tmp_proto = *it;
    if (tmp_proto.empty()) continue;
    if (proto == tmp_proto) {
      proto_match = true;
      break;
    }
  }
  return proto_match;
}

static bool check_domain(std::set<string>& domain_list, const string& domain) {
  bool domain_match = false;

  if (domain_list.size() == 0) 
    return true;
  if (domain.empty())
    return false;
  for(auto it = domain_list.begin();it != domain_list.end();it++) {
    string tmp_domain = *it;
    if (tmp_domain.empty()) continue;
    if (domain == tmp_domain) {
      domain_match = true;
      break;
    }
  }
  return domain_match;
}

/*static bool check_time(time_t t, struct Filter_time& e) {
  bool within = false;

  struct tm *p = localtime(&t);
  for (u32 i=0; i<e.weekday.size(); i++) {
    if (e.weekday[i]==p->tm_wday) {
      within = true;
      break;
    }
  }

  if (within==false)
    return (e.coverrange == WITHIN)? false : true;

  if (p->tm_hour >= e.stime_hour
    && p->tm_min  >= e.stime_min
    && p->tm_sec  >= e.stime_sec
    && p->tm_hour <= e.etime_hour
    && p->tm_min  <= e.etime_min
    && p->tm_sec  <= e.etime_sec
  )
    within = true;
  else
    within = false;

  if ( (within==true && e.coverrange==WITHIN) || (within==false && e.coverrange==WITHOUT) )
    return true;
  else
    return false;
}*/
//////////////////////////////////////////////////////////

namespace config{

ConfigEvent::ConfigEvent(const std::string& type, cppdb::session* sql):Config(type, sql){
	_req = NULL;
	_id = 0;
	return;
}
ConfigEvent::~ConfigEvent(){
	if (_req){
		delete _req;
	}
}

bool ConfigEvent::Process(cgicc::Cgicc& cgi){
	bool res;

	cout<<"[";
	if (!ParseReq(cgi)) {
		cout<<"]"<<endl;
		return false;
	}
	if (!ValidateRequest()) {
		cout<<"]"<<endl;
		return false;
	}

	switch (_target) {
		case EVENT:
			res = ProcessEvent();
			break;
		case TYPE:
			res = ProcessType();
			break;
		case URL_TYPE:
			res = ProcessUrlType();
			break;
    case EVENT_IGNORE:
      res = ProcessEventIgnore();
      break;
		case CONFIG_THRESHOLD:
			res = ProcessConfigThreshold();
			break;
		case CONFIG_PORT_SCAN:
			res = ProcessConfigPortScan();
			break;
		case CONFIG_IP_SCAN:
			res = ProcessConfigIPScan();
			break;
		case CONFIG_SRV:
			res = ProcessConfigSrv();
			break;
    case CONFIG_SUS:
      res = ProcessConfigSus();
      break;
    case CONFIG_BLACK:
      res = ProcessConfigBlack();
      break;
		case LEVEL:
			res = ProcessLevel();
			break;
		case ACTION:
			res = ProcessAction();
			break;
		case CONFIG_ALL:
			res = ProcessConfigAll();
			break;
		case DATA_AGGRE:
			res = ProcessDataAggre();
			break;
		case CONFIG_DGA:
			res = ProcessConfigDga();
			break;
		case CONFIG_DNS:
			res = ProcessConfigDns();
			break;
		case CONFIG_DNSTUNNEL:
			res = ProcessConfigDnstunnel();
			break;
		case CONFIG_DNSTUN_AI:
			res = ProcessConfigDnstunAI();
			break;
    case CONFIG_URL_CONTENT:
      res = ProcessConfigUrlContent();
      break;
    case CONFIG_FRN_TRIP:
      res = ProcessConfigFrnTrip();
      break;
    case CONFIG_ICMP_TUN:
      res = ProcessConfigIcmpTun();
      break;
    default:
      break;
	}
	cout<<"]";

	return res;
}

bool ConfigEvent::ParseReq(cgicc::Cgicc& cgi){
	if (!cgi("id").empty())
		_id = atoll(cgi("event_id").c_str());

	if (_type.empty())
		return false;
	else {
		string target = boost::to_upper_copy(_type);

		if (target=="EVENT")
			_target = EVENT;
		else if (target=="EVENT_TYPE")
			_target = TYPE;
		else if (target=="EVENT_URL_TYPE")
			_target = URL_TYPE;
    else if (target=="EVENT_IGNORE")
      _target = EVENT_IGNORE;
		else if (target=="EVENT_CONFIG"){
			string event_type = boost::to_upper_copy(cgi("event_type"));

			if (event_type.empty())
				_target = CONFIG_ALL;
			else if (event_type=="MO")
				_target = CONFIG_THRESHOLD;
			else if (event_type=="PORT_SCAN")
				_target = CONFIG_PORT_SCAN;
			else if (event_type=="IP_SCAN")
				_target = CONFIG_IP_SCAN;
			else if (event_type=="SRV")
				_target = CONFIG_SRV;
      else if (event_type=="TI")
        _target = CONFIG_SUS;
      else if (event_type=="BLACK")
        _target = CONFIG_BLACK;
			else if (event_type=="DGA")
				_target = CONFIG_DGA;
			else if (event_type=="DNS")
				_target = CONFIG_DNS;
			else if (event_type=="DNS_TUN")
				_target = CONFIG_DNSTUNNEL;
			else if (event_type=="DNSTUN_AI")
				_target = CONFIG_DNSTUN_AI;
			else if (event_type=="URL_CONTENT")
				_target = CONFIG_URL_CONTENT;
			else if (event_type=="FRN_TRIP")
				_target = CONFIG_FRN_TRIP;
			else if (event_type=="ICMP_TUN")
				_target = CONFIG_ICMP_TUN;
		}
		else if (target=="EVENT_LEVEL")
			_target = LEVEL;
		else if (target=="EVENT_ACTION")
			_target = ACTION;
		else if (target=="EVENT_DATA_AGGRE")
			_target = DATA_AGGRE;
		else
			return false;
	}

	if (cgi("op").empty())
		return false;
	else {
		string op = boost::to_upper_copy(cgi("op"));

		if (op=="ADD")
			_op = ADD;
		else if (op=="DEL")
			_op = DEL;
		else if (op=="MOD")
			_op = MOD;
		else if (op=="GET")
			_op = GET;  
    else if (op=="DEL_EVENT")
      _op = DEL_EVENT;
		else
			return false;
	}

	switch (_target) {
		case EVENT:
			return ParseReqForEvent(cgi);
			break;
		case TYPE:
			return ParseReqForType(cgi);
			break;
		case URL_TYPE:
			return ParseReqForUrlType(cgi);
			break;
		case EVENT_IGNORE:
			return ParseReqForEventIgnore(cgi);
			break;
		case CONFIG_THRESHOLD:
			return ParseReqForConfigThreshold(cgi);
			break;
		case CONFIG_PORT_SCAN:
			return ParseReqForConfigPortScan(cgi);
			break;
		case CONFIG_IP_SCAN:
			return ParseReqForConfigIPScan(cgi);
			break;
		case CONFIG_SRV:
			return ParseReqForConfigSrv(cgi);
			break;
    case CONFIG_SUS:
      return ParseReqForConfigSus(cgi);
      break;
    case CONFIG_BLACK:
      return ParseReqForConfigBlack(cgi);
      break;
		case LEVEL:
			return ParseReqForLevel(cgi);
			break;
		case ACTION:
			return ParseReqForAction(cgi);
			break;
		case CONFIG_ALL:
			return true;
			break;
		case DATA_AGGRE:
			return ParseReqForDataAggre(cgi);
			break;
		case CONFIG_DGA:
			return ParseReqForConfigDga(cgi);
			break;
		case CONFIG_DNS:
			return ParseReqForConfigDns(cgi);
			break;
		case CONFIG_DNSTUNNEL:
			return ParseReqForConfigDnstunnel(cgi);
			break;
		case CONFIG_DNSTUN_AI:
			return ParseReqForConfigDnstunAI(cgi);
			break;
		case CONFIG_URL_CONTENT:
			return ParseReqForConfigUrlContent(cgi);
			break;
		case CONFIG_FRN_TRIP:
			return ParseReqForConfigFrnTrip(cgi);
			break;
		case CONFIG_ICMP_TUN:
			return ParseReqForConfigIcmpTun(cgi);
			break;
    default:
      break;
	}

	return false; //This code should never execute.
}

bool ConfigEvent::ValidateRequest(){
	switch (_target) {
		case EVENT:
			return ValidateEvent();
			break;
		case TYPE:
			return ValidateType();
			break;
		case URL_TYPE:
			return ValidateUrlType();
			break;
		case EVENT_IGNORE:
			return ValidateEventIgnore();
			break;
		case CONFIG_THRESHOLD:
			return ValidateConfigThreshold();
			break;
		case CONFIG_PORT_SCAN:
			return ValidateConfigPortScan();
			break;
		case CONFIG_IP_SCAN:
			return ValidateConfigIPScan();
		case CONFIG_SRV:
			return ValidateConfigSrv();
			break;
		case CONFIG_SUS:
			return ValidateConfigSus();
			break;
		case CONFIG_BLACK:
			return ValidateConfigBlack();
			break;
		case LEVEL:
			return ValidateLevel();
			break;
		case ACTION:
			return ValidateAction();
			break;
		case CONFIG_ALL:
			return ValidateConfigAll();
			break;
		case DATA_AGGRE:
			return ValidateDataAggre();
			break;
		case CONFIG_DGA:
			return ValidateConfigDga();
			break;
		case CONFIG_DNS:
			return ValidateConfigDns();
			break;
		case CONFIG_DNSTUNNEL:
			return ValidateConfigDnstunnel();
			break;
		case CONFIG_DNSTUN_AI:
			return ValidateConfigDnstunAI();
			break;
		case CONFIG_URL_CONTENT:
			return ValidateConfigUrlContent();
			break;
		case CONFIG_FRN_TRIP:
			return ValidateConfigFrnTrip();
			break;
		case CONFIG_ICMP_TUN:
			return ValidateConfigIcmpTun();
			break;
	}

	return false; //This code should never execute.
}

bool ConfigEvent::ProcessEvent(){
  Event *req = (Event *)this->_req;

  switch (_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `server`.`t_event_status` (`moid`, `status`) VALUES (?,?)";
      if (req->moid()!="")
        st << req->moid();
      else
        st << cppdb::null;
      st << req->status();

      try{
        st << cppdb::exec;
        req->set_status_id( st.last_insert_id() );
      } catch ( cppdb::cppdb_error const &e ){
        log_err("event_status: add: %s", e.what());
        return Failed();
      }

      st = *_sql << "INSERT INTO `t_event_list` (`type_id`, `config_id`, `level_id`, `action_id`, `status_id`, `desc`, `devid`, `weekday`, `stime`, `etime`, `coverrange`) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
      try{
        st << req->type_id() << req->config_id() << req->level_id() << req->action_id() << req->status_id() << req->desc();
        if (req->devid()=="")
          st << cppdb::null;
        else
          st << req->devid();

        st << req->weekday() << req->stime() << req->etime() << req->coverrange();

        st << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("event_list: add: %s", e.what());
        return Failed();
      }

      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      try{
        cppdb::statement st = *_sql << "DELETE FROM `t_event_list` WHERE `id` = ?";
        st << req->event_id() << cppdb::exec;

        st = *_sql << "DELETE FROM `t_event_status` WHERE `id` = ?";
        st << req->status_id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case MOD:{
      string str = "UPDATE `t_event_list` SET ";
      if (req->has_type_id())
        stAddUpdateSet(str, "`type_id` = ?");
      if (req->has_config_id())
        stAddUpdateSet(str, "`config_id` = ?");
      if (req->has_level_id())
        stAddUpdateSet(str, "`level_id` = ?");
      if (req->has_action_id())
        stAddUpdateSet(str, "`action_id` = ?");
      if (req->has_status_id())
        stAddUpdateSet(str, "`status_id` = ?");
      if (req->has_desc())
        stAddUpdateSet(str, "`desc` = ?");
      if (req->has_devid())
        stAddUpdateSet(str, "`devid` = ?");
      if (req->has_weekday())
        stAddUpdateSet(str, "`weekday` = ?");
      if (req->has_stime())
        stAddUpdateSet(str, "`stime` = ?");
      if (req->has_etime())
        stAddUpdateSet(str, "`etime` = ?");
      if (req->has_coverrange())
        stAddUpdateSet(str, "`coverrange` = ?");
      str+=" WHERE `id` = ?";

      cppdb::statement st = *_sql << str;
      try{
        if (req->has_type_id())
          st << req->type_id();
        if (req->has_config_id())
          st << req->config_id();
        if (req->has_level_id())
          st << req->level_id();
        if (req->has_action_id())
          st << req->action_id();
        if (req->has_status_id())
          st << req->status_id();
        if (req->has_desc())
          st << req->desc();
        if (req->has_devid()){
          if (req->devid()=="")
            st << cppdb::null;
          else
            st << req->devid();
        }
        if (req->has_weekday())
          st << req->weekday();
        if (req->has_stime())
          st << req->stime();
        if (req->has_etime())
          st << req->etime();
        if (req->has_coverrange())
          st << req->coverrange();
        st<<req->event_id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      if (req->has_status()){
        cppdb::statement st = *_sql << "UPDATE `t_event_status` SET `status` = ? WHERE `id` = ?";
        try{
          st << req->status() << req->status_id() << cppdb::exec;
        } catch ( cppdb::cppdb_error const &e ){
          log_err("%s", e.what());
          return Failed();
        }
      }
      if (req->has_moid()){
        cppdb::statement st = *_sql << "UPDATE `t_event_status` SET `moid` = ? WHERE `id` = ?";
        try{
          if (req->moid()=="")
            st << cppdb::null;
          else
            st << req->moid();
          st << req->status_id() << cppdb::exec;
        } catch ( cppdb::cppdb_error const &e ){
          log_err("%s", e.what());
          return Failed();
        }
      }

      return Executed();
      break;
    }
    case GET:{
      string str = "SELECT t1.`id`, t1.`desc`, t2.`desc`, t3.`desc`, t4.`status`, t1.`action_id`, t1.`config_id`, t1.`devid`, t1.`weekday`, t1.`stime`, t1.`etime`, t1.`coverrange`"
        " FROM `t_event_list` t1, `t_event_type` t2, `t_event_level` t3, `t_event_status` t4"
        " WHERE t1.`type_id` = t2.`id` AND t1.`level_id` = t3.`id` AND t1.`status_id` = t4.`id`";

      if ( req->has_event_id() )
        str += " AND t1.`id` = ?";
      if ( req->has_desc() )
        str += " AND t1.`desc` = ?";
      if ( req->has_event_type() )
        str += " AND t2.`desc` = ?";
      if ( req->has_event_level() )
        str += " AND t3.`desc` = ?";
      if ( req->has_status() )
        str += " AND t4.`status` = ?";
      if ( req->has_action_id() )
        str += " AND t1.`action_id` = ?";
      if ( req->has_config_id() )
        str += " AND t1.`config_id` = ?";
      if ( req->has_devid() ){
        if (req->devid()=="")
          str += " AND t1.`devid` IS NULL";
        else
          str += " AND t1.`devid` = ?";
      }
      if ( req->has_moid() ){
        if (req->moid()=="")
          str += " AND t4.`moid` IS NULL";
        else
          str += " AND t4.`moid` = ?";
      }
      if ( req->has_weekday() )
        str += " AND t1.`weekday` = ?";
      if ( req->has_stime() )
        str += " AND t1.`stime` = ?";
      if ( req->has_etime() )
        str += " AND t1.`etime` = ?";
      if ( req->has_coverrange() )
        str += " AND t1.`coverrange` = ?";

      cppdb::statement st = *_sql <<str;
      if ( req->has_event_id() )
        st <<req->event_id();
      if ( req->has_desc() )
        st <<req->desc();
      if ( req->has_event_type() )
        st <<req->event_type();
      if ( req->has_event_level() )
        st <<req->event_level();
      if ( req->has_status() )
        st <<req->status();
      if ( req->has_action_id() )
        st <<req->action_id();
      if ( req->has_config_id() )
        st <<req->config_id();
      if ( req->devid()!="")
        st <<req->devid();
      if ( req->moid()!="")
        st << req->moid();
      if ( req->has_weekday() )
        st <<req->weekday();
      if ( req->has_stime() )
        st <<req->stime();
      if ( req->has_etime() )
        st <<req->etime();
      if ( req->has_coverrange() )
        st <<req->coverrange();

      cppdb::result r = st;
      bool first = true;
      cppdb::null_tag_type null_tag;
      while (r.next()){
        u64 u;
        string s;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>s;
        output_string("desc", s);
        cout<<",";

        r>>s;
        output_string("event_type", s);
        cout<<",";

        r>>s;
        output_string("event_level", s);
        cout<<",";

        r>>s;
        output_string("status", s);
        cout<<",";

        r>>s;
        output_string("action_id", s);
        cout<<",";

        r>>u;
        output_u64("config_id", u);
        cout<<",";

        r>>cppdb::into(u,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("devid","");
        else
          output_u64("devid", u);
        cout<<",";

        r>>s;
        output_string("weekday", s);
        cout<<",";
        
        r>>s;
        output_string("stime", s);
        cout<<",";

        r>>s;
        output_string("etime", s);
        cout<<",";

        r>>s;
        output_string("coverrange", s);
        cout<<"}";
      }
      break;
    }
    default:
      return false;
      break;
  }

  return true;
}

bool ConfigEvent::ProcessEventIgnore(){
	EventIgnore *req = (EventIgnore *)this->_req;

	switch (_op){
		case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_ignore`(`time`, `lip`, `tip`, `tport`, `protocol`, `domain`, `desc`, `weekday`, `stime`, `etime`, `coverrange`, `count`) VALUES (FROM_UNIXTIME(?),?,?,?,?,?,?,?,?,?,?,?)";
      st << req->time();
      if ( req->lip()=="" ) st << cppdb::null;
      else st << req->lip();
      if ( req->tip()=="" ) st << cppdb::null;
      else st << req->tip();
      if ( req->tport()=="" ) st << cppdb::null;
      else st << req->tport();
      if ( req->protocol()=="" ) st << cppdb::null;
      else st << req->protocol();
      if ( req->domain()=="" ) st << cppdb::null;
      else st << req->domain();

      if ( req->has_desc() )  st << req->desc();

      st << req->weekday() << req->stime() << req->etime() << req->coverrange() << req->count();
      
      try{
        st << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }
			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
      try{
        cppdb::statement st = *_sql << "DELETE FROM `t_event_ignore` WHERE `id` = ?";
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }
			return Executed();
			break;
		}
		case MOD:{
      string str = "UPDATE `t_event_ignore` SET ";
      if (req->has_time())
        stAddUpdateSet(str, "`time` = FROM_UNIXTIME(?)");
      if (req->has_lip())
        stAddUpdateSet(str, "`lip` = ?");
      if (req->has_tip())
        stAddUpdateSet(str, "`tip` = ?");
      if (req->has_tport())
        stAddUpdateSet(str, "`tport` = ?");
      if (req->has_protocol())
        stAddUpdateSet(str, "`protocol` = ?");
      if (req->has_domain())
        stAddUpdateSet(str, "`domain` = ?");
      if (req->has_desc())
        stAddUpdateSet(str, "`desc` = ?");
      if (req->has_weekday())
        stAddUpdateSet(str, "`weekday` = ?");
      if (req->has_stime())
        stAddUpdateSet(str, "`stime` = ?");
      if (req->has_etime())
        stAddUpdateSet(str, "`etime` = ?");
      if (req->has_coverrange())
        stAddUpdateSet(str, "`coverrange` = ?");
      if (req->has_count())
        stAddUpdateSet(str, "`count` = ?");
  
      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_time())
          st << req->time();
        if (req->has_lip()){
          if ( req->lip()=="") st <<cppdb::null;
          else st << req->lip();
        }
        if (req->has_tip()){
          if ( req->tip()=="") st <<cppdb::null;
          else st << req->tip();
        }
        if (req->has_tport()){
          if (req->tport()=="") st <<cppdb::null;
          else st << req->tport();
        }
        if (req->has_protocol()){
          if ( req->protocol()=="") st <<cppdb::null;
          else st << req->protocol();
        }
        if (req->has_domain()){
          if ( req->domain()=="") st <<cppdb::null;
          else st << req->domain();
        }
        if (req->has_desc())
          st << req->desc();
        if (req->has_weekday())
          st << req->weekday();
        if (req->has_stime())
          st << req->stime();
        if (req->has_etime())
          st << req->etime();
        if (req->has_coverrange())
          st << req->coverrange();
        if (req->has_count())
          st<< req->count();

        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }
			return Executed();
			break;
		}
		case GET:{
			string str = "SELECT `id`, `time`, `lip`, `tip`, `tport`, `protocol`, `domain`, `desc`, `weekday`, `stime`, `etime`, `coverrange`,`count` FROM `t_event_ignore` WHERE 1";

      if ( req->has_id() )
        str += " AND `id` = ?";
      if ( req->has_time() )
        str += " AND `time` = FROM_UNIXTIME(?)";
      if ( req->has_lip() ) {
        if (req->lip()=="")
          str += " AND `lip` IS NULL";
        else
          str += " AND `lip` = ?";
      }
      if ( req->has_tip() ) {
        if (req->tip()=="")
          str += " AND `tip` IS NULL";
        else
          str += " AND `tip` = ?";
      }
      if ( req->has_tport() ) {
        if (req->tport()=="")
          str += " AND `tport` IS NULL";
        else
          str += " AND `tport` = ?";
      }
      if ( req->has_protocol() ) {
        if (req->protocol()=="")
          str += " AND `protocol` IS NULL";
        else
          str += " AND `protocol` = ?";
      }
      if ( req->has_domain() ) {
        if (req->domain()=="")
          str += " AND `domain` IS NULL";
        else
          str += " AND `domain` = ?";
      }
      if ( req->has_desc() )
        str += " AND `desc` = ?";
      if ( req->has_weekday() )
        str += " AND `weekday` = ?";
      if ( req->has_stime() )
        str += " AND `stime` = ?";
      if ( req->has_etime() )
        str += " AND `etime` = ?";
      if ( req->has_coverrange() )
        str += " AND `coverrange` = ?";
      if ( req->has_count() )
        str += " AND `count` = ?";

      cppdb::statement st = *_sql <<str;

      if ( req->has_id() )
        st <<req->id();
      if ( req->has_time() )
        st <<req->time();
      if (req->lip()!="") st << req->lip();
      if (req->tip()!="") st << req->tip();
      if (req->tport()!="") st << req->tport();
      if (req->protocol()!="") st << req->protocol();
      if (req->domain()!="") st << req->domain();
      if ( req->has_desc() )
        st <<req->desc();
      if ( req->has_weekday() )
        st <<req->weekday();
      if ( req->has_stime() )
        st <<req->stime();
      if ( req->has_etime() )
        st <<req->etime();
      if ( req->has_coverrange() )
        st <<req->coverrange();
      if ( req->has_count() )
        st <<req->count();

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;
        struct tm t;
        cppdb::null_tag_type null_tag;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>t;
        u=mktime(&t);
        output_u64("time", u);
        cout<<",";

        r>>cppdb::into(s,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("lip", "");
        else
          output_string("lip", s);
        cout<<',';

        r>>cppdb::into(s,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("tip", "");
        else
          output_string("tip", s);
        cout<<',';

        r>>cppdb::into(s,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("tport", "");
        else
          output_string("tport", s);
        cout<<',';

        r>>cppdb::into(s,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("protocol", "");
        else
          output_string("protocol", s);
        cout<<',';

        r>>cppdb::into(s,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("domain", "");
        else
          output_string("domain", s);
        cout<<',';

        r>>s;
        output_string("desc", s);
        cout<<',';

        r>>s;
        output_string("weekday", s);
        cout<<",";

        r>>s;
        output_string("stime", s);
        cout<<",";

        r>>s;
        output_string("etime", s);
        cout<<",";

        r>>s;
        output_string("coverrange", s);
        cout<<",";

        r>>u;
        output_u64("count", u);

        cout<<"}";
      }
      break;
    }
    case DEL_EVENT: {
      cppdb::statement st;
      string str = "SELECT `lip`, `tip`, `tport`, `protocol`, `domain`, `weekday`, `stime`, `etime`, `coverrange`, `count` FROM `t_event_ignore` WHERE `id` = ?";
      st = *_sql <<str;
      if ( req->has_id() )
        st <<req->id();       

      cppdb::result res = st;
      while (res.next()) {
        u64 count;
        string lip, tip, tport, proto, domain;
        string weekday, stime, etime, coverrange; 
        res>>lip>>tip>>tport>>proto>>domain>>weekday>>stime>>etime>>coverrange>>count; 

        trim(lip);
        trim(tip);
        trim(tport);
        trim(proto);
        trim(domain);
        trim(weekday);
        trim(stime);
        trim(etime);
        trim(coverrange);

        ids_.push_back(req->id());

        bool flag_l_v6 = false;
        set<string> tmp_lip;
        if (!lip.empty()){
          if(lip.find(":") != lip.npos)
            flag_l_v6 = true;
          if (lip[0] == '!') {
            size_t left_pos = lip.find_first_not_of("(", 1);
            size_t right_pos = lip.find_last_not_of(")");

            lip = lip.substr(left_pos, right_pos - left_pos + 1);
            size_t pos = lip.find(",");  //!(x.x.x.x)
            while(std::string::npos != pos) {
              string tmp = lip.substr(0, pos);
              string ipseg = flag_l_v6 ? transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
              if (!ipseg.empty())
                tmp_lip.insert('!' + ipseg);
              lip = lip.substr(pos + 1);
              pos = lip.find(",");
            }
            string ipseg = flag_l_v6 ? transfrom_to_ipseg_v6(trim(lip)) : transfrom_to_ipseg(trim(lip));
            if (!ipseg.empty())
              tmp_lip.insert("!" + ipseg);
          } else {
            size_t pos = lip.find(",");
            while(std::string::npos != pos) {
              string tmp = lip.substr(0, pos);
              string ipseg = flag_l_v6 ? transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
              if (!ipseg.empty())
                tmp_lip.insert(ipseg);
              lip = lip.substr(pos + 1);
              pos = lip.find(",");
            }
            string ipseg = flag_l_v6 ? transfrom_to_ipseg_v6(trim(lip)) : transfrom_to_ipseg(trim(lip));
            if (!ipseg.empty())
              tmp_lip.insert(ipseg);
          }
        } 
        if(flag_l_v6)
          lip6_.push_back(tmp_lip);
        else 
          lip_.push_back(tmp_lip);

        bool flag_t_v6 = false;
        set<string> tmp_tip;
        if(!tip.empty()) {
          if(tip.find(":") != tip.npos)
            flag_t_v6 = true;
          if (tip[0] == '!') {
            size_t left_pos = tip.find_first_not_of("(", 1);
            size_t right_pos = tip.find_last_not_of(")");

            tip = tip.substr(left_pos, right_pos - left_pos + 1);
            size_t pos = tip.find(",");
            while(std::string::npos != pos) {
              string tmp = tip.substr(0, pos);
              string ipseg = flag_t_v6 ? transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
              if (!ipseg.empty())
                tmp_tip.insert("!" + ipseg);
              tip = tip.substr(pos + 1);
              pos = tip.find(",");
            }
            string ipseg = flag_t_v6 ? transfrom_to_ipseg_v6(trim(tip)) : transfrom_to_ipseg(trim(tip));
            if (!ipseg.empty())
              tmp_tip.insert("!" + ipseg);
          } else {
            size_t pos = tip.find(",");
            while(std::string::npos != pos) {
              string tmp = tip.substr(0, pos);
              string ipseg = flag_t_v6 ? transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
              if (!ipseg.empty())
                tmp_tip.insert(ipseg);
              tip = tip.substr(pos + 1);
              pos = tip.find(",");
            }
            string ipseg = flag_t_v6 ? transfrom_to_ipseg_v6(trim(tip)) : transfrom_to_ipseg(trim(tip));
            if (!ipseg.empty())
              tmp_tip.insert(ipseg);
          }
        }
        if(flag_t_v6)
          tip6_.push_back(tmp_tip);
        else 
          tip_.push_back(tmp_tip);

        set<string> tmp_tport;
        if (tport.empty()) tport_.push_back(tmp_tport);
        else {
          if (tport[0] == '!') {
            size_t left_pos = tport.find_first_not_of("(", 1);
            size_t right_pos = tport.find_last_not_of(")");

            tport = tport.substr(left_pos, right_pos - left_pos + 1);
            size_t pos = tport.find(",");
            while(std::string::npos != pos) {
              string tmp = tport.substr(0, pos);
              tmp_tport.insert("!" + trim(tmp));
              tport = tport.substr(pos + 1);
              pos = tport.find(",");
            }
            tmp_tport.insert("!" + trim(tport));
          } else {
            size_t pos = tport.find(",");
            while(std::string::npos != pos) {
              string tmp = tport.substr(0, pos);
              tmp_tport.insert(trim(tmp));
              tport = tport.substr(pos + 1);
              pos = tport.find(",");
            }
            tmp_tport.insert(trim(tport));
          }
          tport_.push_back(tmp_tport);
        }
       
        set<string> tmp_proto;
        if (proto.empty())  proto_.push_back(tmp_proto);
        else {
          size_t pos = proto.find(",");
          while(std::string::npos != pos) {
            string tmp = proto.substr(0, pos);
            tmp = trim(tmp);
            if (is_protonum(tmp))
              tmp_proto.insert(proto_to_string(atoi(tmp.c_str())));
            else
              tmp_proto.insert(boost::to_upper_copy(tmp));
            proto = proto.substr(pos + 1);
            pos = proto.find(",");
          }
          proto = trim(proto);
          if (is_protonum(proto))
            tmp_proto.insert(proto_to_string(atoi(proto.c_str())));
          else
            tmp_proto.insert(boost::to_upper_copy(proto));
          proto_.push_back(tmp_proto);
        }

        set<string> tmp_domain;
        if (domain.empty())  domain_.push_back(tmp_domain);
        else {
          size_t pos = domain.find(",");
          while(std::string::npos != pos) {
            string tmp = domain.substr(0, pos);
            tmp = trim(tmp);
            tmp_domain.insert(tmp);
            domain = domain.substr(pos + 1);
            pos = domain.find(",");
          }
          domain = trim(domain);
          tmp_domain.insert(domain);
          domain_.push_back(tmp_domain);
        }
        
        struct Filter_time tmp_time;
        set_weekday(tmp_time, weekday);
        set_stime(tmp_time, stime);
        set_etime(tmp_time, etime);
        set_coverrange(tmp_time, coverrange);
        time_.push_back(tmp_time);
       
        count_.push_back(count);
 
        white_count++; 
      }

      res = *_sql  << "SELECT `obj`, `type` from `t_event_data_aggre`";
      string obj, type;
      while(res.next()) {
        res>>obj>>type;

        bool flag_v6 = false;
        size_t pos, pos1, pos2, sip_l, sip_r, dip_l, dip_r;
        struct in6_addr sip_v6,dip_v6;
        u32 sip,dip;
        string desc_domain; 
        //FIX: Condition: ":>[ipv6]:port protocol desc"
        sip_l = obj.find("[");
        pos1 = obj.find(">");

        if(sip_l != std::string::npos){//ipv6
          flag_v6 = true;
          if (sip_l > pos1) {//sip=""
            sip_v6 = ipstr_to_ipnum_v6("");
            dip_l = sip_l;
            dip_r = obj.find("]",dip_l+1);
            dip_v6 = ipstr_to_ipnum_v6(obj.substr(dip_l+1, dip_r-dip_l-1));
            pos2 = obj.find(":",dip_r+1);
          } else{
            sip_r = obj.find("]",sip_l+1);
            sip_v6 = ipstr_to_ipnum_v6(obj.substr(sip_l+1, sip_r-sip_l-1));
            dip_l = obj.find("[",pos1+1);
            dip_r = obj.find("]",dip_l+1);
            dip_v6 = ipstr_to_ipnum_v6(obj.substr(dip_l+1, dip_r-dip_l-1));
            pos2 = obj.find(":",dip_r+1);
          }
        } else {  //ipv4
          flag_v6 = false;
          pos = obj.find(":");
          sip = ipstr_to_ipnum(obj.substr(0, pos));
          pos2 = obj.find(":", pos1+1);
          dip = ipstr_to_ipnum(obj.substr(pos1+1, pos2-pos1-1));

        }
        size_t pos3 = obj.find(" ", pos2+1);
        u16 dport = atoi(obj.substr(pos2+1, pos3-pos2-1).c_str());
        size_t pos4 = obj.find(" ", pos3+1);
        size_t rpos = obj.rfind(" ");
        string prot, domain;
        prot = obj.substr(pos3+1, pos4-pos3-1);
        if (type == "dns_tun" || type == "dns") {
          domain = obj.substr(pos4+1, rpos-pos4-1);
        }

        bool is_white = false;
        bool lip_match = false, tip_match = false, tport_match = false, proto_match = false, domain_match = false;
        for(u32 i = 0;i < white_count;i++) {

          lip_match = flag_v6?check_ip_v6(lip6_[i], sip_v6):check_ip(lip_[i], sip);
          if (!lip_match) continue;
          tip_match = flag_v6?check_ip_v6(tip6_[i], dip_v6):check_ip(tip_[i], dip);
          if (!tip_match) continue;
          tport_match = check_port(tport_[i], dport);
          if (!tport_match) continue;
          proto_match = check_proto(proto_[i], prot);
          if (!proto_match) continue;
          domain_match = check_domain(domain_[i], domain);
          if (!domain_match) continue;
          

          if (lip_match && tip_match && tport_match && proto_match && domain_match) {
            is_white = true;
            count_[i]++;

            cppdb::statement st = *_sql <<"UPDATE `t_event_ignore` SET `count` = ?, `time` = FROM_UNIXTIME(?) WHERE `id` = ?";
            st<<count_[i]<<time(NULL)<<ids_[i]<<cppdb::exec;
            break;
          }
        }
        
        if (is_white) {
          cppdb::statement st = *_sql << "DELETE FROM `t_event_data` where `obj` = ?";
          try{
            st << obj << cppdb::exec;
          } catch ( cppdb::cppdb_error const &e ){
            log_err("%s", e.what());
            return Failed();
          }
          st = *_sql << "DELETE FROM `t_event_data_aggre` where `obj` = ?";
          try{
            st << obj << cppdb::exec;
          } catch ( cppdb::cppdb_error const &e ){
            log_err("%s", e.what());
            return Failed();
          }
        }
      }
      return Executed();
      break;
    }
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessType(){
	EventType *req = (EventType *)this->_req;

	switch (_op){
		case ADD:
			return false;
			break;
		case DEL:
			return false;
			break;
		case MOD:
			return false;
			break;
		case GET:{
			string str = "SELECT `id`, `desc` FROM `t_event_type` WHERE 1";

			if ( req->has_id() )
				str += " AND `id` = ?";
			if ( req->has_desc() )
				str += " AND `desc` = ?";

			cppdb::statement st = *_sql <<str;

			if ( req->has_id() )
				st <<req->id();
			if ( req->has_desc() )
				st <<req->desc();

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 id;
				string desc;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>id>>desc;
				output_u64("id", id);
				cout<<",";
				output_string("desc", desc);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessUrlType(){
  EventUrlType *req = (EventUrlType *)this->_req;

  switch (_op){
    case ADD:
      return false;
      break;
    case DEL:
      return false;
      break;
    case MOD:
      return false;
      break;
    case GET:{
      string str = "SELECT `id`, `desc` FROM `t_url_attack_type` WHERE 1";

      if ( req->has_id() )
        str += " AND `id` = ?";
      if ( req->has_desc() )
        str += " AND `desc` = ?";

      cppdb::statement st = *_sql <<str;

      if ( req->has_id() )
        st <<req->id();
      if ( req->has_desc() )
        st <<req->desc();

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 id;
        string desc;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>id>>desc;
        output_u64("id", id);
        cout<<",";
        output_string("desc", desc);
        cout<<"}";
      }
      break;
    }
    default:
      return false; // This code should never execute
      break;
  }

  return true;
}

bool ConfigEvent::ProcessConfigUrlContent(bool out_type) {
  EventConfig *req = (EventConfig *)this->_req;

  switch(_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_url_content`(`type`, `min`, `pat`) VALUES (?,?,?)";
      try{
        st << req->url_type() << req->min() << req->pat() << cppdb::exec;
      } catch (cppdb::cppdb_error const &e) {
        log_err("%s", e.what());
        return Failed();
      }
      system("/Server/bin/config_pusher >> dev/null 2>&1");
      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_url_content` WHERE `id` = ?";
      try{
        st << req->id() << cppdb::exec;
      } catch (cppdb::cppdb_error const &e) {
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");

      return Executed();
      break;
    } 
    case MOD:{
      string str = "UPDATE `t_event_config_url_content` SET ";
      if (req->has_url_type())
        stAddUpdateSet(str, "`type` = ?");
      if (req->has_min())
        stAddUpdateSet(str, "`min` = ?");
      if (req->has_pat())
        stAddUpdateSet(str, "`pat` = ?");

      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_url_type())
          st << req->url_type();
        if (req->has_min()) {
          if (req->min() == "")
            st << 0;
          else
            st << atol(req->min().c_str());
        } 
        if (req->has_pat())
          st << req->pat();

        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }
      
      system("/Server/bin/config_pusher >> /dev/null 2>&1");

      return Executed();
      break;
    }    
    case GET:{
      cppdb::statement st;
      string str = "SELECT `id`, `type`, `min`, `pat` FROM `t_event_config_url_content` WHERE 1";
      if (req != NULL) {
        if (req->has_id())
          str += " AND `id` = ?";
        if (req->has_url_type())
          str += " AND `type` = ?";
        if (req->has_pat())
          str += " AND `pat` = ?";

        st = *_sql <<str;
        if ( req->has_id() )
          st << req->id();
        if (req->has_url_type())
          st << req->url_type();
        if (req->has_pat())
          st << req->pat(); 
      } else
        st = *_sql <<str;

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;
        
        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        if (out_type){
          output_string("config_type", "thres");
          cout<<",";
        }

        r>>u;
        output_u64("type", u);
        cout<<",";

        r>>u;
        output_u64("min", u);
        cout<<",";

        r>>s;
        output_string("pat", s);
        cout<<"}";
      }
      break;
    }
    default:
      return false; // This code should never execute
      break;
  }

  return true;
}

bool ConfigEvent::ProcessConfigThreshold(bool out_type){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:{
			cppdb::statement st = *_sql << "INSERT INTO `t_event_config_threshold`(`moid`, `thres_mode`, `data_type`, `min`, `max`, `grep_rule`) VALUES (?,?,?,?,?,?)";
			try{
				st << req->moid() << req->thres_mode() << req->data_type();
				if (req->min()=="")
					st << cppdb::null;
				else
					st << req->min();
				if (req->max()=="")
					st << cppdb::null;
				else
					st << req->max();
				st << req->grep_rule() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
			cppdb::statement st = *_sql << "DELETE FROM `t_event_config_threshold` WHERE `id` = ?;";
			try{
				st << req->id() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case MOD:{
			string str = "UPDATE `t_event_config_threshold` SET ";
			if (req->has_moid())
				stAddUpdateSet(str, "`moid` = ?");
			if (req->has_thres_mode())
				stAddUpdateSet(str, "`thres_mode` = ?");
			if (req->has_data_type())
				stAddUpdateSet(str, "`data_type` = ?");
			if (req->has_min())
				stAddUpdateSet(str, "`min` = ?");
			if (req->has_max())
				stAddUpdateSet(str, "`max` = ?");
			if (req->has_grep_rule())
				stAddUpdateSet(str, "`grep_rule` = ?");
			str+=" WHERE id = ?";
			try{
				cppdb::statement st = *_sql <<str;
				if (req->has_moid())
					st << req->moid();
				if (req->has_thres_mode())
					st << req->thres_mode();
				if (req->has_data_type())
					st << req->data_type();
				if (req->has_min()){
					if (req->min()=="")
						st << cppdb::null;
					else
						st << atol(req->min().c_str());
				}
				if (req->has_max()){
					if (req->max()=="")
						st << cppdb::null;
					else
						st << atol(req->max().c_str());
				}
				if (req->has_grep_rule())
					st << req->grep_rule();
				st<<req->id();
				st<<cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case GET:{
			cppdb::statement st;
			string str = "SELECT `id`, `moid`, `thres_mode`, `data_type`, `min`, `max`, `grep_rule` FROM `t_event_config_threshold` WHERE 1";

			if ( req!=NULL ){
				if ( req->has_id() )
					str += " AND `id` = ?";
				if ( req->has_moid() )
					str += " AND `moid` = ?";
				if ( req->has_thres_mode() )
					str += " AND `thres_mode` = ?";
				if ( req->has_data_type() )
					str += " AND `data_type` = ?";
				if ( req->has_min() ){
					if ( req->min()=="" )
						str += " AND `min` IS NULL";
					else
						str += " AND `min` = ?";
				}
				if ( req->has_max() ){
					if ( req->max()=="" )
						str += " AND `max` IS NULL";
					else
						str += " AND `max` = ?";
				}
				if (req->has_grep_rule())
					str += " AND `grep_rule` = ?";

				st = *_sql <<str;

				if ( req->has_id() )
					st <<req->id();
				if ( req->has_moid() )
					st <<req->moid();
				if ( req->has_thres_mode() )
					st <<req->thres_mode();
				if ( req->has_data_type() )
					st <<req->data_type();
				if ( req->has_min() && req->min()!="" )
					st <<req->min();
				if ( req->has_max() && req->max()!="" )
					st <<req->max();
				if (req->has_grep_rule())
					st <<req->grep_rule();
			}
			else
				st = *_sql <<str;

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 u;
				string s;
				cppdb::null_tag_type null_tag;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>u;
				output_u64("id", u);
				cout<<",";

				if (out_type){
					output_string("config_type", "thres");
					cout<<",";
				}

				r>>u;
				output_u64("moid", u);
				cout<<",";

				r>>s;
				output_string("thres_mode", s);
				cout<<",";

				r>>s;
				output_string("data_type", s);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("min","");
				else
					output_u64("min", u);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("max","");
				else
					output_u64("max", u);
				cout<<",";

				r>>s;
				output_string("grep_rule", s);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessConfigSus(bool out_type){
  EventConfig *req = (EventConfig *)this->_req;
  
  switch (_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_sus`(`data_type`, `min`, `max`) VALUES (?,?,?)";
      try{
        st << req->data_type() << req->min();
        if (req->max()=="")
          st << cppdb::null;
        else
          st << req->max();
        st << cppdb::exec;
      } catch (cppdb::cppdb_error const &e) {
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");
      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_sus` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");
      return Executed();
      break;
    }
    case MOD:{
      string str = "UPDATE `t_event_config_sus` SET ";
      if (req->has_data_type())
        stAddUpdateSet(str, "`data_type` = ?");
      if (req->has_min())
        stAddUpdateSet(str, "`min` = ?");
      if (req->has_max())
        stAddUpdateSet(str, "`max` = ?");
      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_data_type())
          st << req->data_type();
        if (req->has_min())
          st << atol(req->min().c_str());
        if (req->has_max()) {
          if (req->max() == "")
            st << cppdb::null;
          else 
            st << atol(req->max().c_str());
        }
        st<<req->id();
        st<<cppdb::exec;
      } catch (cppdb::cppdb_error const &e) {
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");
      return Executed();
      break;
    }
    case GET:{
      cppdb::statement st;
      string str = "SELECT `id`, `data_type`, `min`, `max` FROM `t_event_config_sus` WHERE 1"; 
      if (req != NULL){
        if (req->has_id())
          str += " AND `id` = ?";
        if (req->has_data_type())
          str += " AND `data_type` = ?";
        if (req->has_min())
          str += " AND `min` = ?";
        if (req->has_max()){
          if (req->max() == "")
            str += " AND `max` IS NULL";
          else
            str += " AND `max` = ?";
        }
        st = *_sql <<str;
        if (req->has_id())
          st <<req->id();
        if (req->has_data_type())
          st <<req->data_type();
        if (req->has_min())
          st <<req->min();
        if (req->max() != "")
          st <<req->max();
      } else 
        st = *_sql <<str;

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;
        cppdb::null_tag_type null_tag;
        
        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        if (out_type){
          output_string("config_type", "sus");
          cout<<",";
        }

        r>>s;
        output_string("data_type", s);
        cout<<",";

        r>>u;
        output_u64("min", u);
        cout<<",";

        r>>cppdb::into(u,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("max","");
        else 
          output_u64("max", u);
        cout<<"}";
      }
      break;
    }
    default:
      return false; // This code should never execute
      break;
  }
  
  return true;
}

bool ConfigEvent::ProcessConfigBlack(bool out_type){
  EventConfig *req = (EventConfig *)this->_req;
  
  switch (_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_black`(`data_type`, `min`, `max`) VALUES (?,?,?)";
      try{
        st << req->data_type() << req->min();
        if (req->max()=="")
          st << cppdb::null;
        else
          st << req->max();
        st << cppdb::exec;
      } catch (cppdb::cppdb_error const &e) {
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");
      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_black` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");
      return Executed();
      break;
    }
    case MOD:{
      string str = "UPDATE `t_event_config_black` SET ";
      if (req->has_data_type())
        stAddUpdateSet(str, "`data_type` = ?");
      if (req->has_min())
        stAddUpdateSet(str, "`min` = ?");
      if (req->has_max())
        stAddUpdateSet(str, "`max` = ?");
      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_data_type())
          st << req->data_type();
        if (req->has_min())
          st << atol(req->min().c_str());
        if (req->has_max()) {
          if (req->max() == "")
            st << cppdb::null;
          else 
            st << atol(req->max().c_str());
        }
        st<<req->id();
        st<<cppdb::exec;
      } catch (cppdb::cppdb_error const &e) {
        log_err("%s", e.what());
        return Failed();
      }

      system("/Server/bin/config_pusher >> /dev/null 2>&1");
      return Executed();
      break;
    }
    case GET:{
      cppdb::statement st;
      string str = "SELECT `id`, `data_type`, `min`, `max` FROM `t_event_config_black` WHERE 1"; 
      if (req != NULL){
        if (req->has_id())
          str += " AND `id` = ?";
        if (req->has_data_type())
          str += " AND `data_type` = ?";
        if (req->has_min())
          str += " AND `min` = ?";
        if (req->has_max()){
          if (req->max() == "")
            str += " AND `max` IS NULL";
          else
            str += " AND `max` = ?";
        }
        st = *_sql <<str;
        if (req->has_id())
          st <<req->id();
        if (req->has_data_type())
          st <<req->data_type();
        if (req->has_min())
          st <<req->min();
        if (req->max() != "")
          st <<req->max();
      } else 
        st = *_sql <<str;

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;
        cppdb::null_tag_type null_tag;
        
        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        if (out_type){
          output_string("config_type", "black");
          cout<<",";
        }

        r>>s;
        output_string("data_type", s);
        cout<<",";

        r>>u;
        output_u64("min", u);
        cout<<",";

        r>>cppdb::into(u,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("max","");
        else 
          output_u64("max", u);
        cout<<"}";
      }
      break;
    }
    default:
      return false; // This code should never execute
      break;
  }
  
  return true;
}

bool ConfigEvent::ProcessConfigPortScan(bool out_type){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:{
			cppdb::statement st = *_sql << "INSERT INTO `t_event_config_port_scan`(`min_peerips`, `max_peerips`, `ip`, `port`, `protocol`) VALUES (?,?,?,?,?)";
			try{
				st << req->min_peerips();
				if ( req->max_peerips()=="" )
					st << cppdb::null;
				else
					st << req->max_peerips();
				if ( req->ip()=="" )
					st << cppdb::null;
				else
					st << req->ip();
				if ( req->port()=="" )
					st << cppdb::null;
				else
					st << req->port();
				if ( req->protocol()=="" )
					st << cppdb::null;
				else
					st << req->protocol();
				st << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
			cppdb::statement st = *_sql << "DELETE FROM `t_event_config_port_scan` WHERE `id` = ?;";
			try{
				st << req->id() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case MOD:{
			string str = "UPDATE `t_event_config_port_scan` SET ";
			if (req->has_min_peerips())
				stAddUpdateSet(str, "`min_peerips` = ?");
			if (req->has_max_peerips())
				stAddUpdateSet(str, "`max_peerips` = ?");
			if (req->has_ip())
				stAddUpdateSet(str, "`ip` = ?");
			if (req->has_port())
				stAddUpdateSet(str, "`port` = ?");
			if (req->has_protocol())
				stAddUpdateSet(str, "`protocol` = ?");
			str+=" WHERE id = ?";
			try{
				cppdb::statement st = *_sql <<str;
				if (req->has_min_peerips())
					st << req->min_peerips();
				if (req->has_max_peerips()){
					if (req->max_peerips()=="")
						st << cppdb::null;
					else
						st << atol(req->max_peerips().c_str());
				}
				if (req->has_ip()){
					if (req->ip()=="")
						st << cppdb::null;
					else
						st << req->ip();
				}
				if (req->has_port()){
					if (req->port()=="")
						st << cppdb::null;
					else
						st << req->port();
				}
				if (req->has_protocol()){
					if (req->protocol()=="")
						st << cppdb::null;
					else
						st << req->protocol();
				}
				st<<req->id();
				st<<cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case GET:{
			cppdb::statement st;
			string str = "SELECT `id`, `min_peerips`, `max_peerips`, `ip`, `port`, `protocol` FROM `t_event_config_port_scan` WHERE 1";

			if ( req!=NULL ){
				if ( req->has_id() )
					str += " AND `id` = ?";
				if ( req->has_min_peerips() )
					str += " AND `min_peerips` = ?";
				if ( req->has_max_peerips() ){
					if (req->max_peerips()=="")
						str += " AND `max_peerips` IS NULL";
					else
						str += " AND `max_peerips` = ?";
				}
				if ( req->has_ip() ){
					if (req->ip()=="")
						str += " AND `ip` IS NULL";
					else
						str += " AND `ip` = ?";
				}
				if ( req->has_port() ){
					if (req->port()=="")
						str += " AND `port` IS NULL";
					else
						str += " AND `port` = ?";
				}
				if ( req->has_protocol() ){
					if (req->protocol()=="")
						str += " AND `protocol` IS NULL";
					else
						str += " AND `protocol` = ?";
				}

				st = *_sql <<str;

				if ( req->has_id() )
					st <<req->id();
				if ( req->has_min_peerips() )
					st <<req->min_peerips();
				if ( req->max_peerips()!="")
					st <<req->max_peerips();
				if ( req->ip()!="")
					st <<req->ip();
				if ( req->port()!="")
					st <<req->port();
				if (req->protocol()!="")
					st <<req->protocol();
			}
			else
				st = *_sql <<str;

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 u;
				string s;
				cppdb::null_tag_type null_tag;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>u;
				output_u64("id", u);
				cout<<",";

				if (out_type){
					output_string("config_type", "port_scan");
					cout<<",";
				}

				r>>u;
				output_u64("min_peerips", u);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("max_peerips","");
				else
					output_u64("max_peerips", u);
				cout<<",";

				r>>cppdb::into(s,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("ip","");
				else
					output_string("ip", s);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("port","");
				else
					output_u64("port", u);
				cout<<",";

				r>>cppdb::into(s,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("protocol","");
				else
					output_string("protocol", s);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessConfigIPScan(bool out_type){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:{
			cppdb::statement st = *_sql << "INSERT INTO `t_event_config_ip_scan`(`min_peerports`, `max_peerports`, `sip`, `dip`, `protocol`) VALUES (?,?,?,?,?)";
			try{
				st << req->min_peerports();
				if ( req->max_peerports()=="" )
					st << cppdb::null;
				else
					st << req->max_peerports();
				if ( req->sip()=="" )
					st << cppdb::null;
				else
					st << req->sip();
				if ( req->dip()=="" )
					st << cppdb::null;
				else
					st << req->dip();
				if ( req->protocol()=="" )
					st << cppdb::null;
				else
					st << req->protocol();
				st << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
			cppdb::statement st = *_sql << "DELETE FROM `t_event_config_ip_scan` WHERE `id` = ?;";
			try{
				st << req->id() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case MOD:{
			string str = "UPDATE `t_event_config_ip_scan` SET ";
			if (req->has_min_peerports())
				stAddUpdateSet(str, "`min_peerports` = ?");
			if (req->has_max_peerports())
				stAddUpdateSet(str, "`max_peerports` = ?");
			if (req->has_sip())
				stAddUpdateSet(str, "`sip` = ?");
			if (req->has_dip())
				stAddUpdateSet(str, "`dip` = ?");
			if (req->has_protocol())
				stAddUpdateSet(str, "`protocol` = ?");
			str+=" WHERE id = ?";
			try{
				cppdb::statement st = *_sql <<str;
				if (req->has_min_peerports())
					st << req->min_peerports();
				if (req->has_max_peerports()){
					if (req->max_peerports()=="")
						st << cppdb::null;
					else
						st << atol(req->max_peerports().c_str());
				}
				if (req->has_sip()){
					if (req->sip()=="")
						st << cppdb::null;
					else
						st << req->sip();
				}
				if (req->has_dip()){
					if (req->dip()=="")
						st << cppdb::null;
					else
						st << req->dip();
				}
				if (req->has_protocol()){
					if (req->protocol()=="")
						st << cppdb::null;
					else
						st << req->protocol();
				}
				st<<req->id();
				st<<cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case GET:{
			cppdb::statement st;
			string str = "SELECT `id`, `min_peerports`, `max_peerports`, `sip`, `dip`, `protocol` FROM `t_event_config_ip_scan` WHERE 1";

			if ( req!=NULL ){
				if ( req->has_id() )
					str += " AND `id` = ?";
				if ( req->has_min_peerports() )
					str += " AND `min_peerports` = ?";
				if ( req->has_max_peerports() ){
					if (req->max_peerports()=="")
						str += " AND `max_peerports` IS NULL";
					else
						str += " AND `max_peerports` = ?";
				}
				if ( req->has_sip() ){
					if (req->sip()=="")
						str += " AND `sip` IS NULL";
					else
						str += " AND `sip` = ?";
				}
				if ( req->has_dip() ){
					if (req->dip()=="")
						str += " AND `dip` IS NULL";
					else
						str += " AND `dip` = ?";
				}
				if ( req->has_protocol() ){
					if (req->protocol()=="")
						str += " AND `protocol` IS NULL";
					else
						str += " AND `protocol` = ?";
				}

				st = *_sql <<str;

				if ( req->has_id() )
					st <<req->id();
				if ( req->has_min_peerports() )
					st <<req->min_peerports();
				if ( req->max_peerports()!="")
					st <<req->max_peerports();
				if ( req->sip()!="")
					st <<req->sip();
				if ( req->dip()!="")
					st <<req->dip();
				if (req->protocol()!="")
					st <<req->protocol();
			}
			else
				st = *_sql <<str;

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 u;
				string s;
				cppdb::null_tag_type null_tag;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>u;
				output_u64("id", u);
				cout<<",";

				if (out_type){
					output_string("config_type", "ip_scan");
					cout<<",";
				}

				r>>u;
				output_u64("min_peerports", u);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("max_peerports","");
				else
					output_u64("max_peerports", u);
				cout<<",";

				r>>cppdb::into(s,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("sip","");
				else
					output_string("sip", s);
				cout<<",";

				r>>cppdb::into(s,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("dip","");
				else
					output_string("dip", s);
				cout<<",";

				r>>cppdb::into(s,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("protocol","");
				else
					output_string("protocol", s);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessConfigSrv(bool out_type){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:{
			cppdb::statement st = *_sql << "INSERT INTO `t_event_config_srv`(`min_portsessions`, `max_portsessions`, `ip`, `port`, `protocol`) VALUES (?,?,?,?,?)";
			try{
				st << req->min_portsessions();
				if ( req->max_portsessions()=="" )
					st << cppdb::null;
				else
					st << req->max_portsessions();
				st << req->ip();
				if ( req->port()=="" )
					st << cppdb::null;
				else
					st << req->port();
				if ( req->protocol()=="" )
					st << cppdb::null;
				else
					st << req->protocol();
				st << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
			cppdb::statement st = *_sql << "DELETE FROM `t_event_config_srv` WHERE `id` = ?;";
			try{
				st << req->id() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case MOD:{
			string str = "UPDATE `t_event_config_srv` SET ";
			if (req->has_min_portsessions())
				stAddUpdateSet(str, "`min_portsessions` = ?");
			if (req->has_max_portsessions())
				stAddUpdateSet(str, "`max_portsessions` = ?");
			if (req->has_ip())
				stAddUpdateSet(str, "`ip` = ?");
			if (req->has_port())
				stAddUpdateSet(str, "`port` = ?");
			if (req->has_protocol())
				stAddUpdateSet(str, "`protocol` = ?");
			str+=" WHERE id = ?";
			try{
				cppdb::statement st = *_sql <<str;
				if (req->has_min_portsessions())
					st << req->min_portsessions();
				if (req->has_max_portsessions()){
					if (req->max_portsessions()=="")
						st << cppdb::null;
					else
						st << req->max_portsessions();
				}
				if (req->has_ip())
					st << req->ip();
				if (req->has_port()){
					if (req->port()=="")
						st << cppdb::null;
					else
						st << req->port();
				}
				if (req->has_protocol()){
					if (req->protocol()=="")
						st << cppdb::null;
					else
						st << req->protocol();
				}
				st<<req->id();
				st<<cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			system("/Server/bin/config_pusher >> /dev/null 2>&1");

			return Executed();
			break;
		}
		case GET:{
			cppdb::statement st;
			string str = "SELECT `id`, `min_portsessions`, `max_portsessions`, `ip`, `port`, `protocol` FROM `t_event_config_srv` WHERE 1";

			if ( req!=NULL ){
				if ( req->has_id() )
					str += " AND `id` = ?";
				if ( req->has_min_portsessions() )
					str += " AND `min_portsessions` = ?";
				if ( req->has_max_portsessions() ){
					if (req->max_portsessions()=="")
						str += " AND `max_portsessions` IS NULL";
					else
						str += " AND `max_portsessions` = ?";
				}
				if ( req->has_ip() )
					str += " AND `ip` = ?";
				if ( req->has_port() ){
					if (req->port()=="")
						str += " AND `port` IS NULL";
					else
						str += " AND `port` = ?";
				}
				if ( req->has_protocol() ){
					if (req->protocol()=="")
						str += " AND `protocol` IS NULL";
					else
						str += " AND `protocol` = ?";
				}

				st = *_sql <<str;

				if ( req->has_id() )
					st <<req->id();
				if ( req->has_min_portsessions() )
					st <<req->min_portsessions();
				if ( req->max_portsessions()!="" )
					st <<req->max_portsessions();
				if ( req->has_ip() )
					st <<req->ip();
				if ( req->port()!="")
					st <<req->port();
				if (req->protocol()!="")
					st <<req->protocol();
			}
			else
				st = *_sql <<str;

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 u;
				string s;
				cppdb::null_tag_type null_tag;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>u;
				output_u64("id", u);
				cout<<",";

				if (out_type){
					output_string("config_type", "srv");
					cout<<",";
				}

				r>>u;
				output_u64("min_portsessions", u);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("max_portsessions","");
				else
					output_u64("max_portsessions", u);
				cout<<",";

				r>>s;
				output_string("ip", s);
				cout<<",";

				r>>cppdb::into(u,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("port","");
				else
					output_u64("port", u);
				cout<<",";

				r>>cppdb::into(s,null_tag);
				if (null_tag==cppdb::null_value)
					output_string("protocol","");
				else
					output_string("protocol", s);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessLevel(){
	EventLevel *req = (EventLevel *)this->_req;

	switch (_op){
		case ADD:
			return false;
			break;
		case DEL:
			return false;
			break;
		case MOD:
			return false;
			break;

		case GET:{
			string str = "SELECT `id`, `desc`, `profile` FROM `t_event_level` WHERE 1";

			if ( req->has_id() )
				str += " AND `id` = ?";
			if ( req->has_desc() )
				str += " AND `desc` = ?";
			if ( req->has_profile() )
				str += " AND `profile` = ?";

			cppdb::statement st = *_sql <<str;

			if ( req->has_id() )
				st <<req->id();
			if ( req->has_desc() )
				st <<req->desc();
			if ( req->has_profile() )
				st <<req->profile();

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 id;
				string desc, profile;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>id>>desc>>profile;
				output_u64("id", id);
				cout<<",";
				output_string("desc", desc);
				cout<<",";
				output_string("profile", profile);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessAction(){
	EventAction *req = (EventAction *)this->_req;

	switch (_op){
		case ADD:{
			cppdb::statement st = *_sql << "INSERT INTO `t_event_action`(`act`, `mail`, `phone`, `uid`, `desc`) VALUES (?,?,?,?,?)";
			try{
				st << req->act() << req->mail() << req->phone() << req->uid() << req->desc();
				st << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
			cppdb::statement st = *_sql << "DELETE FROM `t_event_action` WHERE `id` = ?;";
			try{
				st << req->action_id() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			return Executed();
			break;
		}
		case MOD:{
			string str = "UPDATE `t_event_action` SET ";
			if (req->has_act())
				stAddUpdateSet(str, "`act` = ?");
			if (req->has_mail())
				stAddUpdateSet(str, "`mail` = ?");
			if (req->has_phone())
				stAddUpdateSet(str, "`phone` = ?");
			if (req->has_uid())
				stAddUpdateSet(str, "`uid` = ?");
			if (req->has_desc())
				stAddUpdateSet(str, "`desc` = ?");
			str+=" WHERE id = ?";
			try{
				cppdb::statement st = *_sql <<str;
				if (req->has_act())
					st << req->act();
				if (req->has_mail())
					st << req->mail();
				if (req->has_phone())
					st << req->phone();
				if (req->has_uid())
					st << req->uid();
				if (req->has_desc())
					st << req->desc();
				st<<req->action_id();
				st<<cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			return Executed();
			break;
		}
		case GET:{
			string str = "SELECT `id`, `act`, `mail`, `phone`, `uid`, `desc` FROM `t_event_action` WHERE 1";

			if ( req->has_action_id() )
				str += " AND `id` = ?";
			if ( req->has_act() )
				str += " AND `act` = ?";
			if ( req->has_mail() )
				str += " AND `mail` = ?";
			if ( req->has_phone() )
				str += " AND `phone` = ?";
			if ( req->has_uid() )
				str += " AND `uid` = ?";
			if ( req->has_desc() )
				str += " AND `desc` = ?";

			cppdb::statement st = *_sql <<str;

			if ( req->has_action_id() )
				st <<req->action_id();
			if ( req->has_act() )
				st <<req->act();
			if ( req->has_mail() )
				st <<req->mail();
			if ( req->has_phone() )
				st <<req->phone();
			if ( req->has_uid() )
				st <<req->uid();
			if ( req->has_desc() )
				st <<req->desc();

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 u;
				string s;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>u;
				output_u64("id", u);
				cout<<",";

				r>>u;
				output_u64("act", u);
				cout<<",";

				r>>s;
				output_string("mail", s);
				cout<<",";

				r>>s;
				output_string("phone", s);
				cout<<",";

				r>>s;
				output_string("uid", s);
				cout<<",";

				r>>s;
				output_string("desc", s);
				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessConfigAll(){
	if(!this->ProcessConfigThreshold(true))
		return false;
	cout<<","<<endl;
	if(!this->ProcessConfigSrv(true))
		return false;
	cout<<","<<endl;
	if(!this->ProcessConfigPortScan(true))
		return false;

	return true;
}

bool ConfigEvent::ProcessDataAggre(){
	EventDataAggre* tmp_req = (EventDataAggre *)this->_req;
	EventDataAggre& req = *tmp_req;
	ostream& output = cout;

	switch (_op){
		case ADD:
			return false;
			break;
		case DEL:
			return false;
			break;
		case MOD:
			return false;
			break;

		case GET:{
			string str = "SELECT `id`, `event_id`, `devid`, `obj`, `type`, `level`, `alarm_peak`, `sub_events`, `alarm_avg`, `value_type`, `desc`, `duration`, `starttime`, `endtime`, `is_alive` "
			             "FROM `t_event_data_aggre` WHERE ( ";
			stAddWhere(str,"`starttime` >= ?");
			stAddWhere(str,"`endtime` <= ?");
			if (req.has_id())
			  stAddWhere(str,"`id` = ?");
			if (req.has_type())
			  stAddWhere(str,"`type` = ?");
			if (req.has_devid())
			  stAddWhere(str,"`devid` = ?");
			if (req.has_event_id())
			  stAddWhere(str,"`event_id` = ?");
			if (req.has_obj())
			  stAddWhere(str,"`obj` LIKE ?");
			if (req.has_level())
			  stAddWhere(str,"`level` = ?");
			str += " ) ORDER BY `starttime`";

			cppdb::statement st = *_sql <<str;
			st<<req.starttime()<<req.endtime();
			if (req.has_id())
			  st<<req.id();
			if (req.has_type())
			  st<<req.type();
			if (req.has_devid())
			  st<<req.devid();
			if (req.has_event_id())
			  st<<req.event_id();
			if (req.has_obj())
			  st<<"%"+req.obj()+"%";
			if (req.has_level())
			  st<<req.level();

			try{
			  cppdb::result r = st;
			  string s;
			  u32 u;
			  bool first = true;

			  while(r.next()){
			    if (first)
			      first=false;
			    else
			      output<<","<<endl;

			    output<<"{";

			    r>>u;
			    output_u64("id", u);
			    output<<',';

			    r>>u;
			    output_u64("event_id", u);
			    output<<',';

			    r>>u;
			    output_u64("devid", u);
			    output<<',';

			    r>>s;
			    output_string("obj", s);
			    output<<',';

			    r>>s;
			    output_string("type", s);
			    output<<',';

			    r>>s;
			    output_string("level", s);
			    output<<',';

			    r>>u;
			    output_u64("alarm_peak", u);
			    output<<',';

			    r>>u;
			    output_u64("sub_events", u);
			    output<<',';

			    r>>u;
			    output_u64("alarm_avg", u);
			    output<<',';

			    r>>s;
			    output_string("value_type", s);
			    output<<',';

			    r>>s;
			    output_string("desc", s);
			    output<<',';

			    r>>u;
			    output_u64("duration", u);
			    output<<',';

			    r>>u;
			    output_u64("starttime", u);
			    output<<',';

			    r>>u;
			    output_u64("endtime", u);
			    output<<',';

			    r>>u;
			    output_u64("is_alive", u);
			    output<<"}";
			  }
			} catch ( cppdb::cppdb_error const &e ){
			  log_err("%s", e.what());
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessConfigDnstunAI(bool out_type) {
  EventConfig *req = (EventConfig *)this->_req;
  
  switch (_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_dnstun_ai`(`sip`, `dip`, `min`) VALUES (?,?,?)";
      try{
        if (req->sip().empty())
          st << cppdb::null;
        else
          st << req->sip();

        if (req->dip().empty())
          st << cppdb::null;
        else
          st << req->dip();

        st << req->min() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL: {
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_dnstun_ai` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case MOD:{
      string str = "UPDATE `t_event_config_dnstun_ai` SET ";
      if (req->has_sip())
        stAddUpdateSet(str, "`sip` = ?");
      if (req->has_dip())
        stAddUpdateSet(str, "`dip` = ?");
      if (req->has_min())
        stAddUpdateSet(str, "`min` = ?");
      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_sip()) {
          if (req->sip().empty())
            st << cppdb::null;
          else
            st << req->sip();
        }
        if (req->has_dip()) {
          if (req->dip().empty())
            st << cppdb::null;
          else
            st << req->dip();
        }
        if (req->has_min())
          st << req->min();

        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    } 
    case GET: {
      cppdb::statement st;
      string str = "SELECT `id`, `sip`, `dip`, `min` FROM `t_event_config_dnstun_ai` WHERE 1";

      if ( req!=NULL ){
        if ( req->has_id() )
          str += " AND `id` = ?";

        st = *_sql <<str;

        if ( req->has_id() )
          st << req->id();
      }
      else
        st = *_sql <<str;

      cppdb::result r = st;
      bool first = true;
      while(r.next()) {
        u64 u;
        string s;
        cppdb::null_tag_type null_tag;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("sip", "");
        else
          output_string("sip", s);
        cout<<",";         

        r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("dip", "");
        else
          output_string("dip", s);
        cout<<",";

        r>>u;
        output_u64("min", u);

        cout<<"}";
      }
      break;
    }
    default:
      return false;
      break;
  }   

  return true;
}

bool ConfigEvent::ProcessConfigDga(bool out_type){
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_dga`(`sip`, `dip`, `qcount`, `min`) VALUES (?,?,?,?)";
      try{
        if (req->sip().empty())
          st << cppdb::null;
        else
          st << req->sip();

        if (req->dip().empty())
          st << cppdb::null;
        else
          st << req->dip();

        if (req->has_qcount())
          st << req->qcount();

        st << req->min() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL: {
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_dga` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;     
    }
    case MOD:{
      string str = "UPDATE `t_event_config_dga` SET ";
      if (req->has_sip())
        stAddUpdateSet(str, "`sip` = ?");
      if (req->has_dip())
        stAddUpdateSet(str, "`dip` = ?");
      if (req->has_qcount())
        stAddUpdateSet(str, "`qcount` = ?");
      if (req->has_min())
        stAddUpdateSet(str, "`min` = ?");
      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_sip()) {
          if (req->sip().empty())
            st << cppdb::null;
          else
            st << req->sip();
        }
        if (req->has_dip()) {
          if (req->dip().empty())
            st << cppdb::null;
          else
            st << req->dip();
        }
        if (req->has_qcount())
          st << req->qcount();
        if (req->has_min())
          st << req->min();

        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case GET: {
      cppdb::statement st;
      string str = "SELECT `id`, `sip`, `dip`, `qcount`, `min`  FROM `t_event_config_dga` WHERE 1";

      if ( req!=NULL ){
        if ( req->has_id() )
          str += " AND `id` = ?";

        st = *_sql <<str;

        if ( req->has_id() )
          st << req->id();
      }
      else
        st = *_sql <<str;

      cppdb::result r = st;
      bool first = true;
      while(r.next()) {
        u64 u;
        string s;
        cppdb::null_tag_type null_tag;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("sip", "");
        else
          output_string("sip", s);
        cout<<",";

        r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("dip", "");
        else
          output_string("dip", s);
        cout<<",";

        r>>u;
        output_u64("qcount", u);
        cout<<",";      

        r>>u;
        output_u64("min", u);

        cout<<"}"; 
      } 
      break;
    }
    default:
      return false;
      break; 
  }

  return true;
}

bool ConfigEvent::ProcessConfigDns(bool out_type){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:{
			cppdb::statement st = *_sql << "INSERT INTO `t_event_config_dns`(`ip`, `qname`, `qcount`, `desc`) VALUES (?,?,?,?)";
			try{
        if (req->ip().empty())
          st << cppdb::null;
        else
          st << req->ip();
        
        if (req->qname().empty())
          st << cppdb::null;
        else
          st << req->qname();

				st << req->qcount() << req->desc();
				st << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			return Executed("\"id\": "+to_string(st.last_insert_id()));
			break;
		}
		case DEL:{
			cppdb::statement st = *_sql << "DELETE FROM `t_event_config_dns` WHERE `id` = ?;";
			try{
				st << req->id() << cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			return Executed();
			break;
		}
		case MOD:{
			string str = "UPDATE `t_event_config_dns` SET ";
			if (req->has_ip())
				stAddUpdateSet(str, "`ip` = ?");
			if (req->has_qname())
				stAddUpdateSet(str, "`qname` = ?");
			if (req->has_qcount())
				stAddUpdateSet(str, "`qcount` = ?");
			if (req->has_desc())
				stAddUpdateSet(str, "`desc` = ?");
			str+=" WHERE id = ?";
			try{
				cppdb::statement st = *_sql <<str;
        if (req->has_ip()) {
          if (req->ip().empty())
            st << cppdb::null;
          else
            st << req->ip();
        } 
        if (req->has_qname()) {
          if (req->qname().empty())
            st << cppdb::null;
          else
            st << req->qname();
        }
				if (req->has_qcount())
				  st << req->qcount();
				if (req->has_desc())
				  st << req->desc();
	
				st<<req->id();
				st<<cppdb::exec;
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}

			return Executed();
			break;
		}
		case GET:{
			cppdb::statement st;
			string str = "SELECT `id`, `ip`, `qname`, `qcount`, `desc` FROM `t_event_config_dns` WHERE 1";

			if ( req!=NULL ){
				if ( req->has_id() )
					str += " AND `id` = ?";
				if ( req->has_ip() ) {
          if (req->ip().empty())
					  str += " AND `ip` IS NULL";
          else
            str += " AND `ip` = ?";
        }
				if ( req->has_qname() ) {
          if (req->qname().empty())
            str += " AND `qname` IS NULL";
          else
					  str += " AND `qname` = ?";
        }
				if ( req->has_qcount() )
					str += " AND `qcount` = ?";
        if ( req->has_desc() )
          str += " AND `desc` = ?";

				st = *_sql <<str;

				if ( req->has_id() )
					st << req->id();
				if ( !req->ip().empty() )
					st << req->ip();
				if ( !req->qname().empty() )
					st << req->qname();
				if ( req->has_qcount() )
					st << req->qcount();
				if ( req->has_desc() )
					st << req->desc();
			}
			else
				st = *_sql <<str;

			cppdb::result r = st;
			bool first = true;
			while (r.next()){
				u64 u;
				string s;
				cppdb::null_tag_type null_tag;

				if (first){
					cout<<"{";
					first = false;
				}
				else
					cout<<","<<endl<<"{";

				r>>u;
				output_u64("id", u);
				cout<<",";

				r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("ip", "");
        else
				  output_string("ip", s);
				cout<<",";

				r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("qname", "");
        else
				  output_string("qname", s);
				cout<<",";

				r>>u;
				output_u64("qcount", u);
        cout<<",";
  
        r>>s;
        output_string("desc", s);

				cout<<"}";
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ProcessConfigIcmpTun(bool out_type){
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op) {
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_icmp_tunnel`(`sip`, `dip`, `IF1`, `IF2`, `IF3`, `desc`) VALUES (?,?,?,?,?,?)";
      try{
        if (req->has_sip())
          st << req->sip();
        if (req->has_dip())
          st << req->dip();
        st << req->if1() << req->if2() << req->if3();
        st << req->desc();
        st << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_icmp_tunnel` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case MOD:{
      string str = "UPDATE `t_event_config_icmp_tunnel` SET ";
      if (req->has_sip())
        stAddUpdateSet(str, "`sip` = ?");
      if (req->has_dip())
        stAddUpdateSet(str, "`dip` = ?");
      if (req->has_if1())
        stAddUpdateSet(str, "`IF1` = ?");
      if (req->has_if2())
        stAddUpdateSet(str, "`IF2` = ?");
      if (req->has_if3())
        stAddUpdateSet(str, "`IF3` = ?");
      if (req->has_desc())
        stAddUpdateSet(str, "`desc` = ?");

      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_sip()) 
          st << req->sip();
        if (req->has_dip())
          st << req->dip();
        if (req->has_if1())
          st << req->if1();
        if (req->has_if2())
          st << req->if2();
        if (req->has_if3())
          st << req->if3();
        if (req->has_desc()){
          st << req->desc();
        }

        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case GET:{
      cppdb::statement st;
      string str = "SELECT `id`, `sip`, `dip`, `IF1`, `IF2`, `IF3`, `desc` FROM `t_event_config_icmp_tunnel` WHERE 1";

      if ( req!=NULL ){
        if ( req->has_id() )
          str += " AND `id` = ?";
        if ( req->has_sip() ) 
          str += " AND `sip` = ?";
        if ( req->has_dip() )
          str += " AND `dip` = ?";
        if ( req->has_desc() )
          str += " AND `desc` = ?";

        st = *_sql <<str;

        if ( req->has_id() )
          st << req->id();
        if ( req->has_sip() )
          st << req->sip();
        if ( req->has_dip() )
          st << req->dip();
        if ( req->has_desc() )
          st << req->desc();
      }
      else
        st = *_sql <<str;  

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>s;
        output_string("sip", s);
        cout<<",";

        r>>s;
        output_string("dip", s);
        cout<<",";

        r>>u;
        output_u64("IF1", u);
        cout<<",";

        r>>u;
        output_u64("IF2", u);
        cout<<",";

        r>>u;
        output_u64("IF3", u);
        cout<<",";

        r>>s;
        output_string("desc", s);

        cout<<"}";
      }

      break;
    }
    default:
      return false;
      break;
  }
    
  return true; 
}

bool ConfigEvent::ProcessConfigFrnTrip(bool out_type){
  EventConfig *req = (EventConfig *)this->_req;
  
  switch (_op) {
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_frn_trip`(`sip`, `dip`, `min`, `desc`) VALUES (?,?,?,?)";
      try{
        if ( req->sip().empty() )
          st << cppdb::null;
        else
          st << req->sip();

        st << req->dip() << req->min() << req->desc();
        st << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_frn_trip` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();     
      break;
    }  
    case MOD:{
      string str = "UPDATE `t_event_config_frn_trip` SET ";
      if (req->has_sip())
        stAddUpdateSet(str, "`sip` = ?");
      if (req->has_dip())
        stAddUpdateSet(str, "`dip` = ?");
      if (req->has_min())
        stAddUpdateSet(str, "`min` = ?");
      if (req->has_desc())
        stAddUpdateSet(str, "`desc` = ?");

      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_sip()) {
          if (req->sip().empty())
            st << cppdb::null;
          else
            st << req->sip();
        }
        if (req->has_dip())
          st << req->dip();
        if (req->has_min()){
          st << req->min();
        }
        if (req->has_desc()){
          st << req->desc();
        }

        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();     
      break;
    }
    case GET:{
      cppdb::statement st;
      string str = "SELECT `id`, `sip`, `dip`, `min`, `desc` FROM `t_event_config_frn_trip` WHERE 1";

      if ( req!=NULL ){
        if ( req->has_id() )
          str += " AND `id` = ?";
        if ( req->has_sip() ) {
          if (req->sip().empty())
            str += " AND `sip` IS NULL";
          else
            str += " AND `sip` = ?";
        }
        if ( req->has_dip() )
          str += " AND `dip` = ?";
        if ( req->has_min() )
          str += " AND `min` = ?";
        
        if ( req->has_desc() )
          str += " AND `desc` = ?";

        st = *_sql <<str;

        if ( req->has_id() )
          st << req->id();
        if ( req->has_sip() )
          st << req->sip();
        if ( req->has_dip() )
          st << req->dip();
        if ( req->has_min() )
          st << req->min();
        if ( req->has_desc() )
          st << req->desc();
      }
      else
        st = *_sql <<str; 
      
      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;
        cppdb::null_tag_type null_tag;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>cppdb::into(s, null_tag);
        if (null_tag==cppdb::null_value)
          output_string("sip", "");
        else
          output_string("sip", s);
        cout<<",";

        r>>s;
        output_string("dip", s);
        cout<<",";

        r>>u;
        output_u64("min", u);
        cout<<",";

        r>>s;
        output_string("desc", s);

        cout<<"}";
      }     
 
      break;
    }
    default: 
      return false;
      break;
  }

  return true;
}

bool ConfigEvent::ProcessConfigDnstunnel(bool out_type){
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op){
    case ADD:{
      cppdb::statement st = *_sql << "INSERT INTO `t_event_config_dnstunnel`(`ip`, `namelen`, `fqcount`, `detvalue`, `desc`) VALUES (?,?,?,?,?)";
      try{
        if ( req->ip().empty() )
          st << cppdb::null;
        else
          st << req->ip();

        st << req->namelen() << req->fqcount() << req->detvalue() << req->desc();
        st << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed("\"id\": "+to_string(st.last_insert_id()));
      break;
    }
    case DEL:{
      cppdb::statement st = *_sql << "DELETE FROM `t_event_config_dnstunnel` WHERE `id` = ?;";
      try{
        st << req->id() << cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case MOD:{
      string str = "UPDATE `t_event_config_dnstunnel` SET ";
      if (req->has_ip())
        stAddUpdateSet(str, "`ip` = ?");
      if (req->has_namelen())
        stAddUpdateSet(str, "`namelen` = ?");
      if (req->has_fqcount())
        stAddUpdateSet(str, "`fqcount` = ?");
      if (req->has_detvalue())
        stAddUpdateSet(str, "`detvalue` = ?");
      if (req->has_desc())
        stAddUpdateSet(str, "`desc` = ?");
      
      str+=" WHERE id = ?";
      try{
        cppdb::statement st = *_sql <<str;
        if (req->has_ip()) {
          if (req->ip().empty())
            st << cppdb::null;
          else
            st << req->ip();
        }
        if (req->has_namelen())
          st << req->namelen();
        if (req->has_fqcount()){
          st << req->fqcount();
        }
        if (req->has_detvalue()){
          st << req->detvalue();
        }
        if (req->has_desc()){
          st << req->desc();
        }
        
        st<<req->id();
        st<<cppdb::exec;
      } catch ( cppdb::cppdb_error const &e ){
        log_err("%s", e.what());
        return Failed();
      }

      return Executed();
      break;
    }
    case GET:{
      cppdb::statement st;
      string str = "SELECT `id`, `ip`, `namelen`, `fqcount`, `detvalue`, `desc` FROM `t_event_config_dnstunnel` WHERE 1";

      if ( req!=NULL ){
        if ( req->has_id() )
          str += " AND `id` = ?";
        if ( req->has_ip() ) {
          if (req->ip().empty())
            str += " AND `ip` IS NULL";
          else
            str += " AND `ip` = ?";
        }
        if ( req->has_namelen() )
          str += " AND `namelen` = ?";
        if ( req->has_fqcount() ){
          str += " AND `fqcount` = ?";
        }
        if ( req->has_detvalue() ){
          str += " AND `detvalue` = ?";
        }
        if ( req->has_desc() ){
          str += " AND `desc` = ?";
        }

        st = *_sql <<str;

        if ( req->has_id() )
          st << req->id();
        if ( !req->ip().empty() )
          st << req->ip();
        if ( req->has_namelen() )
          st << req->namelen();
        if ( req->has_fqcount() )
          st << req->fqcount();
        if ( req->has_detvalue() )
          st << req->detvalue();
        if ( req->has_desc() )
          st << req->desc();
      }
      else
        st = *_sql <<str;

      cppdb::result r = st;
      bool first = true;
      while (r.next()){
        u64 u;
        string s;
        cppdb::null_tag_type null_tag;

        if (first){
          cout<<"{";
          first = false;
        }
        else
          cout<<","<<endl<<"{";

        r>>u;
        output_u64("id", u);
        cout<<",";

        r>>cppdb::into(s,null_tag);
        if (null_tag==cppdb::null_value)
          output_string("ip", "");
        else
          output_string("ip", s);
        cout<<",";

        r>>u;
        output_u64("namelen", u);
        cout<<",";

        r>>u;
        output_u64("fqcount", u);
        cout<<",";
        
        r>>u;
        output_u64("detvalue", u);
        cout<<",";

        r>>s;
        output_string("desc", s);

        cout<<"}";
      }
      break;
    }
    default:
      return false;
      break;
  }
  
  return true;
}

bool ConfigEvent::ParseReqForEvent(cgicc::Cgicc& cgi){
	Event *req = new Event();
	this->_req = req;

	if (!cgi("event_id").empty()) req->set_event_id( atol(cgi("event_id").c_str()) );
	if (!cgi("desc").empty()) req->set_desc( cgi("desc") );
	if (!cgi("event_type").empty()) req->set_event_type( cgi("event_type") );
	if (!cgi("event_level").empty()) req->set_event_level( cgi("event_level") );
	if (!cgi("status").empty()) req->set_status( cgi("status") );
	if (!cgi("action_id").empty()) req->set_action_id( cgi("action_id") );
	if (!cgi("config_id").empty()) req->set_config_id( atol(cgi("config_id").c_str()) );
	if (!cgi("moid").empty()) req->set_moid( cgi("moid")=="null"?"":cgi("moid") );
	if (!cgi("devid").empty()) req->set_devid( cgi("devid")=="null"?"":cgi("devid") );

	if (!cgi("weekday").empty()) req->set_weekday( cgi("weekday")=="null"?"":cgi("weekday") );
	if (!cgi("stime").empty()) req->set_stime( cgi("stime") );
	if (!cgi("etime").empty()) req->set_etime( cgi("etime") );
	if (!cgi("coverrange").empty()) req->set_coverrange( cgi("coverrange") );

	return true;
}

bool ConfigEvent::ParseReqForEventIgnore(cgicc::Cgicc& cgi){
  EventIgnore *req = new EventIgnore();
  this->_req = req;

  if (!cgi("id").empty()) req->set_id(atoll(cgi("id").c_str()));
  if (!cgi("time").empty()) req->set_time(atoll(cgi("time").c_str()));
  if (!cgi("lip").empty()) req->set_lip(cgi("lip")=="null"?"":cgi("lip"));
  if (!cgi("tip").empty()) req->set_tip(cgi("tip")=="null"?"":cgi("tip"));
  if (!cgi("tport").empty()) req->set_tport(cgi("tport")=="null"?"":cgi("tport"));
  if (!cgi("protocol").empty()) req->set_protocol(cgi("protocol")=="null"?"":cgi("protocol"));
  if (!cgi("domain").empty()) req->set_domain(cgi("domain")=="null"?"":cgi("domain"));
  if (!cgi("desc").empty()) req->set_desc(cgi("desc")=="null"?"":cgi("desc"));
  if (!cgi("weekday").empty()) req->set_weekday( cgi("weekday")=="null"?"":cgi("weekday") );
  if (!cgi("stime").empty()) req->set_stime( cgi("stime") );
  if (!cgi("etime").empty()) req->set_etime( cgi("etime") );
  if (!cgi("coverrange").empty()) req->set_coverrange( cgi("coverrange") );
  if (!cgi("count").empty()) req->set_count( atol(cgi("count").c_str()) );

  return true;
}

bool ConfigEvent::ParseReqForType(cgicc::Cgicc& cgi){
	EventType *req = new EventType();
	this->_req = req;

	if (!cgi("id").empty()) req->set_id( atol(cgi("id").c_str()) );
	if (!cgi("desc").empty()) req->set_desc( cgi("desc") );

	return true;
}

bool ConfigEvent::ParseReqForUrlType(cgicc::Cgicc& cgi){
  EventUrlType *req = new EventUrlType();
  this->_req = req;

  if (!cgi("id").empty()) req->set_id( atol(cgi("id").c_str()) );
  if (!cgi("desc").empty()) req->set_desc( cgi("desc") );

  return true;
}

bool ConfigEvent::ParseReqForConfigThreshold(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("moid").empty()) req->set_moid( atol(cgi("moid").c_str()) );
	if (!cgi("thres_mode").empty()) req->set_thres_mode( boost::to_lower_copy(cgi("thres_mode")) );
	if (!cgi("data_type").empty()) req->set_data_type( boost::to_lower_copy(cgi("data_type")) );
	if (!cgi("min").empty()) req->set_min( cgi("min")=="null"?"":cgi("min") );
	if (!cgi("max").empty()) req->set_max( cgi("max")=="null"?"":cgi("max") );
	if (!cgi("grep_rule").empty()) req->set_grep_rule( cgi("grep_rule")=="null"?"":cgi("grep_rule") );

	return true;
}

bool ConfigEvent::ParseReqForConfigBlack(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("data_type").empty()) req->set_data_type( boost::to_lower_copy(cgi("data_type")) );
	if (!cgi("min").empty()) req->set_min( cgi("min") );
	if (!cgi("max").empty()) req->set_max( cgi("max")=="null"?"":cgi("max") );

	return true;
}

bool ConfigEvent::ParseReqForConfigSus(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("data_type").empty()) req->set_data_type( boost::to_lower_copy(cgi("data_type")) );
	if (!cgi("min").empty()) req->set_min( cgi("min") );
	if (!cgi("max").empty()) req->set_max( cgi("max")=="null"?"":cgi("max") );

	return true;
}

bool ConfigEvent::ParseReqForConfigPortScan(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("min_peerips").empty()) req->set_min_peerips( atol(cgi("min_peerips").c_str()) );
	if (!cgi("max_peerips").empty()) req->set_max_peerips( cgi("max_peerips")=="null"?"":cgi("max_peerips") );
	if (!cgi("ip").empty()) req->set_ip( ipAddSuffix( cgi("ip")=="null"?"":cgi("ip") ));
	if (!cgi("port").empty()) req->set_port( cgi("port")=="null"?"":cgi("port") );
	if (!cgi("protocol").empty()) req->set_protocol( cgi("protocol")=="null"?"":boost::to_upper_copy(cgi("protocol")) );

	return true;
}

bool ConfigEvent::ParseReqForConfigIPScan(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("min_peerports").empty()) req->set_min_peerports( atol(cgi("min_peerports").c_str()) );
	if (!cgi("max_peerports").empty()) req->set_max_peerports( cgi("max_peerports")=="null"?"":cgi("max_peerports") );
	if (!cgi("sip").empty()) req->set_sip( ipAddSuffix( cgi("sip")=="null"?"":cgi("sip") ));
	if (!cgi("dip").empty()) req->set_dip( ipAddSuffix( cgi("dip")=="null"?"":cgi("dip") ));
	if (!cgi("protocol").empty()) req->set_protocol( cgi("protocol")=="null"?"":boost::to_upper_copy(cgi("protocol")) );

	return true;
}

bool ConfigEvent::ParseReqForConfigSrv(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("min_portsessions").empty()) req->set_min_portsessions( atol(cgi("min_portsessions").c_str()) );
	if (!cgi("max_portsessions").empty()) req->set_max_portsessions( cgi("max_portsessions")=="null"?"":cgi("max_portsessions") );
	if (!cgi("ip").empty()) req->set_ip( ipAddSuffix( cgi("ip")=="null"?"":cgi("ip") ));
	if (!cgi("port").empty()) req->set_port( cgi("port")=="null"?"":cgi("port") );
	if (!cgi("protocol").empty()) req->set_protocol( cgi("protocol")=="null"?"":boost::to_upper_copy(cgi("protocol")) );

	return true;
}

bool ConfigEvent::ParseReqForLevel(cgicc::Cgicc& cgi){
	EventLevel *req = new EventLevel();
	this->_req = req;

	if (!cgi("id").empty()) req->set_id( atol(cgi("id").c_str()) );
	if (!cgi("desc").empty()) req->set_desc( cgi("desc") );
	if (!cgi("profile").empty()) req->set_profile( cgi("profile")=="null"?"":cgi("profile") );

	return true;
}

bool ConfigEvent::ParseReqForAction(cgicc::Cgicc& cgi){
	EventAction *req = new EventAction();
	this->_req = req;

	if (!cgi("action_id").empty()) req->set_action_id( atol(cgi("action_id").c_str()) );
	if (!cgi("act").empty()) req->set_act( atol(cgi("act").c_str()) );
	if (!cgi("mail").empty()) req->set_mail( cgi("mail")=="null"?"":cgi("mail") );
	if (!cgi("phone").empty()) req->set_phone( cgi("phone")=="null"?"":cgi("phone") );
	if (!cgi("uid").empty()) req->set_uid( cgi("uid")=="null"?"":cgi("uid") );
	if (!cgi("desc").empty()) req->set_desc( cgi("desc")=="null"?"":cgi("desc") );

	return true;
}

bool ConfigEvent::ParseReqForDataAggre(cgicc::Cgicc& cgi){
	EventDataAggre *req = new EventDataAggre();
	this->_req = req;

	if (!cgi("starttime").empty()) req->set_starttime(atoll(cgi("starttime").c_str()));
	if (!cgi("endtime").empty()) req->set_endtime(atoll(cgi("endtime").c_str()));
	if (!cgi("step").empty()) req->set_step(atol(cgi("step").c_str()));
	if (!cgi("event_type").empty()) req->set_type(cgi("event_type"));
	if (!cgi("devid").empty()) req->set_devid(atol(cgi("devid").c_str()));
	if (!cgi("event_id").empty()) req->set_event_id(atol(cgi("event_id").c_str()));
	if (!cgi("id").empty()) req->set_id(atol(cgi("id").c_str()));
	if (!cgi("obj").empty()) req->set_obj(cgi("obj"));
	if (!cgi("level").empty()) req->set_level(cgi("level"));

	return true;
}

bool ConfigEvent::ParseReqForConfigDga(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("sip").empty()) req->set_sip( cgi("sip")=="null"?"":cgi("sip") );
	if (!cgi("dip").empty()) req->set_dip( cgi("dip")=="null"?"":cgi("dip") );
	if (!cgi("min").empty()) req->set_min( cgi("min")=="null"?"":cgi("min") );
  if (!cgi("qcount").empty()) req->set_qcount( atol(cgi("qcount").c_str()) );

	return true;
}

bool ConfigEvent::ParseReqForConfigDns(cgicc::Cgicc& cgi){
	EventConfig *req = new EventConfig();
	this->_req = req;

	if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
	if (!cgi("ip").empty()) req->set_ip( cgi("ip")=="null"?"":cgi("ip") );
	if (!cgi("qname").empty()) req->set_qname( cgi("qname")=="null"?"":cgi("qname") );
	if (!cgi("qcount").empty()) req->set_qcount( atol(cgi("qcount").c_str()) );
  if (!cgi("desc").empty()) req->set_desc( cgi("desc")=="null"?"":cgi("desc") );

	return true;
}

bool ConfigEvent::ParseReqForConfigDnstunnel(cgicc::Cgicc& cgi){
  EventConfig *req = new EventConfig();
  this->_req = req;

  if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
  if (!cgi("ip").empty()) req->set_ip( cgi("ip")=="null"?"":cgi("ip") );
  if (!cgi("namelen").empty()) req->set_namelen( atol(cgi("namelen").c_str()) );
  if (!cgi("fqcount").empty()) req->set_fqcount( atol(cgi("fqcount").c_str()) );
  if (!cgi("detvalue").empty()) req->set_detvalue( atol(cgi("detvalue").c_str()) );
  if (!cgi("desc").empty()) req->set_desc( cgi("desc")=="null"?"":cgi("desc") );

  return true;
}

bool ConfigEvent::ParseReqForConfigUrlContent(cgicc::Cgicc& cgi) {
  EventConfig *req = new EventConfig();
  this->_req = req;
  
  if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
  if (!cgi("min").empty()) req->set_min(cgi("min")=="null"?"":cgi("min"));
  if (!cgi("url_type").empty()) req->set_url_type( atol(cgi("url_type").c_str()) );
  if (!cgi("pat").empty()) req->set_pat(cgi("pat")=="null"?"":cgi("pat"));

  return true;
}

bool ConfigEvent::ParseReqForConfigFrnTrip(cgicc::Cgicc& cgi) {
  EventConfig *req = new EventConfig();
  this->_req = req;

  if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
  if (!cgi("min").empty()) req->set_min(cgi("min")=="null"?"":cgi("min"));
  if (!cgi("sip").empty()) req->set_sip( cgi("sip")=="null"?"":cgi("sip") );
  if (!cgi("dip").empty()) req->set_dip(cgi("dip")=="null"?"":cgi("dip"));
  if (!cgi("desc").empty()) req->set_desc(cgi("desc")=="null"?"":cgi("desc"));

  return true;
}

bool ConfigEvent::ParseReqForConfigIcmpTun(cgicc::Cgicc& cgi) {
  EventConfig *req = new EventConfig();
  this->_req = req;

  if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
  if (!cgi("sip").empty()) req->set_sip( cgi("sip") );
  else req->set_sip("");
  if (!cgi("dip").empty()) req->set_dip(cgi("dip"));
  else req->set_dip("");
  if (!cgi("desc").empty()) req->set_desc(cgi("desc")=="null"?"":cgi("desc"));
  if (!cgi("IF1").empty())  req->set_if1(atol(cgi("IF1").c_str()));
  if (!cgi("IF2").empty())  req->set_if2(atol(cgi("IF2").c_str()));
  if (!cgi("IF3").empty())  req->set_if3(atol(cgi("IF3").c_str()));
 
  return true;
}

bool ConfigEvent::ParseReqForConfigDnstunAI(cgicc::Cgicc& cgi) {
  EventConfig *req = new EventConfig();
  this->_req = req;

  if (!cgi("config_id").empty()) req->set_id( atol(cgi("config_id").c_str()) );
  if (!cgi("sip").empty()) req->set_sip( cgi("sip") );
  else req->set_sip("");
  if (!cgi("dip").empty()) req->set_dip(cgi("dip"));
  else req->set_dip("");
  if (!cgi("min").empty()) req->set_min(cgi("min")=="null"?"":cgi("min"));

  return true;
}

bool ConfigEvent::ValidateEvent(){
	Event *req = (Event *)this->_req;

	switch (_op){
		case ADD:
			if ( !req->has_desc() || !req->has_event_type() || !req->has_event_level() || !req->has_status() || !req->has_action_id() || !req->has_config_id() )
				return Failed();
			if (req->status()!="ON" && req->status()!="OFF")
				return Failed();

			if (!req->has_coverrange())
				req->set_coverrange("within");
			if (req->coverrange()!="within" && req->coverrange()!="without")
				return Failed();

			if (req->has_weekday() && req->weekday().empty())
				req->set_weekday("0,1,2,3,4,5,6");

			if (!req->has_stime()) req->set_stime("00:00:00");
			if (!req->has_etime()) req->set_etime("23:59:59");

			try{
				u32 id;
				cppdb::result r;
				if (req->has_event_type()){
					r = *_sql << "SELECT `id` FROM `t_event_type` WHERE `desc` = ?"<<req->event_type();
					r.next();
					r>>id;
					req->set_type_id(id);
				}

				if (req->has_event_level()){
					r = *_sql << "SELECT `id` FROM `t_event_level` WHERE `desc` = ?"<<req->event_level();
					r.next();
					r>>id;
					req->set_level_id(id);
				}
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}
			break;
		case DEL:
			if ( !req->has_event_id() )
				return Failed();
			try{
				u32 id;
				cppdb::result r;

				r = *_sql << "SELECT `status_id` FROM `t_event_list` WHERE `id`=?"<<req->event_id();
				r.next();
				r>>id;
				req->set_status_id(id);
			} catch ( cppdb::cppdb_error const &e ){
				log_err("%s", e.what());
				return Failed();
			}
			break;
		case MOD:
			if ( !req->has_event_id() )
				return Failed();
			if ( !req->has_desc() && !req->has_event_type() && !req->has_event_level() && !req->has_status() && !req->has_action_id() && !req->has_config_id() && !req->has_devid() && !req->has_moid() && !req->has_weekday() && !req->has_stime() && !req->has_etime() && !req->has_coverrange() )
				return Failed();
			if (req->has_status() && req->status()!="ON" && req->status()!="OFF")
				return Failed();
			if (req->has_coverrange() && req->coverrange()!="within" && req->coverrange()!="without")
				return Failed();
			if (req->has_weekday() && req->weekday().empty())
				req->set_weekday("0,1,2,3,4,5,6");

			try{
				u32 id;
				cppdb::result r;

				r = *_sql << "SELECT `status_id` FROM `t_event_list` WHERE `id`=?"<<req->event_id();
				r.next();
				r>>id;
				req->set_status_id(id);

				if (req->has_event_type()){
					r = *_sql << "SELECT `id` FROM `t_event_type` WHERE `desc` = ?"<<req->event_type();
					r.next();
					r>>id;
					req->set_type_id(id);
				}

				if (req->has_event_level()){
					r = *_sql << "SELECT `id` FROM `t_event_level` WHERE `desc` = ?"<<req->event_level();
					r.next();
					r>>id;
					req->set_level_id(id);
				}
			} catch ( cppdb::cppdb_error const &e ){
				log_err("event_list: mod: %s", e.what());
				return Failed();
			}
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateUrlType(){
  switch (_op){
    case ADD:
      return Failed();
      break;
    case DEL:
      return Failed();
      break;
    case MOD:
      return Failed();
      break;
    case GET:
      break;
    default:
      return false; // This code should never execute
      break;   
  }
  return true;
}

bool ConfigEvent::ValidateType(){
	switch (_op){
		case ADD:
			return Failed();
			break;
		case DEL:
			return Failed();
			break;
		case MOD:
			return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigThreshold(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
			if ( req->thres_mode().empty() || req->data_type().empty() )
				return Failed();
			if ( !req->has_min() && !req->has_max())
				return Failed();
			if ( req->thres_mode()!="abs" && req->thres_mode()!="rel_v" && req->thres_mode()!="rel_p" )
				return Failed();
			if ( req->data_type()!="bps" && req->data_type()!="pps" && req->data_type()!="sps" )
				return Failed();
			if ( !req->has_moid() )
				req->set_moid(0);
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_moid() && req->thres_mode().empty() && req->data_type().empty() && !req->has_grep_rule() && !req->has_min() && !req->has_max() )
				return Failed();
			if ( req->has_thres_mode() && req->thres_mode()!="abs" && req->thres_mode()!="rel_v" && req->thres_mode()!="rel_p" )
				return Failed();
			if ( req->has_data_type() && req->data_type()!="bps" && req->data_type()!="pps" && req->data_type()!="sps" )
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigPortScan(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
			if ( !req->has_min_peerips() )
				return Failed();
			if ( req->port()!="" && !is_valid_port(req->port()) )
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_min_peerips() && !req->has_max_peerips() && !req->has_ip() && !req->has_port() && !req->has_protocol() )
				return Failed();
			if ( req->ip()!="" && !is_valid_cidr(req->ip()) )
				return Failed();
			if ( req->port()!="" && !is_valid_port(req->port()) )
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigIPScan(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
			if ( !req->has_min_peerports() )
				return Failed();
			if ( req->dip()!="" && !is_valid_cidr(req->dip()) )
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_min_peerports() && !req->has_max_peerports() && !req->has_sip() && !req->has_dip() && !req->has_protocol() )
				return Failed();
			if ( req->sip()!="" && !is_valid_cidr(req->sip()) )
				return Failed();
			if ( req->dip()!="" && !is_valid_cidr(req->dip()) )
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigSrv(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
			if ( !req->has_min_portsessions() )
				return Failed();
			if ( req->ip()!="" && !is_valid_cidr(req->ip()) )
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_min_portsessions() && !req->has_max_portsessions() && !req->has_ip() && !req->has_port() && !req->has_protocol() )
				return Failed();
			if ( req->ip()!="" && !is_valid_cidr(req->ip()) )
				return Failed();
			if ( req->port()!="" && !is_valid_port(req->port()) )
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigBlack(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
      if ( req->data_type().empty() )
        return Failed();
			if ( req->data_type()!="bps" && req->data_type()!="pps" && req->data_type()!="sps" )
				return Failed();
			if ( !req->has_min() )
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_min() && !req->has_max() && req->data_type().empty() ) 
				return Failed();
      if ( req->has_data_type() && req->data_type()!="bps" && req->data_type()!="pps" && req->data_type()!="sps" )
        return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigSus(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
      if ( req->data_type().empty() )
        return Failed();
			if ( req->data_type()!="bps" && req->data_type()!="pps" && req->data_type()!="sps" )
				return Failed();
			if ( !req->has_min() )
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_min() && !req->has_max() && req->data_type().empty() ) 
				return Failed();
      if ( req->has_data_type() && req->data_type()!="bps" && req->data_type()!="pps" && req->data_type()!="sps" )
        return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}


bool ConfigEvent::ValidateLevel(){
	switch (_op){
		case ADD:
			return Failed();
			break;
		case DEL:
			return Failed();
			break;
		case MOD:
			return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateAction(){
	EventAction *req = (EventAction *)this->_req;
	u32 act = req->act();

	switch (_op){
		case ADD:
			if (req->desc().empty())
				return Failed();
			if ( act==0 || act>0x7 )
				return Failed();
			if ( act&0x1 && req->mail().empty() )
				return Failed();
			if ( act&0x2 && req->phone().empty() )
				return Failed();
			if ( act&0x4 && req->uid().empty() )
				return Failed();
			break;
		case DEL:
			if ( !req->has_action_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_action_id() )
				return Failed();
			if ( act>0x7 )
				return Failed();
			if ( act&0x1 && req->mail().empty() )
				return Failed();
			if ( act&0x2 && req->phone().empty() )
				return Failed();
			if ( act&0x4 && req->uid().empty() )
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigAll(){
	switch (_op){
		case ADD:
			return Failed();
			break;
		case DEL:
			return Failed();
			break;
		case MOD:
			return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateDataAggre(){
	EventDataAggre *req = (EventDataAggre *)this->_req;

	switch (_op){
		case ADD:
			return Failed();
			break;
		case DEL:
			return Failed();
			break;
		case MOD:
			return Failed();
			break;
		case GET:{
			u32 ts = time(NULL);

			if (!req->has_starttime())
			  req->set_starttime( ts - 1800 );
			if (!req->has_endtime())
			  req->set_endtime( ts );
			req->set_starttime(req->starttime() - req->starttime()%300);
			req->set_endtime(req->endtime() - req->endtime()%300);
			req->set_endtime(MAX(req->starttime()+300, req->endtime()));
			if (req->has_step()){
			  req->set_step(req->step() - req->step()%300);
			  req->set_step(MAX(req->step(), 300));
			}
			break;
		}
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateEventIgnore() {
  EventIgnore *req = (EventIgnore *)this->_req;

  switch (_op){
    case ADD:
      if ( !req->has_lip() && !req->has_tport() && !req->has_tip() && !req->has_protocol() && !req->has_domain())
        return Failed();

      if ( req->lip().empty() && req->tport().empty() && req->tip().empty() && req->protocol().empty() && req->domain().empty())
        return Failed();

      if ( !req->has_time() )
        req->set_time(time(NULL));

      if ( !req->has_desc() )
        return Failed();

      if (!req->has_coverrange())
        req->set_coverrange("within");
      if (req->coverrange()!="within" && req->coverrange()!="without")
        return Failed();

      if (req->has_weekday() && req->weekday().empty())
        req->set_weekday("0,1,2,3,4,5,6");

      if (!req->has_stime()) req->set_stime("00:00:00");
      if (!req->has_etime()) req->set_etime("23:59:59");
      if (!req->has_count()) req->set_count(0);

      break;
    case DEL:
      if ( !req->has_id() )
        return Failed();
      break;
    case MOD:
      if ( !req->has_time() )
        req->set_time(time(NULL));  
    
      if ( !req->has_id() )
        return Failed();

      if ( !req->has_time() &&  !req->has_lip() && !req->has_tip() && !req->has_tport() && !req->has_desc() && !req->has_protocol() && !req->has_domain()
          && !req->has_desc() && !req->has_weekday() && !req->has_stime() && !req->has_etime() && !req->has_coverrange())
        return Failed();

      if (req->has_coverrange() && req->coverrange()!="within" && req->coverrange()!="without")
        return Failed();

      if (req->has_weekday() && req->weekday().empty())
        req->set_weekday("0,1,2,3,4,5,6");

      if (!req->has_stime()) req->set_stime("00:00:00");
      if (!req->has_etime()) req->set_etime("23:59:59");
      if (!req->has_count()) req->set_count(0);

      break;
    case GET:
      break;
    case DEL_EVENT:
      if ( !req->has_id() )
        return Failed();
      break;
    default:
      return false;
      break;
  }
  return true;
}

bool ConfigEvent::ValidateConfigDga(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
			if ( !req->has_sip() && !req->has_dip() && !req->has_qcount() && !req->has_min() )
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_sip() && !req->has_dip() && !req->has_qcount() && !req->has_min())
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}
bool ConfigEvent::ValidateConfigDns(){
	EventConfig *req = (EventConfig *)this->_req;

	switch (_op){
		case ADD:
			if ( !req->has_ip() && !req->has_qname() && !req->qcount() && !req->has_desc() )
				return Failed();
      if (!req->has_qcount())
        req->set_qcount(0);
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_ip() && !req->has_qname() && !req->has_qcount() && !req->has_desc())
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	return true;
}

bool ConfigEvent::ValidateConfigDnstunnel(){
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op){
    case ADD:
      if ( !req->has_ip() && !req->has_namelen() && !req->has_fqcount() && !req->has_detvalue() && !req->has_desc())
        return Failed();
      if ( !req->has_namelen())
        req->set_namelen(52);
      if ( !req->has_fqcount())
        req->set_fqcount(150);
      if ( !req->has_detvalue())
        req->set_detvalue(5000); 
      break;
    case DEL:
      if ( !req->has_id() )
        return Failed();
      break;
    case MOD:
      if ( !req->has_id() )
        return Failed();
      if ( !req->has_ip() && !req->has_namelen() && !req->has_fqcount() && !req->has_detvalue() && !req->has_desc())
        return Failed();
      if (!req->has_ip())
        req->set_ip("");
      break;
    case GET:
      break;
    default:
      return false;
      break;
  }

  return true;
}

bool ConfigEvent::ValidateConfigUrlContent() {
  EventConfig *req = (EventConfig *)this->_req;
  
  switch (_op){
    case ADD:
      if (!req->has_url_type()) return Failed();
      if (!req->has_pat() || req->pat().empty()) return Failed(); 
      if (!req->has_url_type() && !req->has_min() && !req->has_pat()) 
        return Failed();
      break;
    case DEL:
      if (!req->has_id()) return Failed();
      break;
    case MOD:
      if (!req->has_id()) return Failed();
      if (!req->has_url_type() && !req->has_min() && !req->has_pat())
        return Failed();
      break;
    case GET:
      break;
    default:
      return false;
      break;    
  }

  return true;
}

bool ConfigEvent::ValidateConfigFrnTrip() {
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op){
    case ADD:
      if (!req->has_min()) return Failed();
      if (!req->has_sip() || req->sip().empty()) return Failed();
      break;
    case DEL:
      if (!req->has_id()) return Failed();
      break;
    case MOD:
      if (!req->has_id()) return Failed();
      if (!req->has_sip() && !req->has_dip() && !req->has_min() && !req->has_desc())
        return Failed();
      break;
    case GET:
      break;
    default:
      return false;
      break;
  }

  return true;
}

bool ConfigEvent::ValidateConfigIcmpTun() {
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op){
    case ADD:
      if (!req->has_if1()) 
        req->set_if1(5);   //影响因子1， 异常类型payload内容种类，默认值5
      if (!req->has_if2())
        req->set_if2(2);   //影响因子3， payload内容种类，默认值2
      if (!req->has_if3())
        req->set_if3(5);   //影响因子4，payload长度的种类，默认值5
      break;
    case DEL:
      if (!req->has_id()) return Failed();
      break;
    case MOD:
      if (!req->has_id()) return Failed();
      if (!req->has_sip() && !req->has_dip() && !req->has_desc() && !req->has_if1() && 
          !req->has_if2() && !req->has_if3())
        return Failed();
      break;
    case GET:
      break;
    default:
      return false;
      break;
  }

  return true;
}

bool ConfigEvent::ValidateConfigDnstunAI() {
  EventConfig *req = (EventConfig *)this->_req;

  switch (_op){
    case ADD:
      if (!req->has_min())
        return Failed();
      break;
    case DEL:
      if (!req->has_id()) return Failed();
      break;
    case MOD:
      if (!req->has_id()) return Failed();
      if (!req->has_sip() && !req->has_dip() && !req->has_min())
        return Failed();
      break;
    case GET:
      break;
    default:
      return false;
      break;
  }

  return true;
}

} // namespace config
