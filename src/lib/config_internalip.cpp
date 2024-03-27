#include "config_internalip.h"
#include <boost/algorithm/string.hpp>
#include "../common/common.h"
#include "../common/log.h"
#include "../common/_strings.h"
#include "boost/regex.hpp"

using namespace std;
using namespace cppdb;
using namespace boost;

static cppdb::session* sql;

static std::string op;
static std::string id;
static std::string ip;
static std::string devid;
static std::string desc;

stringstream output;

// Fucntions used for .so
config::Config *CreateConfigInstance(const std::string& type, cppdb::session* Sql) {
	sql = Sql;
	return new config::ConfigInternalIp(type, Sql);
}

void FreeConfigInstance(config::Config *p){
	// delete p;
}
///////////////////////////////////////////////////////////

// Codes from internalip.cpp

#define VALID_ID_PATTERN "^[1-9]\\d*$"
#define VALID_DEVID_PATTERN "^[0-9]\\d*$"
#define CIDR_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}(/(([12]?[0-9])|(3[0-2])))?$"


////////////////////////////////////////////////////////////////////////////
static void inline output_string(stringstream& out, const string& name, const string& value) 
{
  out << '"' << name << "\":\"" << value << '"'; 
}

////////////////////////////////////////////////////////////////////////////
static void inline output_u64(stringstream& out, const string& name, const u64 value) 
{
  out << '"' << name << "\":" << value; 
}

////////////////////////////////////////////////////////////////////////////
/*static inline bool is_valid_cidr(const std::string& ip) {
  regex pattern(CIDR_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(ip,m,pattern);
}*/

static inline bool is_valid_cidr(const std::string& ip) {
  boost::regex pattern(CIDR_PATTERN, boost::regex::nosubs);
  boost::smatch m;
  bool is_ipv4, is_ipv6;
  struct in6_addr in6;
  u32 slash;

  is_ipv4 = is_ipv6 = false;
  if ((is_ipv4 = boost::regex_match(ip, m, pattern))){
    is_ipv4 = true;
  } else {
    if ((slash = ip.find("/")) != std::string::npos){
      std::string ipv6 = ip.substr(0, slash);
      std::string mask_s = ip.substr(slash+1);
      u32 mask = atoi(mask_s.c_str());

      is_ipv6 = inet_pton(AF_INET6, ipv6.c_str(), (void *)&in6) ? ((mask < 0 || mask > 128) ? false : true) : false;

    } else {
      is_ipv6 = inet_pton(AF_INET6, ip.c_str(), (void *)&in6) ? true : false;
    }
  }

  return (is_ipv4 | is_ipv6);
}


////////////////////////////////////////////////////////////////////////////
static std::string inline ipAddSuffix(const std::string& ip){
  if (ip==""||ip.find('/')!=string::npos)
    return ip;
  else {
    if (ip.npos == ip.find(':'))
      return ip+"/32";
    else
      return ip+"/128";
  }
}

static bool is_valid_id(const std::string& s) {
  regex pattern(VALID_ID_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(s,m,pattern);
}

static bool is_valid_devid(const std::string& s) {
  regex pattern(VALID_DEVID_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(s,m,pattern);
}

////////////////////////////////////////////////////////////////////////////
inline bool validate_request() {
  if ( op!="GET"&&op!="ADD"&&op!="DEL"&&op!="MOD" )
    return false;
  if (id.size() && !is_valid_id(id) )
    return false;
  if (ip.size() && !is_valid_cidr(ip) ) {
    return false;
  }
  if (devid.size() && !is_valid_devid(devid))
    return false;

  if (op=="ADD" && ip.empty())
    return false;
  if (op=="DEL" && id.empty() && ip.empty() )
    return false;
  if (op=="MOD" && ( id.empty() || (ip.empty() && desc.empty()) ) )
    return false;

  return true;
}

////////////////////////////////////////////////////////////////////////////
inline void ParseReqFromUrlParams(cgicc::Cgicc& cgi) {
  if ( !cgi("op").empty() ) op = boost::to_upper_copy(cgi("op"));
  if ( !cgi("id").empty() ) id = cgi("id");
  if ( !cgi("ip").empty() ) ip = ipAddSuffix(cgi("ip"));
  if ( !cgi("devid").empty() ) devid = cgi("devid");
  if ( !cgi("desc").empty() ) desc = cgi("desc");
  else desc = "";
}

////////////////////////////////////////////////////////////////////////////
static bool op_get(){
  if (!sql) return false;

  string str;
  str="select t1.id, t1.ip, t1.devid, t1.`desc` from t_internal_ip_list t1 where ( 1 = 1 ";

  if (id.size())
    str+=" AND t1.id = ? ";
  if (ip.size())
    str+=" AND t1.ip = ? ";
  if (devid.size())
    str+=" AND t1.devid = ? ";
  if (desc.size())
    str+=" AND t1.`desc` = ? ";
  str+=" ) order by t1.id ";

  cppdb::statement st = *sql <<str;
  if (id.size())
    st<<id;
  if (ip.size())
    st<<ip;
  if (devid.size())
    st<<devid;
  if (desc.size())
    st<<desc;

  try{
    cppdb::null_tag_type nullTag;
    cppdb::result res = st;
    u64 id, devid;
    string ip;
    bool first = true;

    while(res.next()){
      if (first)
        first=false;
      else
        output<<","<<endl;

      output<<"{";

      res >> id >> ip;
      output_u64(output, "id", id);
      output<<',';
      output_string(output, "ip", ip);
      output<<',';

      res>>cppdb::into(devid,nullTag);
      if (nullTag==cppdb::null_value)
        output_string(output, "devid", "");
      else
        output_string(output, "devid", to_string(devid));
      output<<',';
 
      res>>desc; 
      output_string(output, "desc", desc);

      output<<"}";
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_add(){
  if (!sql) return false;

  try{
    cppdb::statement st = *sql << "insert into t_internal_ip_list(`ip`,`devid`,`desc`) value(?,?,?)";
    st<<ip;

    if (!devid.empty())
      st<<atoll(devid.c_str());
    else
     st<<cppdb::null;

    st<<desc<<cppdb::exec;
    
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_del(){
  if (!sql) return false;

  string str = "delete from t_internal_ip_list where ( 1=1 ";
  if (id.size())
    str+=" AND id = ? ";
  if (ip.size())
    str+=" AND ip = ? ";
  if (devid.size())
    str+=" AND devid = ? ";
  if (desc.size())
    str+=" AND `desc` = ? ";
  str+=" )";

  try{
    cppdb::statement st = *sql <<str;
    if (id.size())
      st<<id;
    if (ip.size())
      st<<ip;
    if (devid.size())
      st<<devid;
    if (desc.size())
      st<<desc;

    st<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
    return false;
  }

  return true;
}

static void stAddUpdateSet(string& str, const string s){
  static bool first=true;

  if (first){
    str+=s;
    first=false;
  }
  else
    str+=", "+s;
}

////////////////////////////////////////////////////////////////////////////
static bool op_mod(){
  if (!sql) return false;

  string str = "update t_internal_ip_list SET ";
  if (ip.size())
    stAddUpdateSet(str,"ip = ?");

  stAddUpdateSet(str,"devid = ?");

  if (desc.size())
    stAddUpdateSet(str,"`desc` = ?");
  str+=" WHERE id = ?";

  try{
    cppdb::statement st = *sql <<str;
    if (ip.size())
      st<<ip;

    if (devid.size())
      st<<devid;
    else
      st<<cppdb::null;

    if (desc.size())
      st<<desc;

    st<<id<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  bool succeed = false;

  if (!validate_request()){
    output<<"[{failed}]"<<endl;
    return;
  }

  output<<'[';

  if (op=="GET")
    succeed = op_get();
  else if (op=="ADD")
    succeed = op_add();
  else if (op=="DEL")
    succeed = op_del();
  else if (op=="MOD")
    succeed = op_mod();

  if ( op=="ADD"||op=="DEL"||op=="MOD" ){
    if (!succeed)
      output<<"{failed}";
    else
      output<<"{executed}";
  }

  output<<']'<<endl;
}

///////////////////////////////////////////////////////////

namespace config{

ConfigInternalIp::ConfigInternalIp(const std::string& type, cppdb::session* sql):Config(type, sql){
	return;
}
ConfigInternalIp::~ConfigInternalIp(){
}

bool ConfigInternalIp::Process(cgicc::Cgicc& cgi){
	ParseReqFromUrlParams(cgi);

	try {
		process();
	} catch (std::exception const &e) {
		log_err("%s\n", e.what());
		return false;
	}
	cout<<output.str();

	return true;
}

} // namespace config
