#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include "dbc.h"
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <boost/algorithm/string.hpp>
#include "boost/regex.hpp"

#define VALID_ID_PATTERN "^[1-9]\\d*$"
#define VALID_DEVID_PATTERN "^[0-9]\\d*$"
#define CIDR_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}(/(([12]?[0-9])|(3[0-2])))?$"

using namespace std;
using namespace cppdb;
using namespace boost;

static cppdb::session* sql;
static bool is_http = false;

static std::string op;
static std::string id;
static std::string ip;
static std::string devid;
static std::string desc;

stringstream output;

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
static inline bool is_valid_cidr(const std::string& ip) {
  regex pattern(CIDR_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(ip,m,pattern);
}

////////////////////////////////////////////////////////////////////////////
static std::string inline ipAddSuffix(const std::string& ip){
  if (ip==""||ip.find('/')!=string::npos)
    return ip;
  else
    return ip+"/32";
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
  if (ip.size() && !is_valid_cidr(ip) )
    return false;
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
  sql = start_db_session();

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
  sql = start_db_session();
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
  sql = start_db_session();

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
  sql = start_db_session();

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

////////////////////////////////////////////////////////////////////////////
void test(){
  // op = "DEL";
  // id = "5";
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  sql = NULL;
  is_http = getenv("REMOTE_ADDR") != NULL;
  output<<"Content-Type: application/json; charset=UTF-8\r\n\r\n";
  
  if (is_http) {
    cgicc::Cgicc cgi;
    ParseReqFromUrlParams(cgi);
  } else {
    test();
  }

  try {
    process();
  } catch (std::exception const &e) {
   log_err("%s\n", e.what());
  }
  cout<<output.str();
  if (sql){
    sql->close();
    delete sql;
  }
  return 0;
}
