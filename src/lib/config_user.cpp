#include "config_user.h"
#include "../common/common.h"
#include "../common/md5.h"
#include "../common/ip.h"
#include "../common/log.h"
#include <cppdb/frontend.h>
#include <cgicc/CgiDefs.h>
#include <Cgicc.h>
#include <cgicc/HTTPContentHeader.h>
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace cppdb;
using namespace cgicc;
using namespace config_req;
static string level_ = "";


//Fucntions used for .so
config::Config *CreateConfigInstance(const std::string& type, cppdb::session* sql) {
  return new config::ConfigUser(type, sql);
}


void FreeConfigInstance(config::Config *p){
// delete p;
}
////////////////////////////////////////////////////////////////////////////

/*static cppdb::session* start_db_session() {
  string dbdatabase = "server";
  string mysql_group = "gl.server";
  session* sql = new session("mysql:database=" + dbdatabase + ";read_default_group=" + mysql_group);
  return sql;
}*/


static string get_session_from_cookie(const std::vector< HTTPCookie > &cookie_list) {
  string sid = "";
  for( const_cookie_iterator it = cookie_list.begin();
    it != cookie_list.end();
    it++) {
    if (it->getName()=="SESSION_ID")
      sid = it->getValue();
  }

  return sid;
}

/*static void get_level(int uid) {
  cppdb::session* sql = NULL;
  sql = start_db_session();
  try {
    cppdb::result res = *sql<<"SELECT `level` FROM `t_user` WHERE `id` = ?" << uid;
    if (res.next())
      res >> level_;
    } catch (std::exception const &e) {
      log_err("Error when get_uid(): %s", e.what());
    }

}

static int get_uid(const string& sid) {
  int uid = 0;
  cppdb::session* sql = NULL;
  sql = start_db_session();
  if ( sid.size()!=SESSION_LEN )
    return uid;
  
  try {
    cppdb::result res = *sql<<"SELECT `uid` FROM `t_user_session` WHERE `sid` = ?" << sid;
    if (res.next())
      res >> uid;
    } catch (std::exception const &e) {
      log_err("Error when get_uid(): %s", e.what());
    }
    
    return uid;
}*/


namespace config {

ConfigUser::ConfigUser(const std::string& type, cppdb::session* sql):Config(type, sql) {
  _req = NULL;
}

ConfigUser::~ConfigUser() {
  if (_req) {
    delete _req;
  }
}

bool ConfigUser::Process(cgicc::Cgicc& cgi) {
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

  switch (_op) {
    case ADD:
      res = Add();
      break;
    case DEL:
      res = Del();
      break;
    case MOD:
      res = Mod();
      break;
    case GET:
      res = Get();
      break;
    default:
      break; 
  }
  
  cout<<"]";
  return res; 
}

bool ConfigUser::ParseReq(cgicc::Cgicc& cgi) {
  User *req = new User();
  this->_req = req;
  int id = 0;
  string sid = get_session_from_cookie(cgi.getEnvironment().getCookieList());
  if (!sid.empty()) {
    //id = get_uid(sid);
    //get_level(id);
    id = atoi(getenv("UID"));
    level_ = getenv("LEVEL");
  }
  req->set_id(id);

  if (cgi("op").empty())
    return Failed();
  else {
    string op = boost::to_upper_copy(cgi("op"));
    
    if (op == "ADD")
      _op = ADD;
    else if (op == "DEL")
      _op = DEL;
    else if (op == "MOD")
      _op = MOD;
    else if (op == "GET")
      _op = GET;
    else 
      return Failed();
  } 
  
  if (!cgi("passwd").empty()) req->set_pass(cgi("passwd")=="null"?"":MD5(cgi("passwd")).toString());
  if (!cgi("name").empty()) req->set_username(cgi("name"));
  if (!cgi("id").empty()) 
    req->set_uid(atoi(cgi("id").c_str()));
  if (!cgi("level").empty()) req->set_level(cgi("level")=="null"?"":cgi("level"));
  if (!cgi("lockedtime").empty()) req->set_lockedtime(atoll(cgi("lockedtime").c_str()));
  if (!cgi("comm").empty()) req->set_comment(cgi("comm")=="null"?"":cgi("comm"));
  if (!cgi("disabled").empty()) req->set_disabled(cgi("disabled")=="null"?"":cgi("disabled"));
  if (!cgi("reso").empty()) req->set_resource(cgi("reso")=="null"?"":cgi("reso"));

  return true;
}

bool ConfigUser::ValidateRequest() {
 
  User *req = (User *)_req;
  switch (_op) {
    case ADD:
      if (!req->has_username()) {
        return Failed();
      }
      if (!req->has_pass())
        req->set_pass("");
      if (!req->has_disabled() || req->disabled() == "")
        req->set_disabled("N"); 
      if (!req->has_level() || req->level() == "")
        req->set_level("viewer");
      if (!req->has_lockedtime())
        req->set_lockedtime(0);
      if (!req->has_resource())
        req->set_resource("");
      break;
    case DEL:
      if (!req->has_uid())
        return Failed();
      break;
    case MOD:
      if (!req->has_uid())
        return Failed();
      if (!req->has_pass() && !req->has_level() && !req->has_resource() && !req->has_lockedtime())
        return Failed();
      if (!req->has_lockedtime())
        req->set_lockedtime(0);
      break;
    case GET:
      if (level_=="sysadmin")
        req->clear_uid();
      else
        req->set_uid(req->id());
      break;
    default:
      return false;
      break;
  }
  
  return true;
}

bool ConfigUser::Add() {
  User *req = (User *)_req;
  string creator;
  cppdb::result res = *_sql << "SELECT `name` FROM `t_user` WHERE `id` = ?" << req->id();
  if (res.next())
    res >> creator;

  cppdb::statement st = *_sql << "INSERT INTO `t_user` (`name`, `pass`, `lasttime`, `lastip`, `level`, `createtime`, `comment`, `disabled`, `creator`, `lockedtime`, `lastsession`, `resource`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
  try {
    st << req->username() << req->pass();
    st << cppdb::null;
    st << cppdb::null;
    
    st << req->level();

    //st << req->createtime();
    st << time(NULL);

    if (req->comment() == "")
      st << cppdb::null;
    else 
      st << req->comment();
    
    st << req->disabled();
    //st << req->creator();
    st << creator;
    st << req->lockedtime();
    st << "";
    st << req->resource() << cppdb::exec;
  } catch (cppdb::cppdb_error const &e) {
    log_err("%s", e.what());
    return Failed();
  }

  return Executed("\"id\": "+to_string(st.last_insert_id()));
}

bool ConfigUser::Del() {
  User *req = (User *)_req;
  try {
    cppdb::statement st = *_sql << "DELETE FROM `t_user` WHERE `id` = ?";
    st << req->uid() << cppdb::exec;
  } catch (cppdb::cppdb_error const &e) {
    log_err("%s", e.what());
    return Failed();
  }

  return Executed();
}

bool ConfigUser::Mod() {
  User *req = (User *)_req;
  string str = "UPDATE `t_user` SET ";
  if (req->has_pass())
    stAddUpdateSet(str, "`pass` = ?");
  if (req->has_level())
    stAddUpdateSet(str, "`level` = ?");
  if (req->has_resource())
    stAddUpdateSet(str, "`resource` = ?");
  if (req->has_disabled())
    stAddUpdateSet(str, "`disabled` = ?");
  if (req->has_comment())
    stAddUpdateSet(str, "`comment` = ?");
  if (req->has_lockedtime())
    stAddUpdateSet(str, "`lockedtime` = ?");
  str += " WHERE id = ?";
  try {
    cppdb::statement st = *_sql << str;
    if (req->has_pass())
      st << req->pass();
    if (req->has_level()) {
      if (req->level() == "")
        st << "viewer";
      else
        st << req->level();
    }
    if (req->has_resource())
      st << req->resource();
    if (req->has_disabled())
      st << req->disabled();
    if (req->has_comment())
      st << req->comment();
    if (req->has_lockedtime())
      st << req->lockedtime();
    st << req->uid() << cppdb::exec;
  } catch (cppdb::cppdb_error const &e) {
    log_err("%s", e.what());
    return Failed();
  }

  return Executed();
}

bool ConfigUser::Get(){
  User *req = (User *)_req;

  string str = "SELECT `id`, `name`, `lasttime`, `lastip`, `level`, `createtime`, `comment`, `disabled`, `creator`, `lockedtime`, `resource` FROM `t_user` WHERE 1";

  if ( req->has_uid() )
    str += " AND `id` = ?";
  if ( req->has_username() )
    str += " AND `name` = ?";
  if ( req->has_level() ) {
    if (req->level() == "")
      str += " AND `level` = 'VIEWER'";
    else
      str += "AND `level` = ?";
  }
  if ( req->has_comment() ) {
    if (req->comment() == "")
      str += " AND `comment` IS NULL";
    else
      str += " AND `comment` = ?";
  }
  if ( req->has_disabled() )
    str += " AND `disabled` = ?";
  if ( req->has_lockedtime() )
    str += " AND `lockedtime` = ?";
  if ( req->has_resource() ) {
    if (req->resource() == "")
      str += " AND `resource` IS NULL";
    else
      str += " AND `resource` = ?";
  }

  cppdb::statement st = *_sql <<str;

  if ( req->has_uid() )
    st <<req->uid();
  if ( req->has_username() )
    st << req->username();
  if ( req->has_level() )
    st << req->level();
  if ( req->has_comment() )
    st << req->comment();
  if ( req->has_disabled() )
    st << req->disabled();
  if ( req->has_lockedtime() )
    st << req->lockedtime();
  if ( req->has_resource() )
    st << req->resource();

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

    r>>s;
    output_string("name", s);
    cout<<',';

    r>>cppdb::into(u,null_tag);
    if (null_tag==cppdb::null_value)
      output_string("lasttime", "");
    else
      output_u64("lasttime", u);
    cout<<',';

    r>>cppdb::into(u,null_tag);
    if (null_tag==cppdb::null_value)
      output_string("lastip", "");
    else
      output_string("lastip", ipnum_to_ipstr(u));
    cout<<',';

    r>>s;
    output_string("level", s);
    cout<<',';

    r>>cppdb::into(u,null_tag);
    if (null_tag==cppdb::null_value)
      output_string("createtime", "");
    else
      output_u64("createtime", u);
    cout<<",";


    r>>cppdb::into(s,null_tag);
    if (null_tag==cppdb::null_value)
      output_string("comm", "");
    else
      output_string("comm", s);
    cout<<',';

    r>>s;
    output_string("disabled", s);
    cout<<',';

    r>>s;
    output_string("creator", s);
    cout<<',';

    r>>cppdb::into(u,null_tag);
    if (null_tag==cppdb::null_value)
      output_string("lockedtime", "");
    else
      output_u64("lockedtime", u);
    cout<<",";

    r>>cppdb::into(s,null_tag);
    if (null_tag==cppdb::null_value)
      output_string("reso", "");
    else
      output_string("reso", s);

    cout<<"}";
  }
  
  return true;
}    

}

