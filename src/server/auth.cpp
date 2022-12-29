#include "../common/common.h"
#include "../common/log.h"
#include "../common/md5.h"
#include "../common/ip.h"
#include "define.h"
#include "dbc.h"
#include <cppdb/frontend.h>
#include <cgicc/CgiDefs.h>
#include <Cgicc.h>
#include <cgicc/HTTPContentHeader.h>
#include <boost/algorithm/string.hpp>

#define SESSION_LEN 32
#define MAX_AGE_TIME 2592000    // One month
#define DEFAULT_AGE_TIME 14400  // 4 hours
#define DEFAULT_RETRY_TIME 300 // 5 minutes
#define DEFAULT_RETRY_COUNT 5
#define DEFAULT_LOCK_TIME 1800 // half an hour

#define CODE_TARGET 0

#define CODE_SUCCEED 200

#define CODE_FAIL 300
#define CODE_FAIL_AUTH    301
#define CODE_FAIL_PASS    302
#define CODE_FAIL_LOGGED  303
#define CODE_FAIL_RETRY   304
#define CODE_FAIL_TIMEOUT 305
#define CODE_FAIL_NO_AUTH 306

#define ACTION_LOGIN "login"

using namespace std;
using namespace cppdb;
using namespace cgicc;

enum Level {
  SYSADMIN = 1,
  ANALYSER,
  VIEWER 
}; 

static std::set<string> api_set{"mo", "feature", "topn", "login", "logout", "event", "config", 
                                "bwlist", "internalip", "ipinfo", "portinfo", "locinfo", "threatinfo",
                                "threatinfopro", "geoinfo", "auth_status", "sctl", "event_feature", "evidence"};

static cppdb::session* sql;
static bool is_http = false;

// Check if session "sid" has logged.
// return uid for session
// return 0 when failed
static int check_session(const string& sid, time_t ts = 0) {
	int uid = 0;
	string lastsession;

	if ( sid.size()!=SESSION_LEN )
		return uid;

	if (ts==0) ts = time(NULL);

	try {
		cppdb::result res = *sql<<"SELECT `id`, `lastsession` FROM `t_user` WHERE `id` IN (SELECT `uid` FROM `t_user_session` WHERE `sid` = ? AND `expire_time` > ?)" << sid << ts;
		if (res.next())
			res >> uid >> lastsession;
	} catch (std::exception const &e) {
		log_err("Error when check_session(): %s", e.what());
	}

	if (lastsession==sid) // session has logged
		return uid;
	else
		return 0;
}

// Get uid from session
static int get_uid(const string& sid) {
	int uid = 0;

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
}

// Get session id from cookie.
// Return "" if not exists, otherwise return session id "sid"
static string get_session_from_cookie(const std::vector< HTTPCookie > &cookie_list) {
	string sid = "";

	for( const_cookie_iterator it = cookie_list.begin();
		it != cookie_list.end();
		++it) {
		if (it->getName()=="SESSION_ID")
			sid = it->getValue();
	}

	return sid;
}


// Create session
// Return "" if failed
static string create_session(int uid = 0, int expire_time = 0) {
	char buffer[37];
	FILE * fp = popen("uuidgen", "r");
	if (fp==NULL){
		log_err("Exec 'uuidgen' failed");
		return "";
	}
	fgets(buffer, sizeof(buffer), fp);
	pclose(fp);

	string sid = string(buffer);
	for (string::iterator it =sid.begin(); it != sid.end(); ++it) {
		if ( *it == '-')
			sid.erase(it);
	}

	if (sid.size()!=SESSION_LEN) {
		log_err("User session format wrong: %s", sid.c_str());
		return "";
	}

	log_info("User session created: %s", sid.c_str());

	cppdb::statement st = *sql <<"INSERT INTO `t_user_session`(`sid`, `uid`, `expire_time`) VALUES (?,?,?)" <<sid<<uid<<expire_time;
	try{
		st<<cppdb::exec;
	} catch ( std::exception const &e ){
		log_err("Error when INSERT INTO `t_user_session`: %s", e.what());
		return "";
	}

	return sid;
}

// Delete expired session
static bool delete_expired_session(time_t ts = 0) {
	if (ts==0) ts = time(NULL);

	cppdb::statement st = *sql << "DELETE FROM `t_user_session_history` WHERE `sid` IN (SELECT `sid` FROM `t_user_session` WHERE `expire_time`<=?)" << ts;
	try{
	 	st<<cppdb::exec;
	} catch ( std::exception const &e ){
		log_err("Error when DELETE FROM `t_user_session_history`: %s", e.what());
		return false;
	}

	st = *sql << "DELETE FROM `t_user_session` WHERE `expire_time`<=?" << ts;
	try{
	 	st<<cppdb::exec;
	} catch ( std::exception const &e ){
		log_err("Error when DELETE FROM `t_user_session`: %s", e.what());
		return false;
	}

	return true;
}

// Return code for fluent API
static int log_sesssion_history(const string& sid, int uid, const string& action, int code, time_t ts) {
	cppdb::statement st = *sql <<"INSERT INTO `t_user_session_history`(`sid`, `uid`, `action`, `code`,`time`) VALUES (?,?,?,?,?)"
		<<sid<<uid<<action<<code<<ts;
	try {
		st<<cppdb::exec;
	} catch ( std::exception const &e ){
		log_err("Error when INSERT INTO `t_user_session_history`: %s", e.what());
	}

	int count = 0;
	try {
		if (uid>0 && code>=300 && action==ACTION_LOGIN) { // check if user should be locked
			cppdb::result res = *sql<<"SELECT COUNT(*) FROM `t_user_session_history` WHERE `uid` = ? AND `action` = ? AND `code` = ? AND `time` > ?"
				<< uid << ACTION_LOGIN << CODE_FAIL_AUTH << ts - DEFAULT_RETRY_TIME;
			res.next();
			res>>count;
		}
	} catch ( std::exception const &e ){
		log_err("Error when SELECT COUNT(*) FROM `t_user_session_history`: %s", e.what());
	}

	try {
		if (count>DEFAULT_RETRY_COUNT) {
			st = *sql <<"UPDATE `t_user` SET `lockedtime` = ? WHERE `id` = ?"
				<<ts<<uid;
			st<<cppdb::exec;
			return CODE_FAIL_RETRY;
		}
	} catch ( std::exception const &e ){
		log_err("Error when UPDATE `t_user`: %s", e.what());
	}

	return code;
}

// Check user and pass,
// Return code
static int check_user_pass(const string& user, const string& pass, int& uid) {
	time_t lockedtime;

	try{
		cppdb::result res = *sql<<"SELECT `id`, `pass`, `lockedtime` FROM `t_user` WHERE `name` = ? AND `disabled`='N'" << user;
		if (!res.next())
			return CODE_FAIL_AUTH;

		string p;
		res>>uid>>p>>lockedtime;

		if (lockedtime+DEFAULT_LOCK_TIME>time(NULL))
			return CODE_FAIL_RETRY;
		if (MD5(pass).toString()!=p)
			return CODE_FAIL_AUTH;
	} catch (std::exception const &e) {
		log_err("Error when getting user '%s': %s", user.c_str(), e.what());
		return CODE_FAIL;
	}

	return CODE_SUCCEED;
}

static bool update_session(const string& sid, long uid, long expire_time) {
	cppdb::statement st = *sql <<"UPDATE `t_user_session` SET `uid` = ?, `expire_time` = ? WHERE `sid` = ?"
		<<uid<<expire_time<<sid;
	try{
	 	st<<cppdb::exec;
	} catch ( std::exception const &e ){
		log_err("Error when update_session(): %s", e.what());
		return false;
	}

	return true;
}

static int do_login(const Cgicc & cgi, HTTPContentHeader& header) {
	time_t ts = time(NULL);
	int code = CODE_SUCCEED;

	string user = cgi("auth_user");
	string pass = cgi("auth_pass");
	long age_time = atoll( cgi("auth_agetime").c_str() );

	if (age_time > MAX_AGE_TIME)
		age_time = MAX_AGE_TIME;
	if (age_time < DEFAULT_AGE_TIME)
		age_time = DEFAULT_AGE_TIME;

	long expire_time = ts + age_time;

	string sid = get_session_from_cookie( cgi.getEnvironment().getCookieList() );
	if (sid.empty()) {// no session in cookie, create one
		sid = create_session(0, expire_time);
		if (sid.empty())  // session creation failed
			return CODE_FAIL;
	}

	int uid = check_session(sid, ts);
	if (uid) // if session has logged in
		return log_sesssion_history(sid, uid, ACTION_LOGIN, CODE_FAIL_LOGGED, ts);

	code = check_user_pass(user, pass, uid);
	if (code!=CODE_SUCCEED) { // login failed
		code = log_sesssion_history(sid, uid, ACTION_LOGIN, code, ts);
	}
	else if (update_session(sid, uid, expire_time)) {
		cppdb::statement st = *sql <<"UPDATE `t_user` SET `lasttime` = ?, `lastip` = ?, `lastsession` = ? WHERE `id` = ?"
			<<ts<<ipstr_to_ipnum(cgi.getEnvironment().getRemoteAddr())<<sid<<uid;
		try{
		 	st<<cppdb::exec;
		} catch ( std::exception const &e ){
			log_err("Error when UPDATE `t_user`: %s", e.what());
			code = log_sesssion_history(sid, uid, ACTION_LOGIN, CODE_FAIL, ts);
		}
	}
	else { // session updating failed
		code = log_sesssion_history(sid, uid, ACTION_LOGIN, CODE_FAIL, ts);
	}

	HTTPCookie cookie("SESSION_ID", sid);
	cookie.setMaxAge(age_time);
	header.setCookie(cookie);

	return code;
}

static int do_logout(const cgicc::Cgicc & cgi, HTTPContentHeader& header) {
	time_t ts = time(NULL);
	delete_expired_session(ts);

	long age_time = DEFAULT_AGE_TIME;
	long expire_time = ts + age_time;

	string sid = get_session_from_cookie( cgi.getEnvironment().getCookieList() );
	if (sid.empty()) {// no session in cookie, create one
		sid = create_session(0, expire_time);
		if (sid.empty())  // session creation failed
			return CODE_FAIL;
	}

	int uid = check_session(sid, ts);
	if (uid) {// if session has logged in
		if(!update_session(sid, 0, expire_time))
			return CODE_FAIL;
	}

	HTTPCookie cookie("SESSION_ID", sid);
	cookie.setMaxAge(age_time);
	header.setCookie(cookie);

	return CODE_SUCCEED;
}

static int do_auth_status(const cgicc::Cgicc & cgi, HTTPContentHeader& header) {
	time_t ts = time(NULL);

	long age_time = DEFAULT_AGE_TIME;
	long expire_time = ts + age_time;

	string sid = get_session_from_cookie( cgi.getEnvironment().getCookieList() );
	if (sid.empty()) {// no session in cookie, create one
		sid = create_session(0, expire_time);
		if (sid.empty())  // session creation failed
			return CODE_FAIL;

		HTTPCookie cookie("SESSION_ID", sid);
		cookie.setMaxAge(age_time);
		header.setCookie(cookie);

		return CODE_FAIL;
	}

	if (get_uid(sid)==0) {
		return CODE_FAIL;
	}
	else if (check_session(sid, ts)==0)
		return CODE_FAIL_TIMEOUT;

	return CODE_SUCCEED;
}

static Level SetLevel(const string& level) {
  Level l;
  if (level == "SYSADMIN")
    l = SYSADMIN;
  if (level == "ANALYSER")
    l = ANALYSER;
  if (level == "VIEWER")
    l = VIEWER;
  
  return l;
}

static bool viewer_ident(string& resource, cgicc::Cgicc& cgi, int uid) {
  string type;
  string op;
  string devid;
  string auth_target = cgi("auth_target");
  size_t pos;

  if (!cgi("type").empty())
    type = cgi("type");
  if (!cgi("op").empty())
    op = boost::to_upper_copy(cgi("op"));
  if (!cgi("devid").empty()) {
    devid = cgi("devid").c_str();
    pos = resource.find(devid);
    if (pos == std::string::npos)
      return false;
  }

  if (auth_target == "config") {
    //if (type == "agent" || type == "device")
      //return false;
    if (type == "user" && op == "MOD" && !cgi("passwd").empty()) {
      if (!cgi("id").empty() && uid != atoi(cgi("id").c_str()))
        return false;
      return true;
    }
    if (op == "GET" || op == "GGET") {
      return true;
    }
    return false;
  }
  
  if (op == "ADD" || op == "DEL" || op == "MOD")
    return false;
 
  return true;
} 

static bool analyser_ident(string& resource, cgicc::Cgicc& cgi, int uid) {
  string type;
  string op;
  string devid;
  string auth_target = cgi("auth_target");
  size_t pos;

  if (!cgi("type").empty())
    type = cgi("type");
  if (!cgi("op").empty())
    op = boost::to_upper_copy(cgi("op"));
  if (!cgi("devid").empty()) {
    devid = cgi("devid").c_str();
    pos = resource.find(devid);
    if (pos == std::string::npos)
      return false;
  }

  if (auth_target == "config" && (type == "user" || type == "agent" || type == "device")) {
    if (op == "ADD" || op == "DEL")
      return false;

    if (op == "MOD") {
      if (type == "user") {
        if (!cgi("passwd").empty()) {
          if (!cgi("id").empty() && uid != atoi(cgi("id").c_str()))
            return false;
          return true;
        }  
        return false;
      }
      return false;
    }

    if (op == "GET" || op == "GGET") {
      return true;
    }

  }
 
  return true;

}

static bool auth_control(string& level, cgicc::Cgicc& cgi, string& resource, int uid) {
  /*string type;
  string op;
  char devid;
  string auth_target = cgi("auth_target");

  if (!cgi("type").empty()) 
    type = cgi("type");
  if (!cgi("op").empty())
    op = boost::to_upper_copy(cgi("op"));
  if (!cgi("devid").empty()) {
    devid = cgi("devid").c_str();
    size_t pos = resource.find(devid);
  }*/
  string lev = boost::to_upper_copy(level);
  Level type = SetLevel(lev);
  bool res;

  switch (type) {
    case ANALYSER:
      res = analyser_ident(resource, cgi, uid);
      break;
    case SYSADMIN:
      res = true;
      break;
    case VIEWER:
      res = viewer_ident(resource, cgi, uid);
      break;
    default:
      break;
  }
  
  return res;  
}

static int process(cgicc::Cgicc& cgi, HTTPContentHeader& header) {
	int code = CODE_FAIL;
  int uid = 0;

	// Login
	if (cgi("auth_target")=="login")
		return do_login(cgi, header);

	// Logout
	else if (cgi("auth_target")=="logout")
		return do_logout(cgi, header);

	// Logout
	else if (cgi("auth_target")=="auth_status")
		return do_auth_status(cgi, header);

	else {
		time_t ts = time(NULL);
		string sid = get_session_from_cookie( cgi.getEnvironment().getCookieList() );
		if (sid.empty()) {// no session in cookie, create one
			long age_time = atoll( cgi("auth_agetime").c_str() );

			if (age_time > MAX_AGE_TIME)
				age_time = MAX_AGE_TIME;
			if (age_time < DEFAULT_AGE_TIME)
				age_time = DEFAULT_AGE_TIME;

			long expire_time = ts + age_time;

			sid = create_session(0, expire_time);

			if (sid.empty())  // session creation failed
				return CODE_FAIL;

			HTTPCookie cookie("SESSION_ID", sid);
			cookie.setMaxAge(age_time);
			header.setCookie(cookie);

			return CODE_FAIL;
		}
		else if ((uid=get_uid(sid))==0) {
			return CODE_FAIL;
		}
		else if (check_session(sid, ts)==0)
			return CODE_FAIL_TIMEOUT;

    //get level and resource of user
    string level;
    string resource;
    setenv("UID", to_string(uid).c_str(), 1); 
    try {
      cppdb::result res = *sql <<"SELECT `level`, `resource` FROM `t_user` WHERE `id` = ?" << uid;    
      if (res.next())
        res >> level >> resource;
      setenv("LEVEL", level.c_str(), 1); 
    } catch (std::exception const &e) {
      log_err("error when get level and resource: %s\n", e.what());
    }   

		if ( !cgi("auth_target").empty() ) {
      if (!auth_control(level, cgi, resource, uid)) 
        return CODE_FAIL_NO_AUTH;
			// Execute target
			string target = SERVER_WWW_DIR "/" + cgi("auth_target");
			FILE *fp = popen(target.c_str(), "w");
			const auto& d = cgi.getEnvironment().getPostData();
			if (fp&&d.size())
				fwrite(d.data(), d.size(), 1, fp);
			pclose(fp);
			return CODE_TARGET;
		}
		else
			return CODE_FAIL;
	}

	return code;
}

int main(int argc, char *argv[]) {
	sql = start_db_session();
	is_http = getenv("REMOTE_ADDR") != NULL;
  string api = getenv("SCRIPT_NAME");  //防止命令注入
  if (api != "/d/auth") return 0;

	if (is_http) {
		cgicc::Cgicc cgi;
    if (api_set.find(cgi("auth_target")) == api_set.end()) return 0; //防止命令注入
		HTTPContentHeader header("Content-Type: application/javascript; charset=UTF-8");
		int code = process(cgi, header);
		if (code!=CODE_TARGET) {
			cout << header;
			cout << "[{\"code\": " << code << "}]"<<endl;
		}
	}
	else
		cout<< "Please visit from web." <<endl;

	return 0;
}
