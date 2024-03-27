#include "config_bwlist.h"
#include <boost/algorithm/string.hpp>
#include "../common/common.h"
#include "../common/log.h"
#include "../common/_strings.h"

using namespace std;
using namespace config_req;

// Fucntions used for .so
config::Config *CreateConfigInstance(const std::string& type, cppdb::session* sql) {
	return new config::ConfigBwlist(type, sql);
}

void FreeConfigInstance(config::Config *p){
	// delete p;
}
///////////////////////////////////////////////////////////

namespace config{

ConfigBwlist::ConfigBwlist(const std::string& type, cppdb::session* sql):Config(type, sql){
	_req = NULL;
}

ConfigBwlist::~ConfigBwlist(){
	if (_req){
		delete _req;
	}
}

bool ConfigBwlist::Process(cgicc::Cgicc& cgi){
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

	switch (_op){
		case ADD:
			res = this->Add();
			break;
		case DEL:
			res = this->Del();
			break;
		case MOD:
			res = this->Mod();
			break;
		case GET:
			res = this->Get();
			break;
		default:
			break;
	}

	cout<<"]";

	return res;
}

bool ConfigBwlist::ParseReq(cgicc::Cgicc& cgi){
	Bwlist *req = new Bwlist();
	this->_req = req;

	if (cgi("op").empty())
		return Failed();
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
		else
			return Failed();
	}

	if (cgi("target").empty())
		return Failed();
	else
		req->set_target(cgi("target"));

	if (!cgi("id").empty()) req->set_id(atoll(cgi("id").c_str()));
	if (!cgi("time").empty()) req->set_time(atoll(cgi("time").c_str()));
	if (!cgi("ip").empty()) req->set_ip(cgi("ip")=="null"?"":cgi("ip"));
	if (!cgi("port").empty()) req->set_port(cgi("port")=="null"?"":cgi("port"));
	if (!cgi("desc").empty()) req->set_desc(cgi("desc")=="null"?"":cgi("desc"));

	return true;
}

bool ConfigBwlist::CheckIfExists(Bwlist *req){
	if (req->ip()=="" && req->port()=="")
		return false;

	string str_blacklist = "SELECT COUNT(*) FROM `t_blacklist` WHERE 1";
	string str_whitelist = "SELECT COUNT(*) FROM `t_whitelist` WHERE 1";
	string where;

	if ( req->has_ip() ) {
		if (req->ip()=="")
			where += " AND `ip` IS NULL";
		else
			where += " AND `ip` = ?";
	}
	if ( req->has_port() ) {
		if (req->port()=="")
			where += " AND `port` IS NULL";
		else
			where += " AND `port` = ?";
	}

	try{
		string str = str_blacklist+where+" UNION "+str_whitelist+where;
		cppdb::statement st = *_sql <<str;

		if (req->ip()!="") st << req->ip();
		if (req->port()!="") st << req->port();
		if (req->ip()!="") st << req->ip();
		if (req->port()!="") st << req->port();

		cppdb::result r = st;

		int c;
		while (r.next()) {
			r>>c;
			if (c>0)
				return true;
		}
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s", e.what());
	}

	return false;
}

bool ConfigBwlist::ValidateRequest(){
	Bwlist *req = (Bwlist *)_req;

	if ( req->target()!="whitelist" && req->target()!="blacklist" )
		return Failed();
	else
		req->set_target("t_"+req->target());

	switch (_op){
		case ADD:
			if ( !req->has_ip() && !req->has_port() )
				return Failed();
			if ( !req->has_time() )
				req->set_time(time(NULL));
			if (CheckIfExists(req))
				return Failed();
			break;
		case DEL:
			if ( !req->has_id() )
				return Failed();
			break;
		case MOD:
			if ( !req->has_id() )
				return Failed();
			if ( !req->has_time() &&  !req->has_ip() && !req->has_port() && !req->has_desc() )
				return Failed();
			if (req->has_ip() && req->ip()=="" && req->has_port() && req->port()=="")
				return Failed();
			if (CheckIfExists(req))
				return Failed();
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	if (req->ip()!="" && !this->is_valid_cidr(req->ip()))
		return Failed();
	if (req->has_port() && !this->is_valid_port(req->port()))
		return Failed();

	return true;
}

bool ConfigBwlist::Add(){
	Bwlist *req = (Bwlist *)_req;

	cppdb::statement st = *_sql << string("INSERT INTO `")+req->target()+"`(`time`, `ip`, `port`, `desc`) VALUES (FROM_UNIXTIME(?),?,?,?)";
	st << req->time();
	if ( req->ip()=="" ) st << cppdb::null;
	else st << req->ip();
	if ( req->port()=="" ) st << cppdb::null;
	else st << req->port();
	if ( req->has_desc() )  st << req->desc();

	try{
		st << cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s", e.what());
		return Failed();
	}

	return Executed("\"id\": "+to_string(st.last_insert_id()));
}

bool ConfigBwlist::Del(){
	Bwlist *req = (Bwlist *)_req;

	try{
		cppdb::statement st = *_sql << string("DELETE FROM `")+req->target()+"` WHERE `id` = ?";
		st << req->id() << cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigBwlist::Mod(){
	Bwlist *req = (Bwlist *)_req;

	string str = "UPDATE `"+req->target()+"` SET ";
	if (req->has_time())
		stAddUpdateSet(str, "`time` = FROM_UNIXTIME(?)");
	if (req->has_ip())
		stAddUpdateSet(str, "`ip` = ?");
	if (req->has_port())
		stAddUpdateSet(str, "`port` = ?");
	if (req->has_desc())
		stAddUpdateSet(str, "`desc` = ?");
	str+=" WHERE id = ?";
	try{
		cppdb::statement st = *_sql <<str;
		if (req->has_time())
			st << req->time();
		if (req->has_ip()){
			if ( req->ip()=="") st <<cppdb::null;
			else st << req->ip();
		}
		if (req->has_port()){
			if (req->port()=="") st <<cppdb::null;
			else st << req->port();
		}
		if (req->has_desc())
			st << req->desc();

		st<<req->id();
		st<<cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigBwlist::Get(){
	Bwlist *req = (Bwlist *)_req;

	string str = "SELECT `id`, `time`, `ip`, `port`, `desc` FROM `"+req->target()+"` WHERE 1";

	if ( req->has_id() )
		str += " AND `id` = ?";
	if ( req->has_time() )
		str += " AND `time` = FROM_UNIXTIME(?)";
	if ( req->has_ip() ) {
		if (req->ip()=="")
			str += " AND `ip` IS NULL";
		else
			str += " AND `ip` = ?";
	}
	if ( req->has_port() ) {
		if (req->port()=="")
			str += " AND `port` IS NULL";
		else
			str += " AND `port` = ?";
	}
	if ( req->has_desc() )
		str += " AND `desc` = ?";

	cppdb::statement st = *_sql <<str;

	if ( req->has_id() )
		st <<req->id();
	if ( req->has_time() )
		st <<req->time();
	if (req->ip()!="") st << req->ip();
	if (req->port()!="") st << req->port();
	if ( req->has_desc() )
		st <<req->desc();

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
			output_string("ip", "");
		else
			output_string("ip", s);
		cout<<',';

		r>>cppdb::into(u,null_tag);
		if (null_tag==cppdb::null_value)
			output_string("port", "");
		else
			output_string("port", to_string(u));
		cout<<',';

		r>>s;
		output_string("desc", s);

		cout<<"}";
	}

	return true;
}


} // namespace config