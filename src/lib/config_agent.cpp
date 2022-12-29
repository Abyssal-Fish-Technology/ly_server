#include "config_agent.h"
#include <boost/algorithm/string.hpp>
#include "../common/common.h"
#include "../common/log.h"

using namespace std;
using namespace config_req;

// Fucntions used for .so
config::Config *CreateConfigInstance(const std::string& type, cppdb::session* sql) {
	return new config::ConfigAgent(type, sql);
}

void FreeConfigInstance(config::Config *p){
	// delete p;
}
///////////////////////////////////////////////////////////

namespace config{

ConfigAgent::ConfigAgent(const std::string& type, cppdb::session* sql):Config(type, sql){
	_req = NULL;
	_isDevice = false;
	_isController = false;
}

ConfigAgent::~ConfigAgent(){
	if (_req){
		delete _req;
	}
}

bool ConfigAgent::Process(cgicc::Cgicc& cgi){
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

bool ConfigAgent::ParseReq(cgicc::Cgicc& cgi){
	if ( !cgi("target").empty() ){
		if ( boost::to_upper_copy(cgi("target"))=="DEVICE" )
			return ParseReqForDevice(cgi);
		else if ( boost::to_upper_copy(cgi("target"))=="CONTROLLER" )
			return ParseReqForController(cgi);

		return false;
	}

	Agent *req = new Agent();
	this->_req = req;

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
		else
			return false;
	}

	if (!cgi("id").empty()) req->set_id(atoll(cgi("id").c_str()));
	if (!cgi("name").empty()) req->set_name(cgi("name"));
	if (!cgi("ip").empty()) req->set_ip(cgi("ip"));
	if (!cgi("creator").empty()) req->set_creator(cgi("creator"));
	if (!cgi("status").empty()) req->set_status(cgi("status"));
	if (!cgi("comment").empty()) req->set_comment(cgi("comment"));
	if (!cgi("disabled").empty()) req->set_disabled(cgi("disabled"));

	return true;
}

bool ConfigAgent::ParseReqForDevice(cgicc::Cgicc& cgi){
	Device *req = new Device();
	this->_req = req;

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
		else
			return false;
	}

	if (!cgi("id").empty()) req->set_id(atoll(cgi("id").c_str()));
	if (!cgi("name").empty()) req->set_name(cgi("name"));
	if (!cgi("device_type").empty()) req->set_type(cgi("device_type"));
	if (!cgi("model").empty()) req->set_model(cgi("model"));
	if (!cgi("agentid").empty()) req->set_agentid(cgi("agentid")=="null"?0:atoll(cgi("agentid").c_str()));
	if (!cgi("creator").empty()) req->set_creator(cgi("creator"));
	if (!cgi("comment").empty()) req->set_comment(cgi("comment"));
	if (!cgi("ip").empty()) req->set_ip(cgi("ip"));
	if (!cgi("port").empty()) req->set_port(atoll(cgi("port").c_str()));
	if (!cgi("disabled").empty()) req->set_disabled(cgi("disabled"));
	if (!cgi("flowtype").empty()) req->set_flowtype(cgi("flowtype"));

	this->_isDevice = true;
	return true;
}

bool ConfigAgent::ParseReqForController(cgicc::Cgicc& cgi){
	Controller *req = new Controller();
	this->_req = req;

	if (cgi("op").empty())
		return false;
	else {
		string op = boost::to_upper_copy(cgi("op"));

		if (op=="MOD")
			_op = MOD;
		else if (op=="GET")
			_op = GET;
		else
			return false;
	}

	if (!cgi("id").empty()) req->set_id(atoll(cgi("id").c_str()));
	if (!cgi("name").empty()) req->set_name(cgi("name"));
	if (!cgi("value").empty()) req->set_value(cgi("value")=="null"?"":cgi("value"));

	this->_isController = true;
	return true;
}

bool ConfigAgent::ValidateRequest(){
	if (this->_isDevice)
		return ValidateRequestForDevice();

	if (this->_isController)
		return ValidateRequestForController();

	Agent *req = (Agent *)_req;

	switch (_op){
		case ADD:
			if ( !req->has_name() || !req->has_ip() ) {
				log_err("%s: %d: no name or ip", __FILE__, __LINE__);
				return Failed();
			}
			if ( !req->has_status() )
				req->set_status("disconnected");
			if ( !req->has_disabled())
				req->set_disabled("Y");
			break;
		case DEL:
			if ( !req->has_id() ) {
				log_err("%s: %d: no id", __FILE__, __LINE__);
				return Failed();
			}
			break;
		case MOD:
			if ( !req->has_id() ) {
				log_err("%s: %d: no id", __FILE__, __LINE__);
				return Failed();
			}
			if ( !req->has_name() && !req->has_ip() && !req->has_creator() && !req->has_status() && !req->has_comment() && !req->has_disabled() ) {
				log_err("%s: %d: no other params", __FILE__, __LINE__);
				return Failed();
			}
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	if (req->has_ip() && !this->is_valid_cidr(req->ip())) {
		log_err("%s: %d: not valid ip: %s", __FILE__, __LINE__, req->ip().c_str());
		return Failed();
	}
	if (req->has_disabled() && req->disabled()!="Y" && req->disabled()!="N" ) {
		log_err("%s: %d: not valid disabled: %s", __FILE__, __LINE__, req->disabled().c_str());
		return Failed();
	}

	return true;
}

bool ConfigAgent::ValidateRequestForDevice(){
	Device *req = (Device *)_req;

	switch (_op){
		case ADD:
			if ( !req->has_name() ) {
				log_err("%s: %d: no name or ip", __FILE__, __LINE__);
				return Failed();
			}
			if ( !req->has_type() )
				req->set_type("router");
			if ( !req->has_disabled() )
				req->set_disabled("N");
			if ( !CheckAgentAndPort(req) ) {
				log_err("%s: %d: CheckAgentAndPort() failed", __FILE__, __LINE__);
				return Failed();
			}
			if ( req->flowtype()=="" )
				req->set_flowtype("netflow");
			break;
		case DEL:
			if ( !req->has_id() ) {
				log_err("%s: %d: no id", __FILE__, __LINE__);
				return Failed();
			}
			break;
		case MOD:
			if ( !req->has_id() ) {
				log_err("%s: %d: no id", __FILE__, __LINE__);
				return Failed();
			}
			if ( !req->has_name() && !req->has_type() && !req->has_model() && !req->has_agentid() && !req->has_creator() && !req->has_comment() && !req->has_ip() && !req->has_port() && !req->has_disabled() ) {
				log_err("%s: %d: no other params", __FILE__, __LINE__);
				return Failed();
			}
			if ( !CheckAgentAndPort(req) ) {
				log_err("%s: %d: CheckAgentAndPort() failed", __FILE__, __LINE__);
				return Failed();
			}
			break;
		case GET:
			break;
		default:
			return false; // This code should never execute
			break;
	}

	if (req->has_ip() && !this->is_valid_cidr(req->ip())) {
		log_err("%s: %d: not valid ip: %s", __FILE__, __LINE__, req->ip().c_str());
		return Failed();
	}
	if (req->has_disabled() && req->disabled()!="Y" && req->disabled()!="N" ) {
		log_err("%s: %d: not valid disabled: %s", __FILE__, __LINE__, req->disabled().c_str());
		return Failed();
	}
	if (req->has_port() && !this->is_valid_port(req->port())) {
		log_err("%s: %d: not valid port: %u", __FILE__, __LINE__, req->port());
		return Failed();
	}

	return true;
}

bool ConfigAgent::ValidateRequestForController(){
	Controller *req = (Controller *)_req;

	switch (_op){
		case ADD:
			log_err("%s: %d: op=add is not allowed for controller", __FILE__, __LINE__);
			return Failed();
			break;
		case DEL:
			log_err("%s: %d: op=del is not allowed for controller", __FILE__, __LINE__);
			return Failed();
			break;
		case MOD:
			if ( !req->has_id() || !req->has_value() ) {
				log_err("%s: %d: op=mod: no id or value", __FILE__, __LINE__);
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

bool ConfigAgent::Add(){
	if (this->_isDevice)
		return AddDevice();

	Agent *req = (Agent *)_req;
	cppdb::statement st = *_sql << "INSERT INTO `server`.`t_agent` (`name`, `ip`, `creator`, `status`, `comment`, `disabled`) VALUES (?,?,?,?,?,?)";
	st << req->name() << req->ip() << req->creator() << req->status() << req->comment() << req->disabled();

	try{
		st << cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed("\"id\": "+to_string(st.last_insert_id()));
}

bool ConfigAgent::Del(){
	if (this->_isDevice)
		return DelDevice();

	Agent *req = (Agent *)_req;

	try{
		cppdb::statement st = *_sql << "DELETE FROM `t_agent` WHERE `id` = ?";
		st << req->id() << cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigAgent::Mod(){
	if (this->_isDevice)
		return ModDevice();

	if (this->_isController)
		return ModController();

	Agent *req = (Agent *)_req;

	string str = "UPDATE `t_agent` SET ";
	if (req->has_name())
		stAddUpdateSet(str, "`name` = ?");
	if (req->has_ip())
		stAddUpdateSet(str, "`ip` = ?");
	if (req->has_creator())
		stAddUpdateSet(str, "`creator` = ?");
	if (req->has_status())
		stAddUpdateSet(str, "`status` = ?");
	if (req->has_comment())
		stAddUpdateSet(str, "`comment` = ?");
	if (req->has_disabled())
		stAddUpdateSet(str, "`disabled` = ?");
	str+=" WHERE id = ?";
	try{
		cppdb::statement st = *_sql <<str;
		if (req->has_name())
			st << req->name();
		if (req->has_ip())
			st << req->ip();
		if (req->has_creator())
			st << req->creator();
		if (req->has_status())
			st << req->status();
		if (req->has_comment())
			st << req->comment();
		if (req->has_disabled())
			st << req->disabled();
		st<<req->id();
		st<<cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigAgent::Get(){
	if (this->_isDevice)
		return GetDevice();

	if (this->_isController)
		return GetController();

	Agent *req = (Agent *)_req;

	string str = "SELECT `id`, `name`, `ip`, `creator`, `status`, `comment`, `disabled` FROM `t_agent` WHERE 1";

	if ( req->has_id() )
		str += " AND `id` = ?";
	if ( req->has_name() )
		str += " AND `name` = ?";
	if ( req->has_ip() )
		str += " AND `ip` = ?";
	if ( req->has_creator() )
		str += " AND `creator` = ?";
	if ( req->has_status() )
		str += " AND `status` = ?";
	if ( req->has_comment() )
		str += " AND `comment` = ?";
	if ( req->has_disabled() )
		str += " AND `disabled` = ?";

	cppdb::statement st = *_sql <<str;

	if ( req->has_id() )
		st <<req->id();
	if ( req->has_name() )
		st <<req->name();
	if ( req->has_ip() )
		st <<req->ip();
	if ( req->has_creator() )
		st <<req->creator();
	if ( req->has_status() )
		st <<req->status();
	if ( req->has_comment() )
		st <<req->comment();
	if ( req->has_disabled() )
		st <<req->disabled();

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
		output_string("name", s);
		cout<<",";

		r>>s;
		output_string("ip", s);
		cout<<",";

		r>>s;
		output_string("creator", s);
		cout<<",";

		r>>s;
		output_string("status", s);
		cout<<",";

		r>>s;
		output_string("comment", s);
		cout<<",";

		r>>s;
		output_string("disabled", s);
		cout<<"}";
	}

	return true;
}

bool ConfigAgent::AddDevice(){
	Device *req = (Device *)_req;

	cppdb::statement st = *_sql << "INSERT INTO `t_device`(`name`, `type`, `model`, `agentid`, `creator`, `comment`, `ip`, `port`, `disabled`, `flowtype`) VALUES (?,?,?,?,?,?,?,?,?,?)";
	st << req->name() << req->type() << req->model();
	if ( req->has_agentid() && req->agentid()>0 ) st << req->agentid();
	else st << cppdb::null;
	st << req->creator() << req->comment() << req->ip() << req->port() << req->disabled() << req->flowtype();

	try{
		st << cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed("\"id\": "+to_string(st.last_insert_id()));
}

bool ConfigAgent::DelDevice(){
	Device *req = (Device *)_req;

	try{
		cppdb::statement st = *_sql << "DELETE FROM `t_device` WHERE `id` = ?";
		st << req->id() << cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigAgent::ModDevice(){
	Device *req = (Device *)_req;

	string str = "UPDATE `t_device` SET ";
	if (req->has_name())
		stAddUpdateSet(str, "`name` = ?");
	if (req->has_type())
		stAddUpdateSet(str, "`type` = ?");
	if (req->has_model())
		stAddUpdateSet(str, "`model` = ?");
	if (req->has_agentid())
		stAddUpdateSet(str, "`agentid` = ?");
	if (req->has_creator())
		stAddUpdateSet(str, "`creator` = ?");
	if (req->has_comment())
		stAddUpdateSet(str, "`comment` = ?");
	if (req->has_ip())
		stAddUpdateSet(str, "`ip` = ?");
	if (req->has_port())
		stAddUpdateSet(str, "`port` = ?");
	if (req->has_disabled())
		stAddUpdateSet(str, "`disabled` = ?");
	if (req->has_flowtype())
		stAddUpdateSet(str, "`flowtype` = ?");
	str+=" WHERE id = ?";
	try{
		cppdb::statement st = *_sql <<str;
		if (req->has_name())
			st << req->name();
		if (req->has_type())
			st << req->type();
		if (req->has_model())
			st << req->model();
		if (req->has_agentid()){
			if (req->agentid()>0)
				st << req->agentid();
			else
				st << cppdb::null;
		}
		if (req->has_creator())
			st << req->creator();
		if (req->has_comment())
			st << req->comment();
		if (req->has_ip())
			st << req->ip();
		if (req->has_port())
			st << req->port();
		if (req->has_disabled())
			st << req->disabled();
		if (req->has_flowtype())
			st << req->flowtype();
		st<<req->id();
		st<<cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigAgent::GetDevice(){
	Device *req = (Device *)_req;

	string str = "SELECT `id`, `name`, `type`, `model`, `agentid`, `creator`, `comment`, `ip`, `port`, `disabled`, `flowtype` FROM `t_device` WHERE 1";

	if ( req->has_id() )
		str += " AND `id` = ?";
	if ( req->has_name() )
		str += " AND `name` = ?";
	if ( req->has_type() )
		str += " AND `type` = ?";
	if ( req->has_model() )
		str += " AND `model` = ?";
	if ( req->has_agentid() ){
		if ( req->agentid()>0 )
			str += " AND `agentid` = ?";
		else
			str += " AND `agentid` IS NULL";
	}
	if ( req->has_creator() )
		str += " AND `creator` = ?";
	if ( req->has_comment() )
		str += " AND `comment` = ?";
	if ( req->has_ip() )
		str += " AND `ip` = ?";
	if ( req->has_port() )
		str += " AND `port` = ?";
	if ( req->has_disabled() )
		str += " AND `disabled` = ?";
	if ( req->has_flowtype() )
		str += " AND `flowtype` = ?";

	cppdb::statement st = *_sql <<str;

	if ( req->has_id() )
		st <<req->id();
	if ( req->has_name() )
		st <<req->name();
	if ( req->has_type() )
		st <<req->type();
	if ( req->has_model() )
		st <<req->model();
	if ( req->has_agentid() && req->agentid()>0 )
		st <<req->agentid();
	if ( req->has_creator() )
		st <<req->creator();
	if ( req->has_comment() )
		st <<req->comment();
	if ( req->has_ip() )
		st <<req->ip();
	if ( req->has_port() )
		st <<req->port();
	if ( req->has_disabled() )
		st <<req->disabled();
	if ( req->has_flowtype() )
		st <<req->flowtype();

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
		cout<<",";

		r>>s;
		output_string("device_type", s);
		cout<<",";

		r>>s;
		output_string("model", s);
		cout<<",";

		r>>cppdb::into(u,null_tag);
		if (null_tag==cppdb::null_value)
			output_string("agentid","");
		else
			output_u64("agentid", u);
		cout<<",";

		r>>s;
		output_string("creator", s);
		cout<<",";

		r>>s;
		output_string("comment", s);
		cout<<",";

		r>>s;
		output_string("ip", s);
		cout<<",";

		r>>u;
		output_u64("port", u);
		cout<<",";

		r>>s;
		output_string("disabled", s);
		cout<<",";

		r>>s;
		output_string("flowtype", s);
		cout<<"}";
	}

	return true;
}

bool ConfigAgent::ModController(){
	Controller *req = (Controller *)_req;

	string str = "UPDATE `t_config` SET `value` = ? WHERE `id` = ?";
	try{
		cppdb::statement st = *_sql <<str;
		if (req->value()=="")
			st << cppdb::null;
		else
			st << req->value();

		st<<req->id();
		st<<cppdb::exec;
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
		return Failed();
	}

	return Executed();
}

bool ConfigAgent::GetController(){
	Controller *req = (Controller *)_req;

	string str = "SELECT `id`, `name`, `value` FROM `t_config` WHERE 1";

	if ( req->has_id() )
		str += " AND `id` = ?";
	if ( req->has_name() )
		str += " AND `name` = ?";
	if ( req->has_value() ){
		if (req->value()=="")
			str += " AND `value` IS NULL";
		else
			str += " AND `value` = ?";
	}

	cppdb::statement st = *_sql <<str;

	if ( req->has_id() )
		st <<req->id();
	if ( req->has_name() )
		st <<req->name();
	if ( req->value()!="" )
		st <<req->value();

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
		cout<<",";

		r>>cppdb::into(s,null_tag);
		if (null_tag==cppdb::null_value)
			output_string("value","");
		else
			output_string("value", s);
		cout<<"}";
	}

	return true;
}

bool ConfigAgent::CheckAgentAndPort(google::protobuf::Message *_req){
	Device *req = (Device *)_req;
	cppdb::result r;

	if ( req->has_agentid() && req->agentid()>0 ){
		r = *_sql <<"SELECT `id` FROM `t_agent` WHERE `id` = ?"<<req->agentid();
		if (!r.next())
			return false;
	}

	if (req->has_agentid())
		r = *_sql <<"SELECT `id` FROM `t_device` WHERE `agentid`=? AND `port`=?"<<req->agentid()<<req->port();
	else
		r = *_sql <<"SELECT `id` FROM `t_device` WHERE `agentid` IS NULL AND `port`=?"<<req->port();

	if (r.next()) {
		if (_op==ADD)
			return false;

		uint32_t id;
		r>>id;
		if (id!=req->id())
			return false;
	}

	return true;
}

} // namespace config
