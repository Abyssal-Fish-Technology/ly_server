#include "../common/common.h"
#include "../common/log.h"
#include "../common/ip.h"
#include "../common/http.h"
#include "../common/strings.h"
#include "../common/event.pb.h"
#include "../common/event_req.h"
#include "define.h"
#include "dbc.h"
#include <google/protobuf/text_format.h>
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <cgicc/HTTPStatusHeader.h>
#include "../common/mo_req.h"

const char log_file[] = SERVER_LOG_DIR "/" __FILE__;

using namespace std;
using namespace cppdb;
using namespace event;

static bool is_http = false;
static WebReq req;
static bool debug = false;
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

static void process_aggre(){
  session* sql = start_db_session();

  string str = "SELECT `id`, `event_id`, `devid`, `obj`, `type`, `model`, `level`, `alarm_peak`, `sub_events`, `alarm_avg`, `value_type`, `desc`, `duration`, `starttime`, `endtime`, `is_alive`, `proc_status`, `proc_comment` "
               "FROM `t_event_data_aggre` WHERE ( ";
  if (req.has_endtime())
    mo::stAddWhere(str,"`starttime` <= ?");
  if (req.has_starttime())
    mo::stAddWhere(str,"`endtime` >= ?");
  if (req.has_id())
    mo::stAddWhere(str,"`id` = ?");
  if (req.has_type())
    mo::stAddWhere(str,"`type` = ?");
  if (req.has_model())
    mo::stAddWhere(str,"`model` = ?");
  if (req.has_devid())
    mo::stAddWhere(str,"`devid` = ?");
  if (req.has_event_id())
    mo::stAddWhere(str,"`event_id` = ?");
  if (req.has_obj())
    mo::stAddWhere(str,"`obj` = ?");
  if (req.has_level())
    mo::stAddWhere(str,"`level` = ?");
  if (req.has_is_alive())
    mo::stAddWhere(str,"`is_alive` = ?");
  if (req.has_proc_status())
    mo::stAddWhere(str,"`proc_status` = ?");
  if (req.has_proc_comment())
    mo::stAddWhere(str,"`proc_comment` = ?");
  str += " ) ORDER BY `starttime`";

  cppdb::statement st = *sql <<str;
  //st<<req.endtime()<<req.starttime();
  if (req.has_endtime())
    st<<req.endtime();
  if (req.has_starttime())
    st<<req.starttime();
  if (req.has_id())
    st<<req.id();
  if (req.has_type())
    st<<req.type();
  if (req.has_model())
    st<<req.model();
  if (req.has_devid())
    st<<req.devid();
  if (req.has_event_id())
    st<<req.event_id();
  if (req.has_obj())
    st<<req.obj();
  if (req.has_level())
    st<<req.level();
  if (req.has_is_alive())
    st<<req.is_alive();
  if (req.has_proc_status())
    st<<req.proc_status();
  if (req.has_proc_comment())
    st<<req.proc_comment();

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
      output_u64(output, "id", u);
      output<<',';

      r>>u;
      output_u64(output, "event_id", u);
      output<<',';

      r>>u;
      output_u64(output, "devid", u);
      output<<',';

      r>>s;
      output_string(output, "obj", s);
      output<<',';

      r>>s;
      output_string(output, "type", s);
      output<<',';

      r>>u;
      output_u64(output, "model", u);
      output<<',';

      r>>s;
      output_string(output, "level", s);
      output<<',';

      r>>u;
      output_u64(output, "alarm_peak", u);
      output<<',';

      r>>u;
      output_u64(output, "sub_events", u);
      output<<',';

      r>>u;
      output_u64(output, "alarm_avg", u);
      output<<',';

      r>>s;
      output_string(output, "value_type", s);
      output<<',';

      r>>s;
      output_string(output, "desc", s);
      output<<',';

      r>>u;
      output_u64(output, "duration", u);
      output<<',';

      r>>u;
      output_u64(output, "starttime", u);
      output<<',';

      r>>u;
      output_u64(output, "endtime", u);
      output<<',';

      r>>u;
      output_u64(output, "is_alive", u);
      output<<',';

      r>>s;
      output_string(output, "proc_status", s);
      output<<',';

      r>>s;
      output_string(output, "proc_comment", s);
      output<<"}";
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
  }

  delete sql;
}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  // start db connection
  session* sql = start_db_session();

  string str = "SELECT `id`, `time`, `event_id`, `type`, `model`, `devid`, `level`, `obj`, `thres_value`, `alarm_value`, `value_type`, `desc` "
               "FROM `t_event_data` WHERE ( ";
  //mo::stAddWhere(str,"`time` BETWEEN ? AND ?");
  if (req.has_starttime())
    mo::stAddWhere(str,"`time` >= ?");
  if (req.has_endtime())
    mo::stAddWhere(str,"`time` <= ?");
  if (req.has_id())
    mo::stAddWhere(str,"`id` = ?");
  if (req.has_type())
    mo::stAddWhere(str,"`type` = ?");
  if (req.has_model())
    mo::stAddWhere(str,"`model` = ?");
  if (req.has_devid())
    mo::stAddWhere(str,"`devid` = ?");
  if (req.has_event_id())
    mo::stAddWhere(str,"`event_id` = ?");
  if (req.has_obj())
    mo::stAddWhere(str,"`obj` = ?");
  if (req.has_level())
    mo::stAddWhere(str,"`level` = ?");
  str += " ) ORDER BY time";

  cppdb::statement st = *sql <<str;
  //st<<req.starttime()<<req.endtime();
  if (req.has_starttime())
    st<<req.starttime();
  if (req.has_endtime())
    st<<req.endtime();
  if (req.has_id())
    st<<req.id();
  if (req.has_type())
    st<<req.type();
  if (req.has_model())
    st<<req.model();
  if (req.has_devid())
    st<<req.devid();
  if (req.has_event_id())
    st<<req.event_id();
  if (req.has_obj())
    st<<req.obj();
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
      output_u64(output, "id", u);
      output<<',';

      r>>u;
      if (req.has_step())
        u = u - (u-req.starttime()) % req.step();
      output_u64(output, "time", u);
      output<<',';

      r>>u;
      output_u64(output, "event_id", u);
      output<<',';

      r>>s;
      output_string(output, "type", s);
      output<<',';

      r>>u;
      output_u64(output, "model", u);
      output<<',';

      r>>u;
      output_u64(output, "devid", u);
      output<<',';

      r>>s;
      output_string(output, "level", s);
      output<<',';

      r>>s;
      output_string(output, "obj", s);
      output<<',';

      r>>u;
      output_u64(output, "thres_value", u);
      output<<',';

      r>>u;
      output_u64(output, "alarm_value", u);
      output<<',';

      r>>s;
      output_string(output, "value_type", s);
      output<<',';

      r>>s;
      output_string(output, "desc", s);
      output<<"}";
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
  }

  delete sql;
}

static void set_proc_status() {
  session* sql = start_db_session();
  cppdb::statement st = *sql <<"UPDATE `t_event_data_aggre` SET `proc_status` = ?, `proc_comment` = ? WHERE `id` = ?"
    <<req.proc_status()<<req.proc_comment()<<req.id();
  try{
    st<<cppdb::exec;
  } catch ( std::exception const &e ){
    log_err("Error when UPDATE `t_event_data_aggre`: %s", e.what());
  }
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);

  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) debug = true;
    if (!ParseWebReqFromUrlParams(cgi, &req)) {
      std::cout << cgicc::HTTPStatusHeader(400, "Invalid Params");
      std::cout<<"Invalid Params: "<<cgi.getEnvironment().getQueryString()<<std::endl;
      log_err("invalid Params: %s", cgi.getEnvironment().getQueryString().c_str());
      return 1;
    }
    std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";
  } else if (!ParseWebReqFromCmdline(argc, argv, &req)) {
    usage(argv[0]);
  }

  try {
    if (req.req_type()==WebReq::ORI)
      process();
    else if (req.req_type()==WebReq::AGGRE)
      process_aggre();
    else if (req.req_type()==WebReq::SET_PROC_STATUS)
      set_proc_status();
  } catch (std::exception const &e) {
    log_err("%s", e.what());
  }
  cout<<"["<<output.str()<<"]"<<endl;

  return 0;
}
