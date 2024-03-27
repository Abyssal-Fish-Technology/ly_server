#include "../common/common.h"
#include "../common/log.h"
#include "../common/event_feature_req.h"
#include "../common/ip.h"
#include "../common/http.h"
#include "../common/_strings.h"
#include "../common/mo.pb.h"
#include "../common/mo_req.h"
#include "define.h"
#include "dbc.h"
#include "boost/regex.hpp"
#include <google/protobuf/text_format.h>
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <algorithm>
#include <map>
#include <iomanip>

#define SPC_CHAR_PATTERN "[^\\x00-\\x7f\\u4E00-\\u9FFF]+"
#define STEP 3600 
#define RESOFFRONT 100

using namespace boost;

const char log_file[] = SERVER_LOG_DIR "/" __FILE__;

using namespace std;
using namespace boost;
using namespace cppdb;
using namespace eventfeature;

static map<u32, string> type_desc;
static bool is_http = false;
static EventFeatureReq req;
static bool debug = false;
static bool first = true;
static string err_str = "abnormal character";

////////////////////////////////////////////////////////////////////////////
// Get agent ip, router ip, and router id
static void GetDevs(
    session& sql,
    vector<string>& agentips,
    vector<string>& devips,
    vector<int>& devids)
{
    string agentip, devip;

    if (!req.has_devid()) {
      sql << "select t2.ip as agentip, t1.ip as devip from t_device t1, t_agent t2 where "
             "t1.agentid=t2.id and t1.id=? and t2.disabled='N' and t1.disabled='N'"
          << req.devid() << cppdb::row >> agentip >> devip;
      if (!agentip.empty() && !devip.empty()) {
        agentips.push_back(agentip);
        devips.push_back(devip);
        devids.push_back(req.devid());
        return;
      }
    }

    result res = sql << "select t2.ip as agentip, t1.ip as devip, t1.id as devid from t_device t1, t_agent t2 "
      " where t1.agentid=t2.id and t2.disabled='N' and t1.disabled='N'";
    while(res.next()) {
      u32 devid;
      res >> agentip >> devip >> devid;
      agentips.push_back(agentip);
      devips.push_back(devip);
      devids.push_back(devid);
    }
}

////////////////////////////////////////////////////////////////////////////
static void inline output_string(stringstream& out, const string& name, const string& value) 
{
  out << '"' << name << "\":\"" << value << '"'; 
}

////////////////////////////////////////////////////////////////////////////
static void inline output_u64(stringstream& out, const string& name, u64 value) 
{
  out << '"' << name << "\":" << value; 
}

////////////////////////////////////////////////////////////////////////////
static void inline output_double(stringstream& out, const string& name, double value) 
{
  out << '"' << name << "\":" << fixed << setprecision(2) << value; 
}

//////////////////////////////////////////////////////////////////////////
static bool filter_spc_char(const string& str) {
  regex pattern(SPC_CHAR_PATTERN, regex::nosubs);
  smatch m;
  return regex_search(str, m, pattern);
}

////////////////////////////////////////////////////////////////////////////
static inline void OutputRecord(const EventFeatureRecord& rec, stringstream& output){
  output_u64(output, "devid", req.devid());
  output << ",";
  if (rec.has_time()) {
    output_u64(output, "time",  rec.time());
    output << ",";
  }
  if (rec.has_sip()) {
    // output_string(output, "ip", ipnum_to_ipstr(rec.sip()));
    output_string(output, "sip", rec.sip());
    output << ",";
  }
  if (rec.has_dip()) {
    // output_string(output, "ip", ipnum_to_ipstr(rec.dip()));
    output_string(output, "dip", rec.dip());
    output << ",";
  }
  if (rec.has_sport()) {
    output_u64(output, "sport",  rec.sport());
    output << ",";
  }
  if (rec.has_dport()) {
    output_u64(output, "dport",  rec.dport());
    output << ",";
  }
  if (rec.has_protocol()) {
    output_string(output, "protocol",  proto_to_string(rec.protocol()));
    output << ",";
  }
  if (rec.has_type()) {
    output_string(output, "type", type_desc.at(rec.type()));
    output << ",";
  }
  if (rec.has_model()) {
    output_u64(output, "model", rec.model());
    output << ",";
  }
  if (rec.has_icmp_type()) {
    output_u64(output, "icmp_type", rec.icmp_type());
    output << ",";
  }
  if (rec.has_obj()) {
    output_string(output, "obj", rec.obj());
    output << ",";
  }
  if (rec.has_url()) {
    if (filter_spc_char(rec.url())) 
      output_string(output, "url", err_str);
    else
      output_string(output, "url",  escape_back_slash(rec.url()));
    output << ",";
  }
  if (rec.has_domain()) {
    if (filter_spc_char(rec.domain()))
      output_string(output, "domain", err_str);
    else
      output_string(output, "domain",  escape_back_slash(rec.domain()));
    output << ",";
  }
  if (rec.has_qtype()) {
    output_string(output, "qtype",  qtype_to_str(rec.qtype()));
    output << ",";
  }
  if (rec.has_payload()) {
    output_string(output, "payload", escape_back_slash(rec.payload()));
    output << ",";
  }
  if (rec.has_retcode()) {
    output_u64(output, "retcode",  rec.retcode());
    output << ",";
  }
  if (rec.has_captype()) {
    output_string(output, "captype", rec.captype());
    output << ",";
  }
  if (rec.has_capname()) {
    output_string(output, "capname", rec.capname());
    output << ",";
  }
  if (rec.has_capvers()) {
    output_string(output, "capvers", rec.capvers());
    output << ",";
  }
  if (rec.has_capusec()) {
    output_u64(output, "capusec", rec.capusec());
    output << ",";
  }
  if (rec.has_flows()) {
    output_u64(output, "flows", rec.flows());
    output << ",";
  }
  if (rec.has_pkts()) {
    output_u64(output, "pkts", rec.pkts());
    output << ",";
  }
  if (rec.has_bytes()) {
    output_u64(output, "bytes", rec.bytes());
  }
}

//////////////////////////////////////////////////////////////////////////
static void OutputResult(EventFeatureReq* req, vector<EventFeatureRecord>& all, vector<EventFeatureRecord>& l, stringstream& output)
{
  for ( vector<EventFeatureRecord>::iterator i=l.begin(); i!=l.end(); i++)
  {
    const EventFeatureRecord& rec = *i;

    if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

    if (first)
      first = false;
    else
      /*if (rec.has_url()) {
        if (filter_spc_char(rec.url())) continue;
      }
      if (rec.has_host()) {
        if (filter_spc_char(rec.host())) continue;
      }
      if (rec.has_qname()) {
        if (filter_spc_char(rec.qname())) continue;
      }
      output << ",\n";
    }*/
    output << ",\n";

    output << "{";
    OutputRecord(rec, output);
    output << "}";
  }

  for ( vector<EventFeatureRecord>::iterator i=all.begin(); i!=all.end(); i++)
  {
    const EventFeatureRecord& rec = *i;

    if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

    if (first)
      first = false;
    else
      output << ",\n";
    output << "{";
    OutputRecord(rec, output);
    output << "}";
  }

}

//////////////////////////////////////////////////////////////////////
static void ParseDetailOutput(stringstream& oss, vector<EventFeatureRecord>& all, vector<EventFeatureRecord>& l)
{
  EventFeatureResponse res;
  res.ParseFromIstream(&oss);
  vector<EventFeatureRecord> recs;
  EventFeatureRecord all_rec;
  all_rec.set_devid(req.devid());
  all_rec.set_time(req.starttime());
 
  if (res.records_size() == 0) return;

  int limit = req.limit() == 0 ? res.records_size() : req.limit();
  for (int i = 0;i < res.records_size();i++) {
    auto rec = res.records(i);
    if (i < limit)
      l.push_back(rec);

    all_rec.set_flows(all_rec.flows() + rec.flows());
    all_rec.set_pkts(all_rec.pkts() + rec.pkts());
    all_rec.set_bytes(all_rec.bytes() + rec.bytes());
  }
  all.push_back(all_rec);     //汇总
}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  vector<EventFeatureRecord> all, l;
  if (is_http) std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";
  // start db connection
  session* sql = start_db_session();

  //get event type desc
  result res = *sql<<"SELECT `id`, `desc` FROM `t_event_type`";
  while(res.next()) {
    u32 id;
    res >> id;
    res >> type_desc[id];
  }

  // Get agent ip and router ip
  vector<string> agentips;
  vector<string> devips;
  vector<int> devids;
  GetDevs(*sql, agentips, devips, devids);

  stringstream sout;
  sout << "[" << endl;
  bool has_devid = req.has_devid();
  for (u32 i=0; i < agentips.size(); ++i) {
    string agentip, devip;
    u32 devid;
    agentip = agentips[i];
    devip = devips[i];
    devid = devids[i];
    if (has_devid && req.devid() != devid) continue;

    req.set_devid(devid);
    // req.set_router_ip(devip);

    string url = "http://"  + agentip + ":10081/extract_event_feature";
    if (debug) { url += "?dbg=1"; }

    string content;
    if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
      log_err("Unable to convert EventFeatureReq to Text for posting.\n");
      continue;
    }
    if (debug) log_info("agentip:%s, devid:%d, devip:%s, req:%s\n", agentip.c_str(), devid, devip.c_str(), content.c_str());
    stringstream oss;
    http_post(url, content, &oss);
    ParseDetailOutput(oss, all, l);
    OutputResult(&req, all, l, sout);
  }
  sout << endl << "]" << endl;
  cout << sout.str();
  delete sql;
}

static void usage(char * pn)
{
  fprintf(stderr, "usage: %s [options]\n\n", pn);
  fprintf(stderr, "-d <device id>\t\n");
  fprintf(stderr, "-s <starttime>\tdefault:<latest>\n");
  fprintf(stderr, "-S <starttime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-e <endtime>\tdefault:latest\n");
  fprintf(stderr, "-E <endtime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-t <type>\tdefault:ALL\n");
  fprintf(stderr, "-l <limit>\tdefalut:10\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);

  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) debug = true;
    if (!ParseFeatureReqFromUrlParams(cgi, &req)) {
      std::cout << "HTTP/1.1 400 Invalid Params\r\n\r\n";
      return 0;
    }
  } else if (!ParseFeatureReqFromCmdline(argc, argv, &req)) {
    usage(argv[0]);
  }

  try {
    process();
  } catch (std::exception const &e) {
    log_err("%s\n", e.what());
  }

  return 0;
}
