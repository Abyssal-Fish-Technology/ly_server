#include "../common/common.h"
#include "../common/log.h"
#include "../common/feature_req.h"
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
using namespace feature;

static bool is_http = false;
static FeatureReq req;
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

///////////////////////////////////////////////////////////////////////////
static bool compare_rec_by_bytes_desc(const FeatureRecord& a, const FeatureRecord& b ){
  return a.bytes() > b.bytes();
}

static bool compare_rec_by_packets_desc(const FeatureRecord& a, const FeatureRecord& b ){
  return a.pkts() > b.pkts();
}

static bool compare_rec_by_peers_desc(const FeatureRecord& a, const FeatureRecord& b ){
  return a.peers() > b.peers();
}

static bool compare_rec_by_flows_desc(const FeatureRecord& a, const FeatureRecord& b ){
  return a.flows() > b.flows();
}

//////////////////////////////////////////////////////////////////////////
static bool filter_spc_char(const string& str) {
  regex pattern(SPC_CHAR_PATTERN, regex::nosubs);
  smatch m;
  return regex_search(str, m, pattern);
}

////////////////////////////////////////////////////////////////////////////
static inline void OutputRecord(const FeatureRecord& rec, stringstream& output){
  output_u64(output, "devid", req.devid());
  output << ",";
  if (rec.has_time()) {
    output_u64(output, "time",  rec.time());
    output << ",";
  }
  if (rec.has_duration()) {
    output_u64(output, "duration",  rec.duration());
    output << ",";
  }
  if (rec.has_moid()) {
    output_u64(output, "moid", rec.moid());
    output << ",";
  }
  if (rec.has_ip()) {
    // output_string(output, "ip", ipnum_to_ipstr(rec.ip()));
    output_string(output, "ip", rec.ip());
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
  if (rec.has_peers()) {
    output_u64(output, "peers",  rec.peers());
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
  if (rec.has_port()) {
    output_u64(output, "port",  rec.port());
    output << ",";
  }
  if (rec.has_protocol()) {
    output_string(output, "protocol",  proto_to_string(rec.protocol()));
    output << ",";
  }
  if (rec.has_type()) {
    output_string(output, "type", rec.type());
    output << ",";
  }
  if (rec.has_bwclass()) {
    output_string(output, "bwclass",  rec.bwclass());
    output << ",";
  }
  if (rec.has_ti_mark()) {
    output_string(output, "ti_mark",  rec.ti_mark());
    output << ",";
  }
  if (rec.has_srv_mark()) {
    output_string(output, "srv_mark",  rec.srv_mark());
    output << ",";
  }
  if (rec.has_app_proto()) {
    output_string(output, "app_proto",  rec.app_proto());
    output << ",";
  }
  if (rec.has_srv_name()) {
    output_string(output, "srv_name",  rec.srv_name());
    output << ",";
  }
  if (rec.has_srv_version()) {
    output_string(output, "srv_version",  rec.srv_version());
    output << ",";
  }
  if (rec.has_srv_type()) {
    output_string(output, "srv_type",  rec.srv_type());
    output << ",";
  }
  if (rec.has_dev_type()) {
    output_string(output, "dev_type",  rec.dev_type());
    output << ",";
  }
  if (rec.has_dev_name()) {
    output_string(output, "dev_name",  rec.dev_name());
    output << ",";
  }
  if (rec.has_dev_vendor()) {
    output_string(output, "dev_vendor",  rec.dev_vendor());
    output << ",";
  }
  if (rec.has_dev_model()) {
    output_string(output, "dev_model",  rec.dev_model());
    output << ",";
  }
  if (rec.has_os_type()) {
    output_string(output, "os_type",  rec.os_type());
    output << ",";
  }
  if (rec.has_os_name()) {
    output_string(output, "os_name",  rec.os_name());
    output << ",";
  }
  if (rec.has_os_version()) {
    output_string(output, "os_version",  rec.os_version());
    output << ",";
  }
  if (rec.has_midware_type()) {
    output_string(output, "midware_type",  rec.midware_type());
    output << ",";
  }
  if (rec.has_midware_name()) {
    output_string(output, "midware_name",  rec.midware_name());
    output << ",";
  }
  if (rec.has_midware_version()) {
    output_string(output, "midware_version",  rec.midware_version());
    output << ",";
  }
  if (rec.has_threat_type()) {
    output_string(output, "threat_type",  rec.threat_type());
    output << ",";
  }
  if (rec.has_threat_name()) {
    output_string(output, "threat_name",  rec.threat_name());
    output << ",";
  }
  if (rec.has_threat_version()) {
    output_string(output, "os_version",  rec.os_version());
    output << ",";
  }
  if (rec.has_url()) {
    if (filter_spc_char(rec.url())) 
      output_string(output, "url", err_str);
    else
      output_string(output, "url",  escape_back_slash(rec.url()));
    output << ",";
  }
  if (rec.has_host()) {
    if (filter_spc_char(rec.host()))
      output_string(output, "host", err_str);
    else
      output_string(output, "host",  escape_back_slash(rec.host()));
    output << ",";
  }
  if (rec.has_qname()) {
    if (filter_spc_char(rec.qname()))
      output_string(output, "qname", err_str);
    else
      output_string(output, "qname",  escape_back_slash(rec.qname()));
    output << ",";
  }
  if (rec.has_fqname()) {
    if (filter_spc_char(rec.fqname()))
      output_string(output, "fqname", err_str);
    else
      output_string(output, "fqname",  escape_back_slash(rec.fqname()));
    output << ",";
  }
  if (rec.has_qtype()) {
    output_string(output, "qtype",  qtype_to_str(rec.qtype()));
    output << ",";
  }
  if (rec.has_fratio()) {
    output_double(output, "fratio",  rec.fratio());
    output << ",";
  }
  if (rec.has_score()) {
    output_u64(output, "score",  rec.score());
    output << ",";
  }
  if (rec.has_retcode()) {
    output_u64(output, "retcode",  rec.retcode());
    output << ",";
  }
  if (rec.has_peak_flows()) {
    output_u64(output, "peak_flows", rec.peak_flows());
    output << ",";
  }
  if (rec.has_peak_pkts()) {
    output_u64(output, "peak_pkts", rec.peak_pkts());
    output << ",";
  }
  if (rec.has_peak_bytes()) {
    output_u64(output, "peak_bytes", rec.peak_bytes());
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
static void OutputResult(FeatureReq* req, vector<FeatureRecord>& all, vector<FeatureRecord>& l, stringstream& output)
{
  for ( vector<FeatureRecord>::iterator i=l.begin(); i!=l.end(); i++)
  {
    const FeatureRecord& rec = *i;

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

  for ( vector<FeatureRecord>::iterator i=all.begin(); i!=all.end(); i++)
  {
    const FeatureRecord& rec = *i;

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
static void ParseDetailOutput(stringstream& oss, vector<FeatureRecord>& all, vector<FeatureRecord>& l)
{
  FeatureResponse res;
  res.ParseFromIstream(&oss);
  u32 limit = req.limit();
  u32 count = 0;
  vector<FeatureRecord> recs;
  map<int, vector<FeatureRecord>> h_map;  
  FeatureRecord all_rec;
  all_rec.set_devid(req.devid());
  all_rec.set_time(req.starttime());
 
  if (res.records_size() == 0)
    return;
  for (int i = 0;i < res.records_size();i++) {
    auto rec = res.records(i);

    recs.push_back(rec);
    h_map[(rec.time() - req.starttime()) / STEP].push_back(rec);
    all_rec.set_flows(all_rec.flows() + rec.flows());
    all_rec.set_pkts(all_rec.pkts() + rec.pkts());
    all_rec.set_bytes(all_rec.bytes() + rec.bytes());
  }
  all.push_back(all_rec);     //汇总
  /*if (req.orderby() == FeatureReq::BYTES) sort(recs.begin(), recs.end(), compare_rec_by_bytes_desc);
  if (req.orderby() == FeatureReq::PACKETS) sort(recs.begin(), recs.end(), compare_rec_by_packets_desc);
  if (req.orderby() == FeatureReq::PEERS) sort(recs.begin(), recs.end(), compare_rec_by_peers_desc);
  if (req.orderby() == FeatureReq::FLOWS) sort(recs.begin(), recs.end(), compare_rec_by_flows_desc);
  if (limit > 0) {
      for (u32 j = 0;j < recs.size();j++, count++) {
        if (limit == count && limit > 0)
          break;
        l.push_back(recs[j]);
      }
   } else
      for (u32 j = 0;j < recs.size();j++)
        l.push_back(recs[j]);*/

  auto interval = req.endtime() - req.starttime();
  vector<FeatureRecord> aggr;
  for (u32 i = 0; i< interval / STEP + 1; i++) {
    if (req.orderby() == FeatureReq::BYTES) sort(h_map[i].begin(), h_map[i].end(), compare_rec_by_bytes_desc);
    if (req.orderby() == FeatureReq::PACKETS) sort(h_map[i].begin(), h_map[i].end(), compare_rec_by_packets_desc);
    if (req.orderby() == FeatureReq::PEERS) sort(h_map[i].begin(), h_map[i].end(), compare_rec_by_peers_desc);
    if (req.orderby() == FeatureReq::FLOWS) sort(h_map[i].begin(), h_map[i].end(), compare_rec_by_flows_desc);
    for (u32 j = 0;j < h_map[i].size();j++, count++) {
      if (RESOFFRONT == count)
        break;
      aggr.push_back(h_map[i].at(j));
    }
    count = 0;
  }

  count = 0; 
  if (req.orderby() == FeatureReq::BYTES) sort(aggr.begin(), aggr.end(), compare_rec_by_bytes_desc);
  if (req.orderby() == FeatureReq::PACKETS) sort(aggr.begin(), aggr.end(), compare_rec_by_packets_desc);
  if (req.orderby() == FeatureReq::PEERS) sort(aggr.begin(), aggr.end(), compare_rec_by_peers_desc);
  if (req.orderby() == FeatureReq::FLOWS) sort(aggr.begin(), aggr.end(), compare_rec_by_flows_desc);
  
  if (limit > 0) {
    for (u32 i = 0;i < aggr.size();i++, count++) {
      if (limit == count)
        break;
      l.push_back(aggr[i]);
    }
  } else {
      l = recs;
  } 

}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  vector<FeatureRecord> all, l;
  if (is_http) std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";
  // start db connection
  session* sql = start_db_session();

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

    string url = "http://"  + agentip + ":10081/extract_feature";
    if (debug) { url += "?dbg=1"; }

    string content;
    if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
      log_err("Unable to convert FeatureReq to Text for posting.\n");
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
