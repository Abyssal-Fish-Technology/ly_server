#include "../common/common.h"
#include "../common/log.h"
#include "../common/evidence_req.h"
#include "../common/ip.h"
#include "../common/http.h"
#include "../common/strings.h"
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
using namespace evidence;

static bool is_http = false;
static EvidenceReq req;
static bool debug = false;
// static bool first = true;
static string err_str = "abnormal character";

////////////////////////////////////////////////////////////////////////////
// Get agent ip, router ip, and router id
static void GetDevs( session& sql, vector<string>& agentips, vector<string>& devips, vector<int>& devids)
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
// static bool filter_spc_char(const string& str) {
//   regex pattern(SPC_CHAR_PATTERN, regex::nosubs);
//   smatch m;
//   return regex_search(str, m, pattern);
// }


////////////////////////////////////////////////////////////////////////////
static inline void OutputRecord(const EvidenceRecord& rec, stringstream& output){
  output_u64(output, "devid", req.devid());
  if (rec.has_time_sec()) {
    output << ",";
    output_u64(output, "time_sec",  rec.time_sec());
  }
  if (rec.has_time_usec()) {
    output << ",";
    output_u64(output, "time_usec",  rec.time_usec());
  }
  if (rec.has_ip()) {
    output << ",";
    // output_string(output, "ip", ipnum_to_ipstr(rec.ip()));
    output_string(output, "ip", rec.ip());
  }
  if (rec.has_port()) {
    output << ",";
    output_u64(output, "port",  rec.port());
  }
  if (rec.has_caplen()) {
    output << ",";
    output_u64(output, "caplen",  rec.caplen());
  }
  if (rec.has_pktlen()) {
    output << ",";
    output_u64(output, "pktlen",  rec.pktlen());
  }
  if (rec.has_smac()) {
    output << ",";
    // output_string(output, "smac", mac_to_str(rec.smac()));
    output_string(output, "smac", rec.smac());
  }
  if (rec.has_dmac()) {
    output << ",";
    // output_string(output, "dmac", mac_to_str(rec.dmac()));
    output_string(output, "dmac", rec.dmac());
  }
  if (rec.has_sip()) {
    output << ",";
    // output_string(output, "sip", ipnum_to_ipstr(rec.sip()));
    output_string(output, "sip", rec.sip());
  }
  if (rec.has_sport()) {
    output << ",";
    output_u64(output, "sport",  rec.sport());
  }
  if (rec.has_dip()) {
    output << ",";
    // output_string(output, "dip", ipnum_to_ipstr(rec.dip()));
    output_string(output, "dip", rec.dip());
  }
  if (rec.has_dport()) {
    output << ",";
    output_u64(output, "dport",  rec.dport());
  }
  if (rec.has_protocol()) {
    output << ",";
    output_string(output, "protocol",  proto_to_string(rec.protocol()));
  }

  if (rec.has_payload()) {
    output << ",";
    output_string(output, "payload",  rec.payload());
  }


  if (rec.has_pkthdr()) {
    output << ",";
    output_string(output, "pkthdr",  rec.pkthdr());
    // output_string(output, "pkthdr",  rec.pkthdr());
  }

  if (rec.has_packet()) {
    output << ",";
    output_string(output, "packet",  rec.packet());
    // output_string(output, "packet",  rec.packet());
  }

  // if (rec.has_url()) {
  //   output << ",";
  //   if (filter_spc_char(rec.url())) 
  //     output_string(output, "url", err_str);
  //   else
  //     output_string(output, "url",  escape_back_slash(rec.url()));
  // }
  // if (rec.has_host()) {
  //   output << ",";
  //   if (filter_spc_char(rec.host()))
  //     output_string(output, "host", err_str);
  //   else
  //     output_string(output, "host",  escape_back_slash(rec.host()));
  // }
  // if (rec.has_qname()) {
  //   output << ",";
  //   if (filter_spc_char(rec.qname()))
  //     output_string(output, "qname", err_str);
  //   else
  //     output_string(output, "qname",  escape_back_slash(rec.qname()));
  // }
  // if (rec.has_fqname()) {
  //   output << ",";
  //   if (filter_spc_char(rec.fqname()))
  //     output_string(output, "fqname", err_str);
  //   else
  //     output_string(output, "fqname",  escape_back_slash(rec.fqname()));
  // }
  // if (rec.has_qtype()) {
  //   output << ",";
  //   output_string(output, "qtype",  qtype_to_str(rec.qtype()));
  // }
}

//////////////////////////////////////////////////////////////////////////
// static void OutputResult(EvidenceReq* req, vector<EvidenceRecord>& all, stringstream& output){
//   for ( vector<EvidenceRecord>::iterator i=all.begin(); i!=all.end(); i++)
//   {
//     const EvidenceRecord& rec = *i;

//     if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

//     if (first)
//       first = false;
//     else
//       output << ",\n";
//     output << "{";
//     OutputRecord(rec, output);
//     output << "}";
//   }
// }

//////////////////////////////////////////////////////////////////////
static void ParseDetailOutput(stringstream& oss, stringstream& output){
  EvidenceResponse res;
  res.ParseFromIstream(&oss);

  if (res.records_size() == 0) return;
  EvidenceRecord rec;
  rec = res.records(0);
  rec.set_devid(req.devid());
 
  if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

  // cout << rec.DebugString().c_str();

  output << "{";
  OutputRecord(rec, output);
  output << "}";
}

////////////////////////////////////////////////////////////////////////////
static void process(){
  vector<EvidenceRecord> all;
  if (is_http) std::cout << "Content-Type: application/json; charset=UTF-8\r\n\r\n";
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

    string url = "http://"  + agentip + ":10081/extract_pcap";
    if (debug) { url += "?dbg=1"; }

    string content;
    if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
      log_err("Unable to convert EvidenceReq to Text for posting.\n");
      continue;
    }
    if (debug) log_info("agentip:%s, devid:%d, devip:%s, req:%s\n", agentip.c_str(), devid, devip.c_str(), content.c_str());
    stringstream oss;
    http_post(url, content, &oss);
    // cout << oss.str();
    ParseDetailOutput(oss, sout);
    // OutputResult(&req, all, sout);
  }
  sout << endl << "]" << endl;
  cout << sout.str();
  delete sql;
}

////////////////////////////////////////////////////////////////////////////
static void download(){
  // vector<EvidenceRecord> all;

  // start db connection
  session* sql = start_db_session();

  // Get agent ip and router ip
  vector<string> agentips;
  vector<string> devips;
  vector<int> devids;
  GetDevs(*sql, agentips, devips, devids);

  stringstream sout;
  bool has_devid = req.has_devid();
  if (!has_devid){
    log_err("Unable to locate device.\n");
    return;
  }

  for (u32 i=0; i < agentips.size(); ++i) {
    string agentip, devip;
    u32 devid;
    agentip = agentips[i];
    devip = devips[i];
    devid = devids[i];
    if (has_devid && req.devid() != devid) continue;

    req.set_devid(devid);
    // req.set_router_ip(devip);

    string url = "http://"  + agentip + ":10081/extract_pcap";
    if (debug) { url += "?dbg=1"; }

    string content;
    if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
      log_err("Unable to convert EvidenceReq to Text for posting.\n");
      continue;
    }
    if (debug) log_info("agentip:%s, devid:%d, devip:%s, req:%s\n", agentip.c_str(), devid, devip.c_str(), content.c_str());
    stringstream oss;
    http_post(url, content, &oss);
    if (is_http){
      std::cout << "Content-Type: application/octet-stream;\r\n";
      std::cout << "Content-Disposition: attachment;filename=evidence.pcap\r\n\r\n";
    }
    cout << oss.str();
    // ParseDetailOutput(oss, sout);
    // OutputResult(&req, all, sout);
  }

  // cout << sout.str();
  delete sql;
}

static void usage(char * pn){
  fprintf(stderr, "usage: %s [options]\n\n", pn);
  fprintf(stderr, "-d <device id>\t\n");
  fprintf(stderr, "-t <time_sec>\t\n");
  fprintf(stderr, "-T <time_usec>\tFormat:YYYYmmddHHMM\n");
  fprintf(stderr, "-a <ip>\t\n");
  fprintf(stderr, "-p <port>\t\n");

  exit(1);
}

int main(int argc, char *argv[]){
  setvbuf(stdout, NULL, _IOFBF, 81920);

  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) debug = true;
    if (!ParseEvidenceReqFromUrlParams(cgi, &req)) {
      std::cout << "Content-Type: application/json; charset=UTF-8\r\n\r\nInvalid Params.\r\n";
      return 0;
    }
  } else if (!ParseEvidenceReqFromCmdline(argc, argv, &req)) {
    usage(argv[0]);
  }

  try {
    if (req.has_download() && req.download()==true ) {
      download();
    } else {
      process();
    }
  } catch (std::exception const &e) {
    log_err("%s\n", e.what());
  }

  return 0;
}
