#include "../common/common.h"
#include "../common/log.h"
#include "../common/topn_req.h"
#include "../common/ip.h"
#include "../common/http.h"
#include "../common/_strings.h"
#include "../common/mo.pb.h"
#include "../common/mo_req.h"
#include "../common/csv.hpp"
#include "../common/policy.pb.h"
#include "../common/policy.hpp"
#include "define.h"
#include "dbc.h"
#include "boost/regex.hpp"
#include <google/protobuf/text_format.h>
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <vector>
#include <map>

#define SPC_CHAR_PATTERN "[^\\x00-\\x7f\\u4E00-\\u9FFF]+"

const char log_file[] = SERVER_LOG_DIR "/" __FILE__;

using namespace std;
using namespace boost;
using namespace cppdb;
using namespace topn;
using namespace policy;

static bool is_http = false;
static TopnReq req;
static bool debug = false;
static bool has_step;
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
static bool filter_spc_char(const string& str) {
  regex pattern(SPC_CHAR_PATTERN, regex::nosubs);
  smatch m;
  return regex_search(str, m, pattern);
}

static inline void OutputRecord(const TopnRecord& rec, stringstream& output){
  output_u64(output, "devid",  rec.devid());
  output << ",";

  if (rec.has_time()) {
    output_u64(output, "time",  rec.time());
    output << ",";
  }
  if (rec.has_type()) {
    output_string(output, "type",  rec.type());
    output << ",";
  }
  if (rec.has_ip()) {
    // output_string(output, "IP", ipnum_to_ipstr(rec.ip()));
    output_string(output, "IP", rec.ip());
    output << ",";
  }
  if (rec.has_sip()) {
    // output_string(output, "SIP", ipnum_to_ipstr(rec.sip()));
    output_string(output, "SIP",rec.sip());
    output << ",";
  }
  if (rec.has_dip()) {
    // output_string(output, "DIP", ipnum_to_ipstr(rec.dip()));
    output_string(output, "DIP",rec.dip());
    output << ",";
  }
  if (rec.has_protocol()) {
    output_string(output, "protocol",  proto_to_string(rec.protocol()));
    output << ",";
  }
  if (rec.has_port()) {
    output_u64(output, "PORT",  rec.port());
    output << ",";
  }
  if (rec.has_sport()) {
    output_u64(output, "SPORT", rec.sport());
    output << ",";
  }
  if (rec.has_dport()) {
    output_u64(output, "DPORT", rec.dport());
    output << ",";
  }
  if (rec.has_flags()) {
    output_u64(output, "flags",  rec.flags());
    output << ",";
  }
  if (rec.has_tos()) {
    output_u64(output, "tos",  rec.tos());
    output << ",";
  }
  if (rec.has_app_proto()) {
    output_string(output, "app_proto", rec.app_proto());
    output << ","; 
  }
  if (rec.has_context()) {
    if (filter_spc_char(rec.context()))
      output_string(output, "context", err_str);
    else
      output_string(output, "context", rec.context());
    output << ",";
  }
  if (rec.has_popular_service()) {
    string popular_service_str = string(rec.popular_service() & 1 ? "src" : "") +
                                 string(rec.popular_service() & 2 ? "dst" : "");
    if (!popular_service_str.empty()) {
      output_string(output, "popular_service", popular_service_str);
      output << ",";
    }
  }
  if (rec.has_service()) {
    string service_str = string(rec.service() & 1 ? "src" : "") +
                         string(rec.service() & 2 ? "dst" : "");
    if (!service_str.empty()) {
      output_string(output, "service", service_str);
      output << ",";
    }
  }
  if (rec.has_scanner()) {
    string scanner_str = string(rec.scanner() & 1 ? "src" : "") + 
                         string(rec.scanner() & 2 ? "dst" : "");
    if (!scanner_str.empty()) {
      output_string(output, "scanner", scanner_str);
      output << ",";
    }
  }
  if (rec.has_whitelist()) {
    string whitelist_str = string(rec.whitelist() & 1 ? "src" : "") +
                           string(rec.whitelist() & 2 ? "dst" : "");
    if (!whitelist_str.empty()) {
      output_string(output, "whitelist", whitelist_str);
      output << ",";
    }
  }
  if (rec.has_blacklist()) {
    string blacklist_str = string(rec.blacklist() & 1 ? "src" : "") +
                           string(rec.blacklist() & 2 ? "dst" : "");
    if (!blacklist_str.empty()) {
      output_string(output, "blacklist", blacklist_str);
      output << ",";
    }
  }
  if (rec.has_moid()) {
    output_u64(output, "moid", rec.moid());
    output << ",";
  }
  if (rec.has_service_type()) {
    output_u64(output, "service_type", rec.service_type());
    output << ",";
  }
  if (rec.has_service_name()) {
    if (filter_spc_char(rec.service_name()))
      output_string(output, "service_name", err_str);
    else
      output_string(output, "service_name", rec.service_name());
    output << ",";
  }
  if (rec.has_service_info1()) {
    if (filter_spc_char(rec.service_info1()))
      output_string(output, "service_info1", err_str);
    else
      output_string(output, "service_info1", rec.service_info1());
    output << ",";
  }
  if (rec.has_service_info2()) {
    if (filter_spc_char(rec.service_info2()))
      output_string(output, "service_info2", err_str);
    else
      output_string(output, "service_info2", rec.service_info2());
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
  output_u64(output, "bytes", rec.bytes());
}

static bool compare_rec_by_bytes_desc(const TopnRecord& a, const TopnRecord& b ){
  return a.bytes() > b.bytes();
}

////////////////////////////////////////////////////////////////////////////
static void OutputResult(TopnReq* req, vector<TopnRecord>& l, vector<TopnRecord>& all, stringstream& output)
{
  for ( vector<TopnRecord>::iterator i=l.begin(); i!=l.end(); i++)
  {
    const TopnRecord& rec = *i;

    if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

    if (first)
      first = false;
    else 
      /*if (rec.has_context()) {
        if (filter_spc_char(rec.context())) continue;
      }
      output << ",\n";
    }*/
    output << ",\n";

    output << "{";
    OutputRecord(rec, output);
    output << "}";
  }

  for ( vector<TopnRecord>::iterator i=all.begin(); i!=all.end(); i++)
  {
    const TopnRecord& rec = *i;

    if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

    if (first)
      first = false;
    else
      output << ",\n";
    output << "{";
    OutputRecord(rec, output);
    output << "}";
  }

  l.clear();
  all.clear();
}

////////////////////////////////////////////////////////////////////////////
static void ParseDetailOutput(TopnReq* req, stringstream& oss, vector<TopnRecord> &l, vector<TopnRecord> &all, u32 devid, string devip)
{
  TopnResponse res;
  string type;
  res.ParseFromIstream(&oss);

  if (debug) {
    log_info("Original response: %d record(s).", res.records_size());
    log_info(res.DebugString().c_str());
    log_info("End of original response.");
  }

#ifndef DISABLE_AGGR

  u32 count = 0;
  u32 limit = req->limit();
  TopnRecord all_rec;

  string sortby = boost::to_upper_copy(req->sortby());
  if ( !has_step && (sortby=="CONV" || sortby=="IP" || sortby=="PORT") ){
    map<string, TopnRecord> aggr;
    // map<u32, TopnRecord> aggr_s, aggr_d;
    map<string, TopnRecord> aggr_s, aggr_d;
    string a="a", b="b", c="c", d="d", e="e";

    all_rec.set_devip(devip);
    all_rec.set_devid(devid);
    all_rec.set_time(req->starttime());
    all_rec.set_type("ALL");

    for (int i=0;i<res.records_size();i++)
    {
      TopnRecord rec = res.records(i);
      rec.set_devid(devid);
      rec.set_devip(devip);

      type = boost::to_upper_copy(rec.type());
      if (type=="ALL"){
        all_rec.set_flows( all_rec.flows() + rec.flows() );
        all_rec.set_pkts( all_rec.pkts() + rec.pkts() );
        all_rec.set_bytes( all_rec.bytes() + rec.bytes() );
      }
      else if ( type=="CONV" )
      {
        // string key = a+to_string(rec.sip())+b+to_string(rec.sport())+c+to_string(rec.protocol())+d+to_string(rec.dip())+e+to_string(rec.dport());
        string key = a+rec.sip()+b+to_string(rec.sport())+c+to_string(rec.protocol())+d+rec.dip()+e+to_string(rec.dport());
        if ( aggr.count(key) ){
          aggr[key].set_flows(aggr[key].flows()+rec.flows());
          aggr[key].set_pkts(aggr[key].pkts()+rec.pkts());
          aggr[key].set_bytes(aggr[key].bytes()+rec.bytes());
        }
        else{
          aggr[key] = rec;
          aggr[key].set_time(req->starttime());
        }
      }
      else if ( sortby=="IP" || sortby=="PORT" ){
        if ( type=="SIP" || type=="SPORT" ){
          // u32 key = rec.sip()+rec.sport();
          string key = rec.sip()+to_string(rec.sport());
          if ( aggr_s.count(key) ){
            aggr_s[key].set_flows(aggr_s[key].flows()+rec.flows());
            aggr_s[key].set_pkts(aggr_s[key].pkts()+rec.pkts());
            aggr_s[key].set_bytes(aggr_s[key].bytes()+rec.bytes());
          }
          else{
            aggr_s[key] = rec;
            aggr_s[key].set_time(req->starttime());
          }
        }
        else{
          // u32 key = rec.dip()+rec.dport();
          string key = rec.dip()+to_string(rec.dport());
          if ( aggr_d.count(key) ){
            aggr_d[key].set_flows(aggr_d[key].flows()+rec.flows());
            aggr_d[key].set_pkts(aggr_d[key].pkts()+rec.pkts());
            aggr_d[key].set_bytes(aggr_d[key].bytes()+rec.bytes());
          }
          else{
            aggr_d[key] = rec;
            aggr_d[key].set_time(req->starttime());
          }
        }
      }
    }

    vector<TopnRecord> recs;

    for ( map<string, TopnRecord>::iterator it=aggr.begin(); it!=aggr.end(); ++it)
      recs.push_back(it->second);
    sort(recs.begin(),recs.end(),compare_rec_by_bytes_desc);
    for (u32 i=0; i<recs.size();i++, count++){
      if (count==limit && limit>0)
        break;
      l.push_back(recs[i]);
    }
    recs.clear();
    count=0;

    // for ( map<u32, TopnRecord>::iterator it=aggr_s.begin(); it!=aggr_s.end(); ++it)
    for ( map<string, TopnRecord>::iterator it=aggr_s.begin(); it!=aggr_s.end(); ++it)
      recs.push_back(it->second);
    sort(recs.begin(),recs.end(),compare_rec_by_bytes_desc);
    for (u32 i=0; i<recs.size();i++, count++){
      if (count==limit && limit>0)
        break;
      l.push_back(recs[i]);
    }
    recs.clear();
    count=0;

    // for ( map<u32, TopnRecord>::iterator it=aggr_d.begin(); it!=aggr_d.end(); ++it)
    for ( map<string, TopnRecord>::iterator it=aggr_d.begin(); it!=aggr_d.end(); ++it)
      recs.push_back(it->second);
    sort(recs.begin(),recs.end(),compare_rec_by_bytes_desc);
    for (u32 i=0; i<recs.size();i++, count++){
      if (count==limit && limit>0)
        break;
      l.push_back(recs[i]);
    }
    recs.clear();
    count=0;

    all.push_back(all_rec);

  }
  else{

#endif

    for (int i=0;i<res.records_size();i++)
    {
      TopnRecord rec = res.records(i);
      rec.set_devid(devid);
      rec.set_devip(devip);

      type = boost::to_upper_copy(rec.type());
      if (type=="ALL")
        all.push_back(rec);
      else
        l.push_back(rec);
    }

#ifndef DISABLE_AGGR
  }
#endif
  
}

string parse_include_exclude_params(cppdb::session* sql, TopnReq& req, string list){
  string s;
  vector<string> vec, res;
  vector<u32> mo_x;

  csv::fill_vector_from_line(vec, list);  // get vector of params

  for (vector<std::string>::iterator it = vec.begin(); it!=vec.end(); it++){
    PolicyName pn = get_policy_name(*it);  // get 'enum PolicyName' for each param
    switch (pn) {
      case MO: {  // if 'mo' specified, get 'mo_x' from database and replace 'mo' with them
        if (mo_x.size()==0) {
          mo_x = mo::getMoIDs(sql, req.groupid(), req.devid());
          for (vector<u32>::iterator it = mo_x.begin(); it!=mo_x.end(); it++) {
            res.push_back("mo_" + to_string(*it));
          }
        }
        break;
      }
      default: res.push_back(*it);break;
    }
  }

  // generate new params from res
  for (vector<string>::iterator it = res.begin(); it!=res.end(); it++){
    if (s.size()>0) {
      s += ",";
      s += *it;
    }
    else
      s = *it;
  }

  return s;
}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  vector<TopnRecord> l, all;

  if (is_http) std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";
  // start db connection
  session* sql = start_db_session();
    
  ComposeReqFilter(&req);

  // Removed by DV @ 20170115
  // std::string filter = req.filter();
  // if (req.has_objid())
  // {
  //   std::string objfilter;
  //   *sql << "select filter from t_monobj where id=?"
  //        << req.objid() << row >> objfilter;
  //   filter += " and (" + objfilter + ")";
  //   req.clear_objid();
  // }
  // req.set_filter(filter);

  has_step = req.has_step();
  if (!has_step)
    req.set_step(300);

  // Get agent ip and router ip
  vector<string> agentips;
  vector<string> devips;
  vector<int> devids;
  GetDevs(*sql, agentips, devips, devids);

  /*if ( (req.has_groupid()||req.mo_only()||req.exclude_mo()) && !req.has_moid() ) {
    std::vector<u32> ids = mo::getMoIDs(sql, req.groupid(), req.devid());
    ostringstream moids;

    if (!ids.empty()){
      moids << ids[0];
      for (u32 k=1;k<ids.size();k++)
        moids << "," << ids[k];
      req.set_moid(moids.str());
    }
  }
  else if (req.has_moid())
    req.set_moid(mo::filterMoIDsWithDevid(sql, req.moid(), req.devid()));

  if ( req.has_include() )
    req.set_include(parse_include_exclude_params(sql, req, req.include()));
  if ( req.has_exclude() )
    req.set_exclude(parse_include_exclude_params(sql, req, req.exclude()));*/

  stringstream sout;
  //if (req.has_jsonp()) sout << req.jsonp() << "(";
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

    string url = "http://"  + agentip + ":10081/flow_scan";
    if (debug) { url += "?dbg=1"; }

    string content;
    if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
      log_err("Unable to convert TopnReq to Text for posting.\n");
      continue;
    }
    if (debug) log_info("agentip:%s, devid:%d, req:%s\n", agentip.c_str(), devid, content.c_str());
    stringstream oss;
    http_post(url, content, &oss);
    ParseDetailOutput(&req, oss, l, all, devid, devip);
    OutputResult(&req, l, all, sout);
  }
  //sout << endl << "]" << (req.has_jsonp()? ");" : "" ) << endl;
  sout << endl << "]" << endl;
  cout << sout.str();
  delete sql;
}

////////////////////////////////////////////////////////////////////////////
static void usage(char * pn)
{
  fprintf(stderr, "usage: %s [options]\n\n", pn);
  fprintf(stderr, "-i <device id>\t\n");
  fprintf(stderr, "-s <starttime>\tdefault:<latest>\n");
  fprintf(stderr, "-S <starttime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-e <endtime>\tdefault:latest\n");
  fprintf(stderr, "-E <endtime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-f <filter>\tdefault:any\n");
  fprintf(stderr, "-t <type>\tdefault:ALL\n");
  fprintf(stderr, "-b <step>\tdefault:<NULL>\n");
  fprintf(stderr, "-d <srcdst>\tdefault:''\n");
  fprintf(stderr, "-n <limit>\tdefalut:10\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);

  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) debug = true;
    if (!ParseTopnReqFromUrlParams(cgi, &req)) {
      std::cout << "HTTP/1.1 400 Invalid Params\r\n\r\n";
      return 0;
    }
  } else if (!ParseTopnReqFromCmdline(argc, argv, &req)) {
    usage(argv[0]);
  }

  try {
    process();
  } catch (std::exception const &e) {
    log_err("%s\n", e.what());
  }

  return 0;
}
