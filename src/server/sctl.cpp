#include <google/protobuf/text_format.h>
#include <iostream>
#include <Cgicc.h>
#include <unistd.h>
#include <sys/types.h>
#include <cppdb/frontend.h>
#include <boost/algorithm/string.hpp>
#include <cgicc/HTTPContentHeader.h>
#include <algorithm>
#include <string>
#include "../common/log.h"
#include "../common/csv.hpp"
#include "../common/http.h"
#include "../common/ctl_req.h"
#include "../common/ctl.pb.h"
#include "define.h"
#include "dbc.h"

using namespace std;
using namespace boost;
using namespace cgicc;
using namespace ctl;
using namespace cppdb;

static bool is_http = false;
static bool debug = false;
static bool first = true;
static CtlReq req;

static void inline output_string(stringstream& out, const string& name, const string& value)
{
  out << '"' << name << "\":\"" << value << '"';
}

static void inline output_u64(stringstream& out, const string& name, u64 value)
{
  out << '"' << name << "\":" << value;
}

static inline void OutputRecord(const CtlRecord& rec, stringstream& output) {
  if (rec.has_node()) {
    output_string(output, "nodetype", rec.node());
    output << ",";
  }
  if (rec.has_srv()) {
    output_string(output, "servicetype", rec.srv());
    output << ",";
  }
  if (rec.has_op()) {
    output_string(output, "op", rec.op());
    output << ",";
  }


  if (rec.has_id()) {
    output_u64(output, "id", rec.id());
    output << ",";
  }
  if (rec.has_name()) {
    output_string(output, "name", rec.name());
    output << ",";
  }
  if (rec.has_ip()) {
    output_string(output, "ip", rec.ip());
    output << ",";
  }
  if (rec.has_relate_server()) {
    output_u64(output, "relate-server", rec.relate_server());
    output << ",";
  }
  if (rec.has_relate_agent()) {
    output_u64(output, "relate-agent", rec.relate_agent());
    output << ",";
  }



  if (rec.has_agentid()) {
    output_u64(output, "agentid", rec.agentid());
    output << ",";
  }
  if (rec.has_devid()) {
    output_u64(output, "devid", rec.devid());
    output << ",";
  }
  if (rec.has_status()) {
    output_string(output, "status", rec.status());
    output << ",";
  }
  if (rec.has_result()) {
    output_string(output, "result", rec.result());
    output << ",";
  }
  if (rec.has_desc()) {
    output_string(output, "desc", rec.desc());
  } else {
    output_string(output, "desc", " ");
  }
}


static void OutputResult(stringstream& oss, stringstream& output) {
  CtlResponse rsp;
  rsp.ParseFromIstream(&oss);
  for (int i = 0;i < rsp.records_size();i++) {
    auto rec = rsp.records(i);
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

static void GetServerNodeInfo(CtlResponse& rsp) {

    CtlRecord rec;
    rec.set_node("server");
    rec.set_id(1);
    rec.set_name("管理节点");
    rec.set_ip("localhost");
    rec.set_status("active");

    auto new_rec = rsp.add_records();
    *new_rec = rec;
}

static void GetAgentNodeInfo(session& sql, CtlResponse& rsp) {
  string sql_str = "select `id`, `name`, `ip`, `disabled` from t_agent";
  try {
    cppdb:: result res = sql << sql_str;
    while (res.next()) {
      u32 id;
      string name, ip, disabled;
      res >> id >> name >> ip >> disabled;

      CtlRecord rec;
      rec.set_node("agent");
      rec.set_id(id);
      rec.set_name(name);
      rec.set_ip(ip);
      string status;
      if(disabled == "N") status = "active"; else status = "inactive";
      rec.set_status(status);
      rec.set_relate_server(1);

      auto new_rec = rsp.add_records();
      *new_rec = rec;
    }
  } catch (std::exception const &e) {
    log_err("Error when get agentip: %s", e.what()); 
  }
}

static void GetProbeNodeInfo(session& sql, CtlResponse& rsp) {
  string sql_str = "select `id`, `name`, `ip`, `disabled`, `agentid` from t_device";
  try {
    cppdb:: result res = sql << sql_str;
    while (res.next()) {
      u32 id, agentid;
      string name, ip, disabled;
      res >> id >> name >> ip >> disabled >> agentid;

      CtlRecord rec;
      rec.set_node("probe");
      rec.set_id(id);
      rec.set_name(name);
      rec.set_ip(ip);
      string status = disabled == "N" ? "active" : "inactive";
      rec.set_status(status);
      rec.set_relate_agent(agentid);

      auto new_rec = rsp.add_records();
      *new_rec = rec;
    }
  } catch (std::exception const &e) {
    log_err("Error when get agentip: %s", e.what()); 
  }
}

static void DealControl(const string& type, const u32 agentid, CtlResponse& rsp) {
  FILE* fp = NULL;
  char line[LINE_MAX];
  CtlRecord rec;
  rec.set_id(agentid);
  string cmd;
  string op = GetReqOpStr(&req);
  rec.set_node("server");
  rec.set_srv(type);
  rec.set_op(op);
  switch (req.op()) {
    case CtlReq::START:
    case CtlReq::RESTART: {
      cmd = "systemctl " + op + " " + type + "d";
      system(cmd.c_str());
      cmd = "systemctl status " + type + "d";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line)-1, fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          rec.set_status("active");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          rec.set_status("inactive");
          rec.set_result("failed");
          rec.set_desc("");
          break;
        }
      }
      pclose(fp);
    } break;
    case CtlReq::STOP: {
      cmd = "systemctl stop "  + type + "d";
      system(cmd.c_str());
      cmd = "systemctl status " + type + "d";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line)-1, fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          rec.set_status("active");
          rec.set_result("failed");
          rec.set_desc("");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          rec.set_status("inactive");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        }
      }
      pclose(fp);
    } break;
    case CtlReq::STATUS: {
      cmd = "systemctl status " + type + "d";
      fp = popen(cmd.c_str(), "r");
      while(fgets(line, sizeof(line)-1, fp)) {
        string str = line;
        if (str.find("Active: active (running)") != string::npos) {
          rec.set_status("active");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        } else if (str.find("Active: inactive (dead)") != string::npos) {
          rec.set_status("inactive");
          rec.set_result("succeed");
          rec.set_desc("");
          break;
        }
      }
      pclose(fp);
    } break;
    default:
      break;
  }

  auto new_rec = rsp.add_records();
  *new_rec = rec;
}

static void ProcessDisk(const u32 agentid, CtlResponse& rsp) {
  string cmd = "df -h";
  FILE* fp = popen(cmd.c_str(), "r");
  char line[LINE_MAX];
  map<string, int> disk_rec;
  fgets(line, sizeof(line), fp);
  while(fgets(line, sizeof(line), fp)) {
    vector<string> vec;
    string str = line;
    size_t pos = str.find(" ");
    while (pos != string::npos) {
      vec.push_back(str.substr(0, pos));
      string str_right = str.substr(pos + 1);
      str = trim(str_right);
      pos = str.find(" ");
    }
    vec.push_back(str);
    string percent = vec[4].substr(0, vec[4].size()-1);
    string disk = vec[5].substr(0, vec[5].size());
    disk_rec[disk] = atoi(percent.c_str()); 
  }
  pclose(fp);
  for (auto& it : disk_rec) {
    CtlRecord rec;
    rec.set_node("server");
    rec.set_srv("disk");
    rec.set_op(GetReqOpStr(&req));
    rec.set_id(agentid);
    if (it.first == "/home" || it.first == "/data" || it.first == "/") {
      rec.set_status(to_string(it.second)+ "%");
      rec.set_desc(it.first);
      rec.set_result("succeed");
      auto new_rec = rsp.add_records();
      *new_rec = rec;
    }
  } 
}

static void ProcessAll(const u32 agentid, CtlResponse& rsp) {
  DealControl("ssh", agentid, rsp);
  DealControl("http", agentid, rsp);
  ProcessDisk(agentid, rsp);
}

static string GetAgentIpByAgentId(session& sql, u32 agentid) {
  string agentip = "";
  try {
    cppdb:: result res = sql << "select `ip` from `t_agent` where `id`=? and `disabled`='N'" << agentid;
    if (res.next()) 
      res >> agentip;
  } catch (std::exception const &e) {
    log_err("Error when get agentip: %s", e.what()); 
  }
  return agentip;
}

static string GetAgentIpByProbeId(session& sql, u32 probeid) {
  string agentip = "";
  try {
    cppdb:: result res = sql << "select a.`ip` from t_agent a, t_device d where d.`id`=? and d.`disabled`='N'and d.`agentid`=a.`id`;" << probeid;
    if (res.next()) 
      res >> agentip;
  } catch (std::exception const &e) {
    log_err("Error when get agentip: %s", e.what()); 
  }
  return agentip;
}

// static void GetRemoteInfo() {}

void process() {
  if (is_http) std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";

  stringstream sout;
  CtlResponse rsp;
  session* sql = start_db_session();

  sout << "[" << endl;

  switch (req.node()) {
    case CtlReq::NODE_ALL:{
      stringstream out;
      switch (req.srv()) {
        case CtlReq::SRV_BASIC:{ // 全部节点基础信息
          if ( req.op() != CtlReq::STATUS ) {
            sout << "{\"result\": \"failed\", \"desc\": \"invalid parameter\"}";
            break;
          }

          GetServerNodeInfo(rsp);
          GetAgentNodeInfo(*sql, rsp);
          GetProbeNodeInfo(*sql, rsp);

          if (!rsp.SerializeToOstream(&out)) {
            log_err("failed to serialize to string");
            return;
          }
          OutputResult(out, sout);

          break;
        }
        case CtlReq::SRV_ALL:{ // 全部节点服务信息 // TODO
          if ( req.op() != CtlReq::STATUS ) {
            sout << "{\"result\": \"failed\", \"desc\": \"invalid parameter\"}";
            break;
          }
          // ServerStatus(rsp);
          ProcessAll(0, rsp);
          if (!rsp.SerializeToOstream(&out)) {
            log_err("failed to serialize to string");
            return;
          }
          OutputResult(out, sout);

          CtlResponse node_info;
          GetAgentNodeInfo(*sql, node_info);
          GetProbeNodeInfo(*sql, node_info);

          for (int i = 0;i < node_info.records_size();i++) {
            auto rec = node_info.records(i);

            if (debug) log_info("rec: %s\n", rec.DebugString().c_str());

            CtlReq node_req;

            if (rec.node() == "agent") 
              node_req.set_node(CtlReq::NODE_AGENT);
            else if (rec.node() == "probe") 
              node_req.set_node(CtlReq::NODE_PROBE);
            else 
              continue;

            node_req.set_srv( CtlReq::SRV_ALL );
            node_req.set_op( CtlReq::STATUS );
            node_req.set_id( to_string(rec.id()) );

            string url = "http://" + rec.ip() + ":10081/actl";
            if (debug) { url += "?dbg=1"; }
            string content;
            if (!google::protobuf::TextFormat::PrintToString(node_req, &content)) {
              log_err("Unable to convert CtlReq to Text for posting.\n");
            }
            if (debug) log_info("agentip:%s, req:%s\n", rec.ip().c_str(), content.c_str());
            stringstream remote_out;
            http_post(url, content, &remote_out);
            OutputResult(remote_out, sout);
          }

          break;
        }
        default:{
          sout << "{\"result\": \"failed\", \"desc\": \"invalid parameter\"}";
          break;
        }

      }
      break;
    }
    case CtlReq::NODE_SERVER:{
      stringstream out;
      switch (req.srv()) {
        case CtlReq::SRV_ALL:{
          ProcessAll(stoi(req.id()), rsp);
          break;
        }
        case CtlReq::SRV_SSH:{
          DealControl("ssh", stoi(req.id()), rsp);
          break;
        }
        case CtlReq::SRV_HTTP:{
          DealControl("http", stoi(req.id()), rsp);
          break;
        }
        case CtlReq::SRV_DISK:{
          ProcessDisk(stoi(req.id()), rsp);
          break;
        }
        default:{
          sout << "{\"result\": \"failed\", \"desc\": \"invalid parameter\"}";
          break;
        }
      }

      if (!rsp.SerializeToOstream(&out)) {
        log_err("failed to serialize to string");
        return;
      }
      OutputResult(out, sout);
      break;
    }
    case CtlReq::NODE_AGENT:{
      string agentip;
      agentip = GetAgentIpByAgentId(*sql, stoi(req.id()));
      if (!agentip.empty()) {
        string url = "http://" + agentip + ":10081/actl";
        if (debug) { url += "?dbg=1"; }
        string content;
        if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
          log_err("Unable to convert CtlReq to Text for posting.\n");
        }
        if (debug) log_info("agentip:%s, req:%s\n", agentip.c_str(), content.c_str());
        stringstream out;
        http_post(url, content, &out);
        OutputResult(out, sout);
      } else {
        // log_warning("Analysis node %d does not have an IP configured.\n", stoi(req.id()));
        sout << "{\"result\": \"failed\", \"desc\": \"Analysis node "<< req.id() <<" does not have an IP configured\"}";
      }
      break;
    }
    case CtlReq::NODE_PROBE:{
      string agentip;
      agentip = GetAgentIpByProbeId(*sql, stoi(req.id()));
      if (!agentip.empty()) {
        string url = "http://" + agentip + ":10081/actl";
        if (debug) { url += "?dbg=1"; }
        string content;
        if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
          log_err("Unable to convert CtlReq to Text for posting.\n");
        }
        if (debug) log_info("agentip:%s, req:%s\n", agentip.c_str(), content.c_str());
        stringstream out;
        http_post(url, content, &out);
        log_info("out: %s\n", out.str().c_str());
        OutputResult(out, sout);
      } else {
        // log_warning("Analysis node %d does not have an IP configured.\n", stoi(req.id()));
        sout << "{\"result\": \"failed\", \"desc\": \"Analysis node "<< req.id() <<" does not have an IP configured\"}";
      }
      break;
    }
    default: {
      sout << "{\"result\": \"failed\", \"desc\": \"invalid parameter\"}";
      break;
    }
  }

  sout << endl << "]" << endl;
  cout << sout.str();
  delete sql;
}

int main(int argc, char *argv[]) 
{
  setvbuf(stdout, NULL, _IOFBF, 81920);
  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) debug = true;
    if (!ParseCtlReqFromUrlParams(cgi, &req)) {
      std::cout << "HTTP/1.1 400 Invalid Params\r\n\r\n";
      return 0;
    }
  }
  try {
    process();
  } catch (std::exception const &e) {
    log_err("%s\n", e.what());
  }
  return 0;
}
