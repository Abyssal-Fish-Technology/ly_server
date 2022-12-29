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

static string GetAgentip(session& sql, u32 agentid)
{
  string agentip = "";
  try {
    cppdb:: result res = sql << "select ip from t_agent where id=? and disabled='N'" << agentid;
    if (res.next()) 
      res >> agentip;
  } catch (std::exception const &e) {
    log_err("Error when get agentip: %s", e.what()); 
  }
  return agentip;
}

static inline void OutputRecord(const CtlRecord& rec, stringstream& output) {
  if (rec.has_type()) {
    output_string(output, "type", rec.type());
    output << ",";
  }
  if (rec.has_op()) {
    output_string(output, "op", rec.op());
    output << ",";
  }
  if (rec.has_tid()) {
    output_u64(output, "tid", rec.tid());
    output << ",";
  }
  if (rec.has_time()) {
    output_u64(output, "time", rec.time());
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


static void DealControl(const string& type, const u32 agentid, CtlResponse& rsp) {
  FILE* fp = NULL;
  char line[LINE_MAX];
  CtlRecord rec;
  rec.set_tid(agentid);
  string cmd;
  string op = GetReqOpStr(&req);
  rec.set_type(type);
  rec.set_op(op);
  switch (req.op()) {
    case CtlReq::START:
    case CtlReq::RESTART: {
      cmd = "systemctl " + op + " " + type + "d";
      system(cmd.c_str());
      cmd = cmd = "systemctl status " + type + "d";
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
    case CtlReq::STAT: {
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

static void ProcessDisk(CtlResponse& rsp) {
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
    //rec.set_type(GetReqTypeStr(&req));
    rec.set_type("disk");
    rec.set_op(GetReqOpStr(&req));
    rec.set_tid(stoi(req.tid()));
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
  ProcessDisk(rsp);
}

void process() {
  vector<string> vec;
  csv::fill_vector_from_line(vec, req.tid());
  session* sql = start_db_session();

  if (is_http) std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";

  stringstream sout;
  sout << "[" << endl;
  for (auto& idstr : vec) {
    u32 agentid = stoi(idstr);       
    if (agentid == 0) {
      CtlResponse rsp;
      stringstream out;
      string type = GetReqTypeStr(&req);
      if (type != "all" && type != "ssh" && type != "http" && type != "disk") continue;
      if (type == "all")
        ProcessAll(agentid, rsp);
      else {
        if (type == "http" || type == "ssh")
          DealControl(type, agentid, rsp);
        if (type == "disk")
          ProcessDisk(rsp);
      }

      if (!rsp.SerializeToOstream(&out)) {
        log_err("failed to serialize to string");
        return;
      }
      OutputResult(out, sout);
    } else {
      string agentip;
      agentip = GetAgentip(*sql, agentid);
      req.set_tid(to_string(agentid));
      if (!agentip.empty()) {
        string url = "http://" + agentip + ":10081/actl";
        if (debug) { url += "?dbg=1"; }
        string content;
        if (!google::protobuf::TextFormat::PrintToString(req, &content)) {
          log_err("Unable to convert CtlReq to Text for posting.\n");
        }
        if (debug) log_info("agentip:%s, req:%s\n", agentip.c_str(), content.c_str());
        stringstream oss;
        http_post(url, content, &oss);
        OutputResult(oss, sout);
      } else {
        log_info("no agent or agent is disabled.\n");
      }
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
