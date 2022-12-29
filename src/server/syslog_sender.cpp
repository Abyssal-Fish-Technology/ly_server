#include "syslog_sender.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cppdb/frontend.h>
#include <boost/algorithm/string.hpp>
#include <string>
#include <iostream>
#include <set>
#include <map>
#include "boost/regex.hpp"

using namespace boost;

#define SYSLOG_CONF_PATTERN "^(.*)\\.(.*)\\s+(@{1,2})(((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?))(:[1-9]\\d{0,15})?$"
static std::set<string> conf_str;

static std::map<string, u32> Level{{"EXTRA_HIGH", 1}, {"HIGH", 2}, {"MIDDLE", 3},
                                   {"LOW", 4}, {"EXTRA_LOW", 5}};

static std::map<string, u32> Facility{{"KERN", 0}, {"USER", 1}, {"MAIL", 2},
                                      {"DAEMON", 3}, {"AUTH", 4}, {"SYSLOG", 5},
                                      {"LPR", 6}, {"NEWS", 7}, {"UUCP", 8},
                                      {"CRON", 9}, {"AUTHPRIV", 10}, {"LOGTP", 11},
                                      {"NTP", 12}, {"AUDIT", 13}, {"ALERT", 14},
                                      {"CLOCK", 15}, {"LOCAL0", 16}, {"LOCAL1", 17},
                                      {"LOCAL2", 18}, {"LOCAL3", 19}, {"LOCAL4", 20},
                                      {"LOCAL5", 21}, {"LOCAL6", 22}, {"LOCAL7", 23}};


static string create_prefix(const string& pri, const string& ip) {
  time_t time_log;
  time(&time_log);
  char* time_str = ctime(&time_log);//Www Mmm dd hh:mm:ss yyyy
  string time_all = time_str;
  std::string time_left = time_all.substr(4, 15);// Mmm dd hh:mm:ss
  string syslog_prefix = "<" + pri + ">" + time_left + " " + ip + " FsEvent: ";
  return syslog_prefix;
}


static string create_pri(u32 facility, u32 level) {
  u32 pri = facility * 8 + level;
  return to_string(pri);
}


static void send_event_str(u16 port, const string& ip, const string& sock_type, const string& syslog_str) {
  struct sockaddr_in server;
  int sock;
  bzero(&server, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = inet_addr(ip.c_str());
  int server_len = sizeof(struct sockaddr_in);

  if (sock_type == "UDP") {
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      log_err("create udp socket error.\n");
      return;
    }
    if (sendto(sock, syslog_str.c_str(), syslog_str.size(), 0, (struct sockaddr *) &server, server_len) < 0) {
      log_err("udp sent events to server error.\n");
      return;
    }
  } else if (sock_type == "TCP") {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      log_err("create tcp socket error.\n");
      return;
    }
    connect(sock, (struct sockaddr *) &server, server_len);
    if(send(sock, syslog_str.c_str(), syslog_str.size(), 0) < 0) {
      log_err("tcp sent events to server error.\n");
      return;
    }
  }
  close(sock);
}

static void send_events_to_syslog(const string& fac_str, const string& log_level, const string& sock_str, 
             const string& ip, const string& port_str,  u32 level_id, const string& event_str) {
  u32 facility, level;
  u16 port;
  string sock_type;
    //syslog config style, for example "*.* @192.168.1.1:514"(facility.level @ip:port, one @ means udp, two @ means tcp)
    //find out facility
  if (fac_str == "*") 
    facility = Facility["LOCAL7"];
  else
    facility = Facility[boost::to_upper_copy(fac_str)];

  //find out level
  if (log_level == "*")
    level = Level["EXTRA_LOW"];
  else
    level = Level[boost::to_upper_copy(log_level)];

  if (level < level_id) return;
  
  //find out proto,  @ means udp, @@ means tcp
  if (sock_str == "@")
    sock_type = "UDP";
  else if (sock_str == "@@")
    sock_type = "TCP";

  //find out port 
  if (!port_str.empty()) {
    string tmp = port_str.substr(1);  //delete ':'
    port = atoi(tmp.c_str());
  } else
    port = 514;

  string pri = create_pri(facility, level);
  string syslog_prefix = create_prefix(pri, ip);
  string message = syslog_prefix + event_str;
  send_event_str(port, ip, sock_type, message);    
}

void send_event_syslog_process(u32 level_id, const string& event_str) {
  ifstream ifs(SYSLOGSENDER_CONF);
  if (!ifs.is_open()) {
//    log_err(__FILE__": failed to load syslog_event config: %s\n", SYSLOGSENDER_CONF);
    return;
  }

  string line;
  regex pattern(SYSLOG_CONF_PATTERN);
  smatch m;
  while(getline(ifs, line)) {
    trim(line);
    if (line.empty() || line[0] == '#' || line[0] == '[') continue;
    else {
      if(regex_match(line, m, pattern)) {
        send_events_to_syslog(m[1].str(), m[2].str(), m[3].str(), m[4].str(), m[8].str(), level_id, event_str);
      }
    }
  }
}
