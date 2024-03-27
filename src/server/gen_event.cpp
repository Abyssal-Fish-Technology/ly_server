#include "../common/common.h"
#include "../common/datetime.h"
#include "../common/log.h"
#include "../common/ip.h"
#include "../common/http.h"
#include "../common/_strings.h"
#include "../common/event.pb.h"
#include "../common/event_req.h"
#include "../common/csv.hpp"
#include "../common/threadpool.hpp"
#include "dbc.h"
#include "syslog_sender.h"
#include "boost/regex.hpp"
#include <google/protobuf/text_format.h>
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <list>
#include <set>
#include <atomic>
#include <boost/algorithm/string.hpp>

#define VALID_PROTO_PATTERN "^\\d+$" 

const char log_file[] = SERVER_LOG_DIR "/" __FILE__;

using namespace std;
using namespace cppdb;
using namespace event;
using namespace boost;

static set<u64> active_ignore;
static map<u32, string> type_desc;
static map<u32, event::Level> levels;
static bool debug = false;
static u32 ignore_count = 0;
static atomic<int> passed(0);
static atomic<int> reserve(0);
static std::mutex mtx; 
static vector<u64> ids_;
static vector<set<string> > lip_;
static vector<set<string> > lip6_;
static vector<set<string> > tip_;
static vector<set<string> > tip6_;
static vector<set<string> > tport_;
static vector<set<string> > proto_;
static vector<set<string> >domains_;
enum Weekday {
    SUN = 0,
    MON = 1,
    TUE = 2,
    WED = 3,
    THU = 4,
    FRI = 5,
    SAT = 6
};

enum Coverrange {
    WITHIN = 0,
    WITHOUT = 1
};

struct Filter_time {
  vector<Weekday> weekday;
  i32 stime_hour;
  i32 stime_min;
  i32 stime_sec;
  i32 etime_hour;
  i32 etime_min;
  i32 etime_sec;
  Coverrange coverrange;
};
static vector<struct Filter_time> time_;
static vector<u64> count_;


////////////////////////////////////////////////////////////////////////////
// Get agent ip
static void GetAgentIps(
    session& sql,
    list<string>& agentips)
{
  string agentip;

  result res = sql << "select t2.ip as agentip from t_device t1, t_agent t2 "
    " where t1.agentid=t2.id and t2.disabled='N' and t1.disabled='N'";
  while(res.next()) {
    res >> agentip;
    agentips.push_back(agentip);
  }

  agentips.sort();
  agentips.unique();
}

static inline u32 get_level_id(const string& level){
  if (boost::to_upper_copy(level)=="EXTRA_HIGH")
    return 1;
  if (boost::to_upper_copy(level)=="HIGH")
    return 2;
  if (boost::to_upper_copy(level)=="MIDDLE")
    return 3;
  if (boost::to_upper_copy(level)=="LOW")
    return 4;
  if (boost::to_upper_copy(level)=="EXTRA_LOW")
    return 5;

  return 0x7FFFFFFF;
}

static inline bool is_protonum(const string& proto) {
  regex pattern(VALID_PROTO_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(proto,m,pattern);
}

static inline void update_event_data_aggre(session& sql, const Event_Data_Aggr_Record& rec){
  cppdb::statement st = sql << "UPDATE `t_event_data_aggre` SET `event_id`=?,`devid`=?,`obj`=?,`type`=?,`model`=?,`level`=?,`alarm_peak`=?,`sub_events`=?,`alarm_avg`=?,`value_type`=?,`desc`=?,`duration`=?,`starttime`=?,`endtime`=?,`is_alive`=? WHERE `id`=?";
  st << rec.event_id << rec.devid << rec.obj << rec.type << rec.model<<rec.level << rec.alarm_peak << rec.sub_events << rec.alarm_avg << rec.value_type << rec.desc << rec.duration << rec.starttime << rec.endtime << rec.is_alive << rec.id;
  st << cppdb::exec;
}

static inline void update_event_data_aggre(session& sql, const GenEventRecord& rec, u32 event_id, const string& obj, const string& type, u32 model, const event::Level& level, const string& desc){
  result res = sql << "SELECT `id`, `event_id`, `devid`, `obj`, `type`, `model`, `level`, `alarm_peak`, `sub_events`, `alarm_avg`, `value_type`, `desc`, `duration`, `starttime`, `endtime`, `is_alive`"
  " FROM `t_event_data_aggre`"
  " WHERE `obj`=? AND `model`=? AND `type`=? AND `is_alive`=1" << obj << model << type;
  if (res.next()){ // has obj record
    Event_Data_Aggr_Record aggr_rec;
    res >> aggr_rec.id >> aggr_rec.event_id >> aggr_rec.devid >> aggr_rec.obj >> aggr_rec.type >> aggr_rec.model >> aggr_rec.level
      >> aggr_rec.alarm_peak >> aggr_rec.sub_events >> aggr_rec.alarm_avg >> aggr_rec.value_type >> aggr_rec.desc
      >> aggr_rec.duration >> aggr_rec.starttime >> aggr_rec.endtime >> aggr_rec.is_alive;

    if (get_level_id(aggr_rec.level)>level.get_id())
      aggr_rec.level = level.get_desc();
    if (rec.alarm_value()>aggr_rec.alarm_peak)
      aggr_rec.alarm_peak = rec.alarm_value();
    aggr_rec.alarm_avg = ( aggr_rec.alarm_avg * aggr_rec.sub_events + rec.alarm_value() )/( aggr_rec.sub_events + 1);
    aggr_rec.sub_events++;
    aggr_rec.endtime = rec.time() + 300;
    aggr_rec.duration = ( aggr_rec.endtime - aggr_rec.starttime )/60;

    update_event_data_aggre(sql, aggr_rec);
  }
  else{ // no obj record, create one
    cppdb::statement st = sql << "INSERT INTO `t_event_data_aggre`(`event_id`, `devid`, `obj`, `type`, `model`, `level`, `alarm_peak`, `sub_events`, `alarm_avg`, `value_type`, `desc`, `duration`, `starttime`, `endtime`, `is_alive`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    st << event_id << rec.devid() << obj << type << model << level.get_desc() << rec.alarm_value() << 1 << rec.alarm_value() << rec.value_type() << desc << 5 << rec.time() << rec.time()+300 << 1;
    st << cppdb::exec;
  }
}


////////////////////////////////////////////////////////////////////////////
static std::string transfrom_to_ipseg(const string& ip) {
  size_t pos;
  string ip_range;
  if((pos = ip.find("/")) != std::string::npos) {
    string ip_left = ip.substr(0, pos); 
    u32 mask = atoi(ip.substr(pos+1).c_str());
    u32 count = pow(2, 32 - mask) - 1;
    u32 left = ipstr_to_ipnum(ip_left);
    if ((count >> mask) & left) return "";

    string ip_right = ipnum_to_ipstr(left + count);
    ip_range = ip_left + "-" + ip_right;
  } else 
    ip_range = ip;
  return ip_range;
}

static std::string transfrom_to_ipseg_v6(const string& ip) {
  size_t pos;
  string ip_range;
  if((pos = ip.find("/")) != std::string::npos) {
    string ip_left = ip.substr(0, pos); 
    u32 mask = atoi(ip.substr(pos+1).c_str());
    struct in6_addr left = ipstr_to_ipnum_v6(ip_left);

    u32 pivot = mask / 32;
    u32 shift = mask % 32;

    if (pivot<4) {
      left.s6_addr32[pivot] += pow(2, shift);
    }
    for (int i = pivot+1; i<4; i++) {
      left.s6_addr32[i] += pow(2, 32);
    }

    string ip_right = ipnum_to_ipstr_v6(left);

    ip_range = ip_left + "-" + ip_right;
  } else 
    ip_range = ip;
  return ip_range;
}

static inline void set_weekday(struct Filter_time& e, const string& weekday) {
  vector<string> v;
  csv::fill_vector_from_line(v, weekday);

  sort(v.begin(), v.end());
  auto new_end = unique(v.begin(), v.end());
  v.resize( std::distance(v.begin(),new_end) );

  for (auto it=v.begin(); it!=v.end(); it++) {
    int d = atol((*it).c_str());
    if (d>=0&&d<=6)
      e.weekday.push_back(Weekday(d));
  }
}

static inline void set_stime(struct Filter_time& e, const string& stime) {
  vector<string> v;
  csv::fill_vector_from_line(v, stime, ':');

  int hour = 0;
  int minute = 0;
  int sec = 0;

  if (v.size()>0) hour = atol(v[0].c_str());
  if (v.size()>1) minute = atol(v[1].c_str());
  if (v.size()>2) sec = atol(v[2].c_str());

  e.stime_hour = hour;
  e.stime_min = minute;
  e.stime_sec = sec;
}

static inline void set_etime(struct Filter_time& e, const string& etime) {
  vector<string> v;
  csv::fill_vector_from_line(v, etime, ':');

  int hour = 0;
  int minute = 0;
  int sec = 0;

  if (v.size()>0) hour = atol(v[0].c_str());
  if (v.size()>1) minute = atol(v[1].c_str());
  if (v.size()>2) sec = atol(v[2].c_str());

  e.etime_hour = hour;
  e.etime_min = minute;
  e.etime_sec = sec;
}

static inline void set_coverrange(struct Filter_time& e, const string& coverrange) {
  if (coverrange=="within")
    e.coverrange = WITHIN;
  else
    e.coverrange = WITHOUT;
}

////////////////////////////////////////////////////////////////////////////
static void get_ignore_list(session& sql) {
  result res = sql << "SELECT `id`, `lip`, `tip`, `tport`, `protocol`, `domain`, `weekday`, `stime`, `etime`, `coverrange`, `count` from `t_event_ignore`";
  while (res.next()) {
    u64 id;
    string lip, tip, tport, proto, domain;
    string weekday, stime, etime, coverrange;
    u64 count;
    res>>id>>lip>>tip>>tport>>proto>>domain>>weekday>>stime>>etime>>coverrange>>count;
    
    trim(lip);
    trim(tip);
    trim(tport);
    trim(proto);
    trim(domain);
    trim(weekday);
    trim(stime);
    trim(etime);
    trim(coverrange);
    
    ids_.emplace_back(id);


    //tranfrom lip
    bool flag_l_v6 = false;
    set<string> tmp_lip;
    if (!lip.empty()){
      if(lip.find(":") != lip.npos)
        flag_l_v6 = true;
      if (lip[0] == '!') {
        size_t left_pos = lip.find_first_not_of("(", 1);
        size_t right_pos = lip.find_last_not_of(")");
        
        lip = lip.substr(left_pos, right_pos - left_pos + 1);
        
        size_t pos = lip.find(",");  //!(x.x.x.x)
        while(std::string::npos != pos) {
          string tmp = lip.substr(0, pos);
          string ipseg = flag_l_v6 ? \
          transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
          if (!ipseg.empty())
            tmp_lip.insert('!' + ipseg);
          lip = lip.substr(pos + 1); 
          pos = lip.find(",");
        }
        string ipseg = flag_l_v6 ? \
        transfrom_to_ipseg_v6(trim(lip)) : transfrom_to_ipseg(trim(lip));
        if (!ipseg.empty())
          tmp_lip.insert("!" + ipseg);
      } else {
        size_t pos = lip.find(",");
        while(std::string::npos != pos) {
          string tmp = lip.substr(0, pos);
          string ipseg = flag_l_v6 ? \
          transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
          if (!ipseg.empty())
            tmp_lip.insert(ipseg);
          lip = lip.substr(pos + 1);
          pos = lip.find(",");
        }
        string ipseg = flag_l_v6 ? \
        transfrom_to_ipseg_v6(trim(lip)) : transfrom_to_ipseg(trim(lip));
        if (!ipseg.empty())
          tmp_lip.insert(ipseg);
      }
    }
    if (flag_l_v6)
      lip6_.emplace_back(tmp_lip);
    else
      lip_.emplace_back(tmp_lip);


    //tranfrom tip
    bool flag_t_v6 = false;
    set<string> tmp_tip;
    if(!tip.empty()){
      if(lip.find(":") != lip.npos)
        flag_t_v6 = true;
      if (tip[0] == '!') {
        size_t left_pos = tip.find_first_not_of("(", 1);
        size_t right_pos = tip.find_last_not_of(")");

        tip = tip.substr(left_pos, right_pos - left_pos + 1);

        size_t pos = tip.find(",");
        while(std::string::npos != pos) {
          string tmp = tip.substr(0, pos);
          string ipseg = flag_t_v6 ? \
          transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
          if (!ipseg.empty())
            tmp_tip.insert("!" + ipseg);
          tip = tip.substr(pos + 1);
          pos = tip.find(",");
        }
        string ipseg = flag_t_v6 ? \
        transfrom_to_ipseg_v6(trim(tip)) : transfrom_to_ipseg(trim(tip));
        if (!ipseg.empty())
          tmp_tip.insert("!" + ipseg);
      } else {
        size_t pos = tip.find(",");
        while(std::string::npos != pos) {
          string tmp = tip.substr(0, pos);
          string ipseg = flag_t_v6 ? \
          transfrom_to_ipseg_v6(trim(tmp)) : transfrom_to_ipseg(trim(tmp));
          if (!ipseg.empty())
            tmp_tip.insert(ipseg);
          tip = tip.substr(pos + 1);
          pos = tip.find(",");
        }
        string ipseg = flag_t_v6 ? \
        transfrom_to_ipseg_v6(trim(tip)) : transfrom_to_ipseg(trim(tip));
        if (!ipseg.empty())
          tmp_tip.insert(ipseg);
      }
    }
    if (flag_t_v6)
      tip6_.emplace_back(tmp_tip);
    else
      tip_.emplace_back(tmp_tip);


    //trnsfrom tport
    set<string> tmp_tport;
    if (tport.empty()) tport_.emplace_back(tmp_tport);
    else {
      if (tport[0] == '!') {
        size_t left_pos = tport.find_first_not_of("(", 1);
        size_t right_pos = tport.find_last_not_of(")");

        tport = tport.substr(left_pos, right_pos - left_pos + 1);
        size_t pos = tport.find(",");
        while(std::string::npos != pos) {
          string tmp = tport.substr(0, pos);
          tmp_tport.insert("!" + trim(tmp));
          tport = tport.substr(pos + 1);
          pos = tport.find(",");
        }
        tmp_tport.insert("!" + trim(tport));
      } else {
        size_t pos = tport.find(",");
        while(std::string::npos != pos) {
          string tmp = tport.substr(0, pos);
          tmp_tport.insert(trim(tmp));
          tport = tport.substr(pos + 1);
          pos = tport.find(",");
        }
        tmp_tport.insert(trim(tport));
      }
      tport_.emplace_back(tmp_tport);
    }
    //transfrom proto
    set<string> tmp_proto;
    if (proto.empty())  proto_.emplace_back(tmp_proto);
    else {
      size_t pos = proto.find(",");
      while(std::string::npos != pos) {
        string tmp = proto.substr(0, pos);
        tmp = trim(tmp);
        if (is_protonum(tmp)) 
          tmp_proto.insert(proto_to_string(atoi(tmp.c_str())));
        else
          tmp_proto.insert(boost::to_upper_copy(tmp));
        proto = proto.substr(pos + 1);
        pos = proto.find(",");
      }
      proto = trim(proto);
      if (is_protonum(proto))
        tmp_proto.insert(proto_to_string(atoi(proto.c_str())));
      else
        tmp_proto.insert(boost::to_upper_copy(proto));
      proto_.emplace_back(tmp_proto);
    }
   
    set<string> tmp_domain;
    if (domain.empty()) domains_.emplace_back(tmp_domain);
    else {
      size_t pos = domain.find(",");
      while(std::string::npos != pos) {
        string tmp = domain.substr(0, pos);
        tmp = trim(tmp);
        tmp_domain.insert(tmp);
        domain = domain.substr(pos + 1);
        pos = domain.find(",");
      }
      domain = trim(domain);
      tmp_domain.insert(domain);
      domains_.emplace_back(tmp_domain);
    } 
     
    struct Filter_time tmp_time;
    set_weekday(tmp_time, weekday);
    set_stime(tmp_time, stime);
    set_etime(tmp_time, etime);
    set_coverrange(tmp_time, coverrange);
    time_.emplace_back(tmp_time);
    
    count_.emplace_back(count);

    ignore_count++; 
  } 
}


static bool check_ip(std::set<string>& ip_list, u32 sip) {
  bool ip_match = false;
  if (ip_list.size() == 0) {
    return true;
  }
  if (sip == 0) {
    return false;
  }
  for(auto it = ip_list.begin();it != ip_list.end();it++) {
    u32 min, max;
    string lip = *it;
    if (lip.empty()) continue;
    size_t pos;
    if (lip[0] == '!') {
      if ((pos = lip.find("-", 1)) != std::string::npos) {
        min = ipstr_to_ipnum(lip.substr(1, pos - 1));
        max = ipstr_to_ipnum(lip.substr(pos + 1));
        if (sip > max || sip < min) {
          ip_match = true;
        } else if (sip >= min && sip <= max) {
          ip_match = false;
          break;
        }
      } else {
        u32 left = ipstr_to_ipnum(lip.substr(1));
        if (sip != left) {
          ip_match = true;
        } else {
          ip_match = false;
          break;
        }
      }
    } else {
      if ((pos = lip.find("-")) != std::string::npos) {
        min = ipstr_to_ipnum(lip.substr(0, pos));
        max = ipstr_to_ipnum(lip.substr(pos + 1));
        if (sip >= min && sip <= max) {
          ip_match = true;
          break;
        }
      } else {
        if (sip == ipstr_to_ipnum(lip)) {
          ip_match = true;
          break;
        }
      }
    }
  }
  return ip_match;
}

static bool check_ip_v6(std::set<string>& ip_list, struct in6_addr sip) {
  bool ip_match = false;
  if (ip_list.size() == 0) {
    return true;
  }
  if (sip.s6_addr32[0] == 0 && sip.s6_addr32[1] == 0 && sip.s6_addr32[2] == 0 && sip.s6_addr32[3] == 0) {
    return false;
  }
  for(auto it = ip_list.begin();it != ip_list.end();it++) {
    struct in6_addr min, max;
    string lip = *it;
    if (lip.empty()) continue;
    size_t pos;

    if (lip[0] == '!') {
      if ((pos = lip.find("-", 1)) != std::string::npos) {
        min = ipstr_to_ipnum_v6(lip.substr(1, pos - 1));
        max = ipstr_to_ipnum_v6(lip.substr(pos + 1));
        if ((memcmp(&sip, &max, sizeof(struct in6_addr)) > 0) || 
              (memcmp(&sip, &min, sizeof(struct in6_addr)) < 0)) {
          ip_match = true;
        } else if ((memcmp(&sip, &min, sizeof(struct in6_addr)) >= 0) && 
              (memcmp(&sip, &max, sizeof(struct in6_addr)) <= 0)) {
          ip_match = false;
          break;
        }
      } else {
        struct in6_addr  left = ipstr_to_ipnum_v6(lip.substr(1));
        if ((memcmp(&sip, &left, sizeof(struct in6_addr)) != 0)) {
          ip_match = true;
        } else {
          ip_match = false;
          break;
        }
      }
    } else {//lip[0] != '!'
      if ((pos = lip.find("-")) != std::string::npos) {
        min = ipstr_to_ipnum_v6(lip.substr(0, pos));
        max = ipstr_to_ipnum_v6(lip.substr(pos + 1));
        if ((memcmp(&sip, &min, sizeof(struct in6_addr)) >= 0) && 
              (memcmp(&sip, &max, sizeof(struct in6_addr)) <= 0)){
          ip_match = true;
          break;
        }
      } else {
        struct in6_addr  left = ipstr_to_ipnum_v6(lip);
        if ((memcmp(&sip, &left, sizeof(struct in6_addr)) == 0)){
          ip_match = true;
          break;
        }
      }
    }
  }//for
  return ip_match;
}

static bool check_port(std::set<string>& port_list, u16 dport) {
  bool port_match = false;
  if (port_list.size() == 0) return true;
  for(auto it = port_list.begin();it != port_list.end();it++) {
    u16 min, max;
    string port = *it;
    if (port.empty()) continue;
    size_t pos;
    if (port[0] == '!') {
      if ((pos = port.find("-", 1)) != std::string::npos) {
        min = atoi(port.substr(1, pos - 1).c_str());
        max = atoi(port.substr(pos + 1).c_str());
        if (dport > max && dport < min) {
          port_match = true;
        } else if (dport >= min && dport <= max) {
          port_match = false;
          break;
        }
      } else {
        u16 left = atoi(port.substr(1).c_str());
        if (dport != left) {
          port_match = true;
        } else {
          port_match = false;
          break;
        }
      }
    } else {
      if ((pos = port.find("-")) != std::string::npos) {
        min = atoi(port.substr(0, pos).c_str());
        max = atoi(port.substr(pos + 1).c_str());
        if (dport >= min && dport <= max) {
          port_match = true;
          break;
        }
      } else {
        if (dport == atoi(port.c_str())) {
          port_match = true;
          break;
        }
      }
    }
  }
  return port_match;
}

static bool check_proto(std::set<string>& proto_list, const string& proto) {
  bool proto_match = false;
  if (proto_list.size() == 0) return true;
  for(auto it = proto_list.begin();it != proto_list.end();it++) {
    string tmp_proto = *it;
    if (tmp_proto.empty()) continue;
    if (proto == tmp_proto) {
      proto_match = true;
      break;
    }
  }
  return proto_match;
}

static bool check_time(time_t t, struct Filter_time& e) {
  bool within = false;

  struct tm *p = localtime(&t);
  for (u32 i=0; i<e.weekday.size(); i++) {
    if (e.weekday[i]==p->tm_wday) {
      within = true;
      break;
    }
  }

  if (within==false)
    return (e.coverrange == WITHIN)? false : true;

  if (p->tm_hour >= e.stime_hour
    && p->tm_min  >= e.stime_min
    && p->tm_sec  >= e.stime_sec
    && p->tm_hour <= e.etime_hour
    && p->tm_min  <= e.etime_min
    && p->tm_sec  <= e.etime_sec
  )
    within = true;
  else
    within = false;

  if ( (within==true && e.coverrange==WITHIN) || (within==false && e.coverrange==WITHOUT) )
    return true;
  else
    return false;
}

static bool check_domain(std::set<string>& domain_list, const string& domain) {
  bool domain_match = false;

  if (domain_list.size() == 0)
    return true;
  if (domain.empty())
    return false;
  for(auto it = domain_list.begin();it != domain_list.end();it++) {
    string tmp_domain = *it;
    if (tmp_domain.empty()) continue;
    if (domain == tmp_domain) {
      domain_match = true;
      break;
    }
  }
  return domain_match;
}

static void process_each_event_record(const GenEventRecord& rec) {
  u32 event_id, level_id;
  string event_str;
  string desc,obj;
  string level;
  string type = type_desc.at(rec.type_id());
 
  session* sql = start_db_session(); 
  result res = *sql<<"SELECT t1.`id`, t1.`desc`, t1.`level_id`"
  " FROM `t_event_list` t1"
  " WHERE (t1.`type_id` = ? AND t1.`config_id` = ? )"
  << rec.type_id() << rec.config_id();

  res.next();
  res >> event_id >> desc >> level_id;

  cppdb::statement st = *sql << "INSERT INTO `t_event_data` (`time`, `event_id`, `type`, `model`, `devid`, `level`, `obj`, `thres_value`, `alarm_value`, `value_type`, `desc`) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
  st << rec.time() << event_id << type << rec.model_id() << rec.devid();

  if (levels.at(level_id).empty()) {
    st << levels.at(level_id).get_desc();
    level = levels.at(level_id).get_desc();
  }
  else{
    level_id = levels.at(level_id).calc_level_id( rec.thres_value(), rec.alarm_value() );
    st << levels.at(level_id).get_desc();
    level = levels.at(level_id).get_desc();
  }

  // ip:port>ip:port protocol desc / [ipv6]:port>[ipv6]:port protocol desc
  obj = rec.obj();
  bool flag_v6 = false;
  size_t pos, pos1, pos2, sip_l, sip_r, dip_l, dip_r;
  struct in6_addr sip_v6, dip_v6;
  u32 sip, dip;
  sip_l = obj.find("[");
  pos1 = obj.find(">");

  if(sip_l != std::string::npos){//ipv6
    flag_v6 = true;
    if (sip_l > pos1) {//sip=""
      sip_v6 = ipstr_to_ipnum_v6("");
      dip_l = sip_l;
      dip_r = obj.find("]", dip_l+1);
      dip_v6 = ipstr_to_ipnum_v6(obj.substr(dip_l+1, dip_r-dip_l-1));
      pos2 = obj.find(":", dip_r+1);
    } else {
      sip_r = obj.find("]", sip_l+1);
      sip_v6 = ipstr_to_ipnum_v6(obj.substr(sip_l+1, sip_r-sip_l-1));
      dip_l = obj.find("[", pos1+1);
      dip_r = obj.find("]", dip_l+1);
      dip_v6 = ipstr_to_ipnum_v6(obj.substr(dip_l+1, dip_r-dip_l-1));
      pos2 = obj.find(":", dip_r+1);
    }
  } else {  //ipv4
    flag_v6 = false;
    pos = obj.find(":");
    sip = ipstr_to_ipnum(obj.substr(0, pos));
    pos1 = obj.find(">", pos+1);
    pos2 = obj.find(":", pos1+1);
    dip = ipstr_to_ipnum(obj.substr(pos1+1, pos2-pos1-1));
  }

  size_t pos3 = obj.find(" ", pos2+1);
  u16 dport = atoi(obj.substr(pos2+1, pos3-pos2-1).c_str());
  size_t pos4 = obj.find(" ", pos3+1);
  size_t rpos = obj.rfind(" ");
  string prot, domain;
  prot = obj.substr(pos3+1, pos4-pos3-1);
  if (type == "dns_tun" || type == "dns") {
    domain = obj.substr(pos4+1, rpos-pos4-1);
  }

  bool is_white = false;
  bool lip_match = false, tip_match = false, tport_match = false, proto_match = false, time_match = false, domain_match = false;
  for(u64 i = 0; i < ignore_count; i++) {
    lip_match = flag_v6 ? check_ip_v6(lip6_[i], sip_v6) : check_ip(lip_[i], sip);
    if (!lip_match) continue;
    tip_match = flag_v6 ? check_ip_v6(tip6_[i], dip_v6) : check_ip(tip_[i], dip);
    if (!tip_match) continue;
    tport_match = check_port(tport_[i], dport);
    if (!tport_match) continue;
    proto_match = check_proto(proto_[i], prot);
    if (!proto_match) continue;
    time_match = check_time(rec.time(), time_[i]);
    if (!time_match) continue;
    domain_match = check_domain(domains_[i], domain);
    if (!domain_match) continue;

    if (lip_match && tip_match && tport_match && proto_match && time_match && domain_match) {
      is_white = true;
      mtx.lock();
      count_[i]++;
      active_ignore.emplace(i);
      mtx.unlock();
      break;
    }
  }

  if (is_white) {
    passed++;
    delete sql;
    return; //is white
  }

  event_str = "devid: " + to_string(rec.devid()) + ", time: " + to_string(rec.time()) + ", event_id: " +  to_string(event_id) + ", type: " + type;
  event_str = event_str + ", level: " + level;
  event_str = event_str + ", obj: " + obj + ", thres_value: " + to_string(rec.thres_value()) + ", alarm_value: " +
              to_string(rec.alarm_value()) + ", value_type: " + rec.value_type() + ", desc: " + desc;

  st << obj << rec.thres_value() << rec.alarm_value() << rec.value_type() << desc;

  send_event_syslog_process(level_id, event_str);

  try{
    st<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("Error when INSERT INTO `t_event_data`: %s\n", e.what());
    delete sql;
    return;
  }
  
  try{
    update_event_data_aggre(*sql, rec, event_id, obj, type, rec.model_id(), levels.at(level_id), desc);
  } catch ( cppdb::cppdb_error const &e ){
    log_err("Error when UPDATE `t_event_data_aggre`: %s\n", e.what());
    delete sql;
    return;
  }

  reserve++;

  delete sql;
}

////////////////////////////////////////////////////////////////////////////
static inline void process_gen_event_response(session& sql, stringstream& oss){
  GenEventRes res;
  res.ParseFromIstream(&oss);

  if (res.records_size() == 0)
    return;

  //get_ignore_list(sql);

  std::vector< std::future<void> > results;
  //int cpu_num = sysconf(_SC_NPROCESSORS_CONF) * 0.8;
  int cpu_num = 1;
  threadpool::Threadpool pool(cpu_num); 

  for (int i=0;i<res.records_size();i++){
    const GenEventRecord& rec = res.records(i);
    results.emplace_back(pool.commit(process_each_event_record, rec));
  }
  for (auto&& re : results) {
    re.get();
  }

  for (auto it = active_ignore.begin(); it != active_ignore.end(); it++) {
    auto num = *it;
    cppdb::statement st = sql <<"UPDATE `t_event_ignore` SET `count` = ?, `time` = FROM_UNIXTIME(?) WHERE `id` = ?";
    st<<count_[num]<<time(NULL)<<ids_[num]<<cppdb::exec; 
  }  

  log_info("total events: %d, filtered：%d, insert into database: %d\n", res.records_size(), passed.load(), reserve.load());
  passed = 0;
  reserve = 0;
  active_ignore.clear();
}

static void check_event_data_aggre_timeout(session& sql, u32 timeout){
  vector<u32> ids;
  u32 id;

  result res = sql << "SELECT `id` FROM `t_event_data_aggre` WHERE `is_alive`=1 AND `endtime`<?" << timeout;
  while (res.next()){
    res>>id;
    ids.push_back(id);
  }
  string update_str = "UPDATE `t_event_data_aggre` SET `is_alive`=0 WHERE `id` = ?";
  cppdb::statement st = sql << update_str;
  for(u32 i = 0; i < ids.size(); i++) {
    st.bind(ids[i]);
    st.exec();
    st.reset();
  }
}

////////////////////////////////////////////////////////////////////////////
static void process(GenEventReq& common_req)
{
  // start db connection
  session* sql = start_db_session();

  // Get agent ip
  list<string> agentips;
  GetAgentIps(*sql, agentips);

  // Get type desc info
  result res = *sql<<"SELECT `id`, `desc` FROM `t_event_type`";
  while(res.next()) {
    u32 id;
    res >> id;
    res >> type_desc[id];
  }

  // Get level info
  u32 id;
  string level_desc, level_profile;
  res = *sql<<"SELECT `id`, `desc`, `profile` FROM `t_event_level`";
  while(res.next()) {
    res >> id >> level_desc >> level_profile;
    levels[id]=Level(id, level_desc, level_profile);
  }

  string content;
  if (!google::protobuf::TextFormat::PrintToString(common_req, &content)) {
    log_err("Unable to convert Req to Text for posting.\n");
  }

  get_ignore_list(*sql);
  // Post req to every agent
  while(!agentips.empty()) {
    string agentip = agentips.front();
    string url = "http://"  + agentip + ":10081/extract_event";
    if (debug) { url += "?dbg=1"; }

    // Post req
    if (debug) log_info("agentip:%s, req:%s\n", agentip.c_str(), content.c_str());
    stringstream oss;
    http_post(url, content, &oss);
    process_gen_event_response(*sql, oss);
    agentips.pop_front();
  }
  check_event_data_aggre_timeout(*sql, common_req.endtime()-4200);
  delete sql;
}

///////////////////////////////////////////////////////////////////////////
static bool ParseCmdline( int argc, char *argv[], GenEventReq& req) {
  u32 stime = 0, etime = 0;
  u32 offset = 0;
  char c;
  while ((c = getopt(argc, argv, "s:e:o:")) != -1) {
    switch (c) {
      case 's':
        stime = atoi(optarg);
        req.set_starttime(stime - stime % 300);
        break;
      case 'e':
        etime = atoi(optarg);
        req.set_endtime(etime - etime % 300);
        break;
      case 'o':
        offset = atoi(optarg);
        offset = offset - offset % 300;
        break;
      default:
        return false;
    }
  }
  
  if (!req.has_endtime()) 
    req.set_endtime(datetime::latest_flow_time());
  if (!req.has_starttime())
    req.set_starttime(req.endtime() - 300);

  req.set_endtime(req.endtime() - offset);
  req.set_starttime(req.starttime() - offset);

  if (req.starttime() > req.endtime()) return false;
  
  return true;
} 

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);
  GenEventReq req;
  
  if (!ParseCmdline(argc, argv, req)) {
    return 0;
  }
 
  try {
    process(req);
  } catch (std::exception const &e) {
    log_err("%s\n", e.what());
  }

  return 0;
}
