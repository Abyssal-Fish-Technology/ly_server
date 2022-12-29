#include "../common/common.h"
#include "../common/log.h"
#include "../common/http.h"
#include "../common/config.pb.h"
#include "../common/csv.hpp"
#include "define.h"
#include "dbc.h"
#include <google/protobuf/text_format.h>
#include <cppdb/frontend.h>
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace cppdb;
using namespace config;
using namespace policy;
using namespace boost;

static cppdb::session* sql = NULL;
static int debug = 0;

////////////////////////////////////////////////////////////////////////////
static void construct_cfg_mo(Config& common_cfg, map<u32,Config>& cfg, const map<u32,u32>& dev_to_agent){
  map<u32, policy::PolicyIndex * > agent_pi;
  PolicyIndex common_pi;

  common_pi.set_policy(MO);
  common_pi.set_format(EMBEDDED);

  for (auto it = cfg.begin(); it!=cfg.end(); it++)
    agent_pi[it->first] = it->second.add_policy_index();

  cppdb::result r;
  try{
    r = *sql << "SELECT `devid`, `id`, `mogroupid`, `moip`, `moport`, `protocol`, `pip`, `pport`, `filter`, `direction` FROM `t_mo`";
    while (r.next()) {
      u32 u;
      string s;
      cppdb::null_tag_type nullTag;
      mo::MoRecord *mo;

      PolicyIndex *pi;
      PolicyData *pd;
      string label;

      r>>cppdb::into(u,nullTag);
      if (nullTag!=cppdb::null_value){
        try {
          mo = cfg[dev_to_agent.at(u)].add_mo();

          pi = agent_pi[dev_to_agent.at(u)];
          pd = cfg[dev_to_agent.at(u)].add_policy_data();

          mo->set_devid(u);
        }
        catch (const std::out_of_range& oor) {
          log_err("%d: Out of range for dev_to_agent.at(%u)\n", __LINE__, u);
        }
      }
      else {
        mo = common_cfg.add_mo();

        pi = &common_pi;
        pd = common_cfg.add_policy_data();
      }

      r>>u;
      mo->set_id(u);

      label = "mo_"+to_string(u);
      pi->add_policy_data_label(label);
      pd->set_label(label);
      pd->set_format(MO_DATA);
      
      r>>u;
      mo->set_mogroupid(u);

      r>>s;
      mo->set_moip(s);

      r>>s;
      mo->set_moport(s);

      r>>s;
      mo->set_protocol(s);

      r>>s;
      mo->set_pip(s);

      r>>s;
      mo->set_pport(s);

      r>>s;
      mo->set_filter(s);
		
      r>>s;
      mo->set_direction(s);

      pd->mutable_mo()->MergeFrom(*mo);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_cfg_mo(): %s", __LINE__, e.what());
    return;
  }

  for (auto it = agent_pi.begin(); it!=agent_pi.end(); it++)
    it->second->MergeFrom(common_pi);
}

static inline void set_weekday(Event *e, const string& weekday) {
  vector<string> v;
  csv::fill_vector_from_line(v, weekday);

  sort(v.begin(), v.end());
  auto new_end = unique(v.begin(), v.end());
  v.resize( std::distance(v.begin(),new_end) );

  for (auto it=v.begin(); it!=v.end(); it++) {
    int d = atol((*it).c_str());
    if (d>=0&&d<=6)
      e->add_weekday(Event::Weekday(d));
  }
}

static inline void set_stime(Event *e, const string& stime) {
  vector<string> v;
  csv::fill_vector_from_line(v, stime, ':');

  int hour = 0;
  int minute = 0;
  int sec = 0;

  if (v.size()>0) hour = atol(v[0].c_str());
  if (v.size()>1) minute = atol(v[1].c_str());
  if (v.size()>2) sec = atol(v[2].c_str());

  e->set_stime_hour(hour);
  e->set_stime_min(minute);
  e->set_stime_sec(sec);
}

static inline void set_etime(Event *e, const string& etime) {
  vector<string> v;
  csv::fill_vector_from_line(v, etime, ':');

  int hour = 0;
  int minute = 0;
  int sec = 0;

  if (v.size()>0) hour = atol(v[0].c_str());
  if (v.size()>1) minute = atol(v[1].c_str());
  if (v.size()>2) sec = atol(v[2].c_str());

  e->set_etime_hour(hour);
  e->set_etime_min(minute);
  e->set_etime_sec(sec);
}

static inline void set_coverrange(Event *e, const string& coverrange) {
  if (coverrange=="within")
    e->set_coverrange(Event::WITHIN);
  else
    e->set_coverrange(Event::WITHOUT);
}

////////////////////////////////////////////////////////////////////////////
static inline void construct_event_config(Config& common_cfg, map<u32,Config>& cfg, const map<u32,u32>& dev_to_agent){
  u32 id, moid, min, max, min_peerips, max_peerips, min_peerports, max_peerports, min_portsessions, max_portsessions;
  u32 if1, if2, if3;
  string thres_mode, data_type, grep_rule;
  cppdb::null_tag_type nullTag, min_nullTag, max_nullTag;
  cppdb::null_tag_type status_moid_nullTag, devid_nullTag;
  cppdb::null_tag_type ip_nullTag;
  cppdb::null_tag_type port_nullTag;
  cppdb::null_tag_type protocol_nullTag;
  u32 devid, status_moid;
  u32 port;
  string ip, protocol, sip, dip;
  string weekday, stime, etime, coverrange;
  Event *p;
  string qname;
  u32 namelen, fqcount, qcount, detvalue;
  u32 sub_type;
  string pat;

  cppdb::result res;
  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, t1.`moid`, `thres_mode`, `data_type`, `min`, `max`, `grep_rule`, t3.`moid`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
      " FROM `t_event_config_threshold` t1, `t_event_list` t2, `t_event_status` t3 "
      " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=1 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while (res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>moid>>thres_mode>>data_type>>cppdb::into(min, min_nullTag)>>cppdb::into(max, max_nullTag)>>grep_rule>>cppdb::into(status_moid, status_moid_nullTag);
      res>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else
      {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(1);
      p->set_config_id(id);
      if ( moid>0 )
        p->set_moid(moid);
      p->set_thres_type(thres_mode);
      p->set_data_type(data_type);
      if (min_nullTag!=cppdb::null_value)
        p->set_min(min);
      if (max_nullTag!=cppdb::null_value)
        p->set_max(max);
      p->set_grep_rule(grep_rule);
      if (status_moid_nullTag!=cppdb::null_value)
        p->set_status_moid(status_moid);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_threshold: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `min_peerips`, `max_peerips`, t1.`ip`, t1.`port`, t1.`protocol`, t3.`moid`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
    " FROM `t_event_config_port_scan` t1, `t_event_list` t2, `t_event_status` t3 "
    " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=2 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

     while (res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>min_peerips>>cppdb::into(max_peerips, nullTag)>>cppdb::into(ip, ip_nullTag)>>cppdb::into(port, port_nullTag)>>cppdb::into(protocol, protocol_nullTag)>>cppdb::into(status_moid, status_moid_nullTag);
      res>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else
      {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(2);
      p->set_config_id(id);
      p->set_min(min_peerips);
      if (nullTag!=cppdb::null_value)
        p->set_max(max_peerips);
      if (ip_nullTag!=cppdb::null_value)
        p->set_ip(ip);
      if (port_nullTag!=cppdb::null_value)
        p->set_port(port);
      if (protocol_nullTag!=cppdb::null_value)
        p->set_protocol(protocol);
      if (status_moid_nullTag!=cppdb::null_value)
        p->set_status_moid(status_moid);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_scan: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `min_peerports`, `max_peerports`, t1.`sip`, t1.`dip`, t1.`protocol`, t3.`moid`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
    " FROM `t_event_config_ip_scan` t1, `t_event_list` t2, `t_event_status` t3 "
    " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=8 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

     while (res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>min_peerports>>cppdb::into(max_peerports, nullTag)>>cppdb::into(sip, ip_nullTag)>>cppdb::into(dip, ip_nullTag)>>cppdb::into(protocol, protocol_nullTag)>>cppdb::into(status_moid, status_moid_nullTag);
      res>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else
      {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(8);
      p->set_config_id(id);
      p->set_min(min_peerports);
      if (nullTag!=cppdb::null_value)
        p->set_max(max_peerports);
      if (ip_nullTag!=cppdb::null_value)
        p->set_sip(sip);
      if (ip_nullTag!=cppdb::null_value)
        p->set_dip(dip);
      if (protocol_nullTag!=cppdb::null_value)
        p->set_protocol(protocol);
      if (status_moid_nullTag!=cppdb::null_value)
        p->set_status_moid(status_moid);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_port_config_port_scan: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `min_portsessions`, `max_portsessions`, t1.`ip`, t1.`port`, t1.`protocol`, t3.`moid`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
    " FROM `t_event_config_srv` t1, `t_event_list` t2, `t_event_status` t3 "
    " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=3 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while (res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>min_portsessions>>cppdb::into(max_portsessions, nullTag)>>ip>>cppdb::into(port, port_nullTag)>>cppdb::into(protocol, protocol_nullTag)>>cppdb::into(status_moid, status_moid_nullTag);
      res>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else
      {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(3);
      p->set_config_id(id);
      p->set_min(min_portsessions);
      if (nullTag!=cppdb::null_value)
        p->set_max(max_portsessions);
      p->set_ip(ip);
      if (port_nullTag!=cppdb::null_value)
        p->set_port(port);
      if (protocol_nullTag!=cppdb::null_value)
        p->set_protocol(protocol);
      if (status_moid_nullTag!=cppdb::null_value)
        p->set_status_moid(status_moid);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_srv: %s", __LINE__, e.what());
    return;
  }

	try {
		res = *sql << "SELECT t1.`id`, t2.`devid`, `data_type`, `min`, `max`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
			" FROM `t_event_config_sus` t1, `t_event_list` t2, `t_event_status` t3"
			" WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=6 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' "; 
	
		while(res.next()) {
			res>>id>>cppdb::into(devid, devid_nullTag)>>data_type>>min>>cppdb::into(max, nullTag);
    	  res>>weekday>>stime>>etime>>coverrange;
      	if (devid_nullTag==cppdb::null_value)
        	p = common_cfg.add_event();
      	else
      	{
        	try{
          	p = cfg[dev_to_agent.at(devid)].add_event();
          	p->set_devid(devid);
        	}catch (const std::out_of_range& oor) {
          	continue;
        	}
      	}

    	p->set_type_id(6);
      p->set_config_id(id);
      p->set_data_type(data_type);
      p->set_min(min);
      if (nullTag!=cppdb::null_value)
        p->set_max(max);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
	} catch (std::exception const &e) {
		log_err("%d: construct_event_config(): t_event_config_sus: %s", __LINE__, e.what());
    return;
	}
	try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `data_type`, `min`, `max`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
      " FROM `t_event_config_black` t1, `t_event_list` t2, `t_event_status` t3"
      " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=5 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";
  
  	while(res.next()) {
    	res>>id>>cppdb::into(devid, devid_nullTag)>>data_type>>min>>cppdb::into(max, nullTag);
      	res>>weekday>>stime>>etime>>coverrange;
      	if (devid_nullTag==cppdb::null_value)
        	p = common_cfg.add_event();
      	else
      	{
        	try{
          	p = cfg[dev_to_agent.at(devid)].add_event();
          	p->set_devid(devid);
        	}catch (const std::out_of_range& oor) {
          	continue;
        	}
      	}

      p->set_type_id(5);
      p->set_config_id(id);
      p->set_data_type(data_type);
      p->set_min(min);
      if (nullTag!=cppdb::null_value)
        p->set_max(max);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_black: %s", __LINE__, e.what());
    return;
  }
	try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `ip`, `qname`, `qcount`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
      " FROM `t_event_config_dns` t1, `t_event_list` t2, `t_event_status` t3"
      " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=4 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";
  
  	while(res.next()) {
    	res>>id>>cppdb::into(devid, devid_nullTag)>>cppdb::into(ip, nullTag)>>cppdb::into(qname, nullTag)>>qcount;
      	res>>weekday>>stime>>etime>>coverrange;
      	if (devid_nullTag==cppdb::null_value)
        	p = common_cfg.add_event();
      	else
      	{
        	try{
          	p = cfg[dev_to_agent.at(devid)].add_event();
          	p->set_devid(devid);
        	}catch (const std::out_of_range& oor) {
          	continue;
        	}
      	}

      p->set_type_id(4);
      p->set_config_id(id);
      if (nullTag!=cppdb::null_value) 
        p->set_ip(ip);
      if (nullTag!=cppdb::null_value)
        p->set_qname(qname);
      p->set_qcount(qcount);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_dns: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `ip`, `namelen`, `fqcount`, `detvalue`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
      " FROM `t_event_config_dnstunnel` t1, `t_event_list` t2, `t_event_status` t3"
      " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=7 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>cppdb::into(ip, nullTag)>>namelen>>fqcount>>detvalue;
        res>>weekday>>stime>>etime>>coverrange;
        if (devid_nullTag==cppdb::null_value)
          p = common_cfg.add_event();
        else
        {
          try{
            p = cfg[dev_to_agent.at(devid)].add_event();
            p->set_devid(devid);
          }catch (const std::out_of_range& oor) {
            continue;
          }
        }

      p->set_type_id(7);
      p->set_config_id(id);
      if (nullTag!=cppdb::null_value)
        p->set_ip(ip);
      p->set_namelen(namelen);
      p->set_fqcount(fqcount);
      p->set_detvalue(detvalue);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_dns_tunnel: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `type`, `min`, `pat`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
                  " FROM `t_event_config_url_content` t1, `t_event_list` t2, `t_event_status` t3"
                  " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=9 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>sub_type>>min>>pat>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(9);
      p->set_config_id(id);
      p->set_sub_type((Event::Ctype)sub_type);
      p->set_min(min);
      p->set_pat(pat);
      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_url_content: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `sip`, `dip`, `min`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
                  " FROM `t_event_config_frn_trip` t1, `t_event_list` t2, `t_event_status` t3"
                  " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=10 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>sip>>dip>>min>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(10);
      p->set_config_id(id);
      p->set_sip(sip);
      p->set_dip(dip);
      p->set_min(min);
      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_frn_trip: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `sip`, `dip`, `IF1`, `IF2`, `IF3`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
                  " FROM `t_event_config_icmp_tunnel` t1, `t_event_list` t2, `t_event_status` t3"
                  " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=11 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>sip>>dip>>if1>>if2>>if3>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(11);
      p->set_config_id(id);
      p->set_sip(sip);
      p->set_dip(dip);
      p->set_if1(if1);
      p->set_if2(if2);
      p->set_if3(if3);
      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_icmp_tunnel: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `sip`, `dip`, `min`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
                  " FROM `t_event_config_dnstun_ai` t1, `t_event_list` t2, `t_event_status` t3"
                  " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`=14 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>sip>>dip>>min>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(14);
      p->set_config_id(id);
      p->set_sip(sip);
      p->set_dip(dip);
      p->set_min(min);
      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_dnstun_ai: %s", __LINE__, e.what());
    return;
  }

  try {
    res = *sql << "SELECT t1.`config_id`, t1.`devid`, t1.`weekday`, t1.`stime`, t1.`etime`, t1.`coverrange` FROM `t_event_list` t1, `t_event_status` t2"
                  " WHERE t1.`type_id` = 15 AND t1.`status_id` = t2.`id` AND t2.`status` = 'ON'";
    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(15);
      p->set_config_id(id);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    return;
  }

  try {
    res = *sql << "SELECT t1.`config_id`, t1.`devid`, t1.`weekday`, t1.`stime`, t1.`etime`, t1.`coverrange` FROM `t_event_list` t1, `t_event_status` t2"
                  " WHERE t1.`type_id` = 13 AND t1.`status_id` = t2.`id` AND t2.`status` = 'ON'";
    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>weekday>>stime>>etime>>coverrange;
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(13);
      p->set_config_id(id);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    return;
  }

  try {
    res = *sql << "SELECT t1.`id`, t2.`devid`, `sip`, `dip`, `qcount`, `min`, t2.`weekday`, t2.`stime`, t2.`etime`, t2.`coverrange` "
      " FROM `t_event_config_dga` t1, `t_event_list` t2, `t_event_status` t3"
      " WHERE t1.`id`=t2.`config_id` AND t2.`type_id`= 12 AND t2.`status_id`=t3.`id` AND t3.`status`='ON' ";

    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag)>>cppdb::into(sip, nullTag)>>cppdb::into(dip, nullTag)>>qcount>>min;
        res>>weekday>>stime>>etime>>coverrange;
        if (devid_nullTag==cppdb::null_value)
          p = common_cfg.add_event();
        else
        {
          try{
            p = cfg[dev_to_agent.at(devid)].add_event();
            p->set_devid(devid);
          }catch (const std::out_of_range& oor) {
            continue;
          }
        }

      p->set_type_id(12);
      p->set_config_id(id);
      if (nullTag!=cppdb::null_value)
        p->set_sip(sip);
      if (nullTag!=cppdb::null_value)
        p->set_dip(dip);
      p->set_qcount(qcount);
      p->set_min(min);

      set_weekday(p, weekday);
      set_stime(p, stime);
      set_etime(p, etime);
      set_coverrange(p, coverrange);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_dga: %s", __LINE__, e.what());
    return;
  }
  /*try {
    res = *sql << "SELECT t1.`id`, t1.`devid` FROM `t_event_list` t1, `t_event_status` t2"
                  " WHERE t1.`type_id` = 13 AND t1.`status_id` = t2.`id` AND t2.`status` = 'ON'";
    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag);
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(13);
      p->set_config_id(id);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_dark: %s", __LINE__, e.what());
    return;
  }
  try {
    res = *sql << "SELECT t1.`id`, t1.`devid` FROM `t_event_list` t1, `t_event_status` t2"
                  " WHERE t1.`type_id` = 14 AND t1.`status_id` = t2.`id` AND t2.`status` = 'ON'";
    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag);
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(14);
      p->set_config_id(id);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_mining: %s", __LINE__, e.what());
    return;
  }
  try {
    res = *sql << "SELECT t1.`id`, t1.`devid` FROM `t_event_list` t1, `t_event_status` t2"
                  " WHERE t1.`type_id` = 15 AND t1.`status_id` = t2.`id` AND t2.`status` = 'ON'";
    while(res.next()) {
      res>>id>>cppdb::into(devid, devid_nullTag);
      if (devid_nullTag==cppdb::null_value)
        p = common_cfg.add_event();
      else {
        try{
          p = cfg[dev_to_agent.at(devid)].add_event();
          p->set_devid(devid);
        }catch (const std::out_of_range& oor) {
          continue;
        }
      }

      p->set_type_id(15);
      p->set_config_id(id);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_event_config(): t_event_config_mining: %s", __LINE__, e.what());
    return;
  }*/

}

static inline void construct_asset_config(Config& common_cfg) {
  PolicyIndex *pi;
  PolicyData  *pd;

  pi = common_cfg.add_policy_index();
  pi->set_policy(ASSET);
  pi->set_format(EMBEDDED);
  pi->add_policy_data_label("asset");

  string ip;
  u32    devid;
  cppdb::null_tag_type ip_nullTag, devid_nullTag;
  DataItem *p;

  pd = common_cfg.add_policy_data();
  pd->set_label("asset");
  pd->set_format(ITEM);
  cppdb::result res;
  try {
    res = *sql << "SELECT `ip`, `devid` FROM `t_internal_ip_list`";
    while (res.next()) {
      res>>cppdb::into(ip, ip_nullTag)>>cppdb::into(devid, devid_nullTag);
      p = pd->add_item();
      if (ip_nullTag!=cppdb::null_value)
        p->set_ip(ip);
      if (devid_nullTag!=cppdb::null_value)
        p->set_devid(devid);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_asset_config(): t_internal_ip_list: %s", __LINE__, e.what());
    return;
  }
}

////////////////////////////////////////////////////////////////////////////
static inline void construct_bwlist_config(Config& common_cfg){
  PolicyIndex *pi;
  PolicyData  *pd;

  pi = common_cfg.add_policy_index();
  pi->set_policy(BLACK);
  pi->set_format(EMBEDDED);
  pi->add_policy_data_label("black");

  pi = common_cfg.add_policy_index();
  pi->set_policy(WHITE);
  pi->set_format(EMBEDDED);
  pi->add_policy_data_label("white");

  string ip;
  u32    port;
  cppdb::null_tag_type ip_nullTag, port_nullTag;
  DataItem *p;

  pd = common_cfg.add_policy_data();
  pd->set_label("black");
  pd->set_format(ITEM);
  cppdb::result res;
  try {
    res = *sql << "SELECT `ip`, `port` FROM `t_blacklist`";
    while (res.next()) {
      res>>cppdb::into(ip, ip_nullTag)>>cppdb::into(port, port_nullTag);
      p = pd->add_item();
      if (ip_nullTag!=cppdb::null_value)
        p->set_ip(ip);
      if (port_nullTag!=cppdb::null_value)
        p->set_port(port);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_bwlist_config(): t_blacklist: %s", __LINE__, e.what());
    return;
  }

  pd = common_cfg.add_policy_data();
  pd->set_label("white");
  pd->set_format(ITEM);
  try {
    res = *sql << "SELECT `ip`, `port` FROM `t_whitelist`";
    while (res.next()) {
      res>>cppdb::into(ip, ip_nullTag)>>cppdb::into(port, port_nullTag);
      p = pd->add_item();
      if (ip_nullTag!=cppdb::null_value)
        p->set_ip(ip);
      if (port_nullTag!=cppdb::null_value)
        p->set_port(port);
    }
  } catch (std::exception const &e) {
    log_err("%d: construct_bwlist_config(): t_whitelist: %s", __LINE__, e.what());
    return;
  }
}

static inline void construct_other_policies(Config& common_cfg) {
  PolicyIndex *pi;

  pi = common_cfg.add_policy_index();
  pi->set_policy(POP);
  pi->set_storage("pop_service");
  pi->set_format(CSV);
  pi->add_policy_data_label("pop");

  pi = common_cfg.add_policy_index();
  pi->set_policy(SUS);
  pi->set_storage("sus_threat");
  pi->set_format(CSV);
  pi->add_policy_data_label("sus");

  pi = common_cfg.add_policy_index();
  pi->set_policy(I_PORT_SCAN);
  pi->set_format(NONE);
  pi->add_policy_data_label("i_port_scan");

  pi = common_cfg.add_policy_index();
  pi->set_policy(I_IP_SCAN);
  pi->set_format(NONE);
  pi->add_policy_data_label("i_ip_scan");

  pi = common_cfg.add_policy_index();
  pi->set_policy(I_SRV);
  pi->set_format(NONE);
  pi->add_policy_data_label("i_srv");
}

////////////////////////////////////////////////////////////////////////////
static void push() {
  Config common_cfg;

  cppdb::result res;
  try {
    res = *sql << "select name,value from t_config";

    while (res.next()) {
      string name, value;
      res >> name >> value;
      if (name == "controller_host") common_cfg.mutable_controller()->set_host(value);
      if (name == "controller_port") common_cfg.mutable_controller()->set_port(value);
    }
  } catch (std::exception const &e) {
    log_err("%d: push(): t_config: %s", __LINE__, e.what());
    return;
  }
 
  map<u32,Config> configs;
  map<u32,string> agentips;
  map<u32,u32> dev_to_agent;
  string devname;
  try {
    res = *sql << "select t1.id,t1.name,t1.type,t2.id,t2.ip,t1.ip,t1.port,t1.disabled,t1.flowtype,t1.model "
                  "from t_device t1 join t_agent t2 on t1.agentid = t2.id ";
    u32 devid, agentid, port;
    string devtype, devip, agentip, disabled;
    string flowtype;
    string devmodel;
    while (res.next()) {
      res >> devid >> devname >> devtype >> agentid >> agentip >> devip >> port
          >> disabled >> flowtype >> devmodel;
      agentips[agentid] = agentip;
      Config& p = configs[agentid];
      auto dev = p.add_dev();
      dev->set_id(devid);
      dev->set_name(devname);
      dev->set_type(devtype);
      dev->set_agentid(agentid);
      dev->set_ip(devip);
      dev->set_port(port);
      dev->set_disabled(disabled == "Y");
      dev->set_flowtype(flowtype);
      dev->set_model(boost::to_upper_copy(devmodel));

      dev_to_agent[devid] = agentid;
    }
  } catch (std::exception const &e) {
    log_err("%d: push(): t_device, t_agent: %s", __LINE__, e.what());
    return;
  }

  construct_cfg_mo(common_cfg, configs, dev_to_agent);

  construct_event_config(common_cfg, configs, dev_to_agent);

  construct_bwlist_config(common_cfg);

  construct_asset_config(common_cfg);

  construct_other_policies(common_cfg);

  for (auto it = agentips.cbegin(); it != agentips.cend(); ++it) {
    string url = "http://" + it->second + ":10081/config_updater";
    auto& cfg = configs[it->first];
    cfg.MergeFrom(common_cfg);
    string cfg_str;
    if (!google::protobuf::TextFormat::PrintToString(cfg, &cfg_str)) {
      log_err("%d: Unable to print device %s config\n", __LINE__, devname.c_str());
    }
    http_post(url, cfg_str);

    if (debug)
      cout<<"Agent: "<<it->second<<endl<<cfg_str<<endl;
  }
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  close(0);

  if (argc>1){
    if (argv[1][0]=='d')
      debug=1;
  }

  try {
    sql = start_db_session();
    if (!sql) return 1;
    push();
  } catch (std::exception const &e) {
   log_err("%d: %s\n", __LINE__, e.what());
  }

  if (sql){
    sql->close();
    delete sql;
  }

  return 0;
}
