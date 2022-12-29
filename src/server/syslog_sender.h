#ifndef __SYSLOG_H__
#define __SYSLOG_H__

#include "../common/log.h"
#include "../common/strings.h"
#include "define.h"

using namespace std;

void send_event_syslog_process(u32 level_id, const string& event_str);

#endif


