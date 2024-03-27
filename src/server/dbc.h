#ifndef DBC_H
#define DBC_H

#include "define.h"
#include <cppdb/frontend.h>
#include <string>
#include "../common/_strings.h"

using namespace cppdb;
using namespace std;

cppdb::session* start_db_session();

#endif
