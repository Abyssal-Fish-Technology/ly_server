#include "dbc.h"

cppdb::session* start_db_session() {

  string user = SERVER_DB_USER;
  string dbdatabase = SERVER_DB_NAME;
  string mysql_group = SERVER_DB_GROUP;
  string line;
  string str, pass;
  size_t pos;
  ifstream ifs(DB_CONF);
  while(getline(ifs, line)) {
    trim(line);
    if (line.empty() || line[0] == '#') continue;
    pos = line.find("=");
    if (pos != std::string::npos) {
      str = line.substr(0,pos);
      if (str == "passwd") {
        pass = line.substr(pos + 1);
        break;
      }
    } 
  }
  session* sql = new session("mysql:database=" + dbdatabase + ";read_default_group=" + mysql_group + ";user=" + user + ";password=" + pass);
  return sql;
}
