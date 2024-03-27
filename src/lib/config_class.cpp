#include "config_class.h"
#include "../common/common.h"
#include "../common/log.h"
#include "../common/ip.h"
#include "../common/http.h"
#include "../common/_strings.h"

using namespace std;

namespace config {
// Config - Base Class
Config::Config(const std::string& type, cppdb::session* sql):_sql(sql),_type(type){}

bool Config::Process(cgicc::Cgicc& cgi){ return false; }

bool Config::Process(int argc, char**argv){ PrintCmdUsage(argv[0]); return false; }

void Config::PrintCmdUsage(const std::string& name){ cout<<"Print cmdline usage here."<<endl; }

void Config::stAddUpdateSet(string& str, const string s){
  static bool first=true;

  if (first){
    str+=s;
    first=false;
  }
  else
    str+=", "+s;
}

void Config::stAddWhere(string& str, const string s){
  static bool first=true;

  if (first){
    str+=s;
    first=false;
  }
  else
    str+=" and "+s;
}

void Config::output_string(const std::string& name, const std::string& value) {
  std::cout << '"' << name << "\":\"" << value << '"'; 
}

void Config::output_u64(const std::string& name, const unsigned long long value) {
  std::cout << '"' << name << "\":" << value;
}

void Config::output_null(const std::string& name) {
  std::cout << '"' << name << "\": null";
}

void Config::output_float(const std::string& name, const float value) {
  std::cout << '"' << name << "\": " << value;
}

bool Config::Executed(const std::string& str){
  std::cout<<"{"<<str<<"}";
  return true;
}

bool Config::Failed(const std::string& str){
  std::cout<<"{"<<str<<"}";
  return false;
}

} // namespace config
