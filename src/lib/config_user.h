#ifndef CONFIG_USER_H
#define CONFIG_USER_H

#include "config_class.h"
#include "config_user.pb.h"

#define SESSION_LEN 32

namespace config {
  
/////////////////////////////////////////////////////////
class ConfigUser: public Config {
public:
  ConfigUser(const std::string& type, cppdb::session* sql);
  ~ConfigUser();

  virtual bool Process(cgicc::Cgicc& cgi);

protected:
  virtual bool ParseReq(cgicc::Cgicc& cgi);
  virtual bool ValidateRequest();

private:
  bool Add();
  bool Del();
  bool Mod();
  bool Get();

protected:
  google::protobuf::Message *_req;
  
  enum Op {
    ADD = 1,
    DEL,
    MOD,
    GET
  } _op;
};  

} //namespace config

#endif
