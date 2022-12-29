#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include <Cgicc.h>
#include "../common/ipip.hpp"
#include "../common/regex_validation.hpp"

const char ipdb_file[] = SERVER_DATA_DIR "/geo_data";

using namespace std;
using namespace ipip::ipdb;

static bool is_http = false;

static void inline output_string(stringstream& out, const string& name, const string& value)
{
  out << '"' << name << "\":\"" << value << '"';
}


static string ipip_query(string& ip, ipdb_reader *reader, const char *language) {
  char body[512];

  stringstream output;
  int err = ipdb_reader_find(reader, ip.c_str(), language, body);
  if (err) return "";      

  string result = "[\"" + string(body) + "\"]";
  output<<"{";
  output_string(output, "ip", ip);
  output<<",";

  int pos = result.find('\t');
  while (pos!=-1){
    result.replace(pos, 1, "\",\"");
    pos = result.find('\t');
  }
  output<<"\"result\": "<<result;
  output<<"}";
  
  return output.str(); 
}


static void process() {
  if (is_http) std::cout << "Content-Type: application/javascript; charset=utf-8\r\n\r\n";
  cgicc::Cgicc cgi;

  const char *lang[2] = {"CN", "EN"};
  ipdb_reader *reader;
  int err = ipdb_reader_new(ipdb_file, &reader); 
  if (err) {
    log_err("ipdb reader init faild.\n");
    return;
  } 

  std::stringstream iplist(cgi("iplist"));
  string ipstr;
  bool first = true;
  cout << '[' <<endl;
  while (std::getline(iplist, ipstr, ',')) {
    if (!is_valid_ip(ipstr))
      continue;

    for (int i = 0; i < 2; ++i) {
      string result = ipip_query(ipstr, reader, lang[i]);
      if (result.size() == 0) continue;

      if (!first) cout << ","<<endl;
      first = false;
      cout << result << "\n";
    }
  }
  cout << ']';   


}


int main(int argc, char *argv[])
{
  is_http = getenv("REMOTE_ADDR") != NULL;

  try {
    process();
  } catch (std::exception const &e) {
    log_err(__FILE__":%s\n", e.what());
  }
  return 0;
}
