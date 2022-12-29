#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include <Cgicc.h>
#include "../common/ipip.hpp"
#include "../common/regex_validation.hpp"

const char ipip_file[] = SERVER_DATA_DIR "/loc_data";  // Default: "/Server/data/loc_data" Format:dat

using namespace std;
using namespace ipip::dat;

static bool is_http = false;

////////////////////////////////////////////////////////////////////////////
static void inline output_string(stringstream& out, const string& name, const string& value) 
{
  out << '"' << name << "\":\"" << value << '"'; 
}

string ipip_query(string ip) {
  char buf[512];
  find(ip.c_str(), buf);

  string result = "[\"" + string(buf) + "\"]";
  stringstream output;
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

////////////////////////////////////////////////////////////////////////////
static void process()
{
  if (is_http) printf("Content-Type: application/javascript; charset=utf-8\r\n\r\n");

  cgicc::Cgicc cgi;

  init(ipip_file);

  std::stringstream iplist(cgi("iplist"));
  string ipstr;
  bool first = true;
  cout << '[' <<endl;
  while (std::getline(iplist, ipstr, ',')) {
    if (!is_valid_ip(ipstr))
      continue;

    string result = ipip_query(ipstr);

    if (!first) cout << ","<<endl;
    first = false;
    cout << result << "\n";
  }
  cout << ']';

  destroy();
}

////////////////////////////////////////////////////////////////////////////
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
