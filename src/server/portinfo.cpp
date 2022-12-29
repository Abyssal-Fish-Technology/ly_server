#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include <Cgicc.h>
#include "../common/strings.h"
#include "../common/csv.hpp"
#include <map>

const char data_file[] = SERVER_DATA_DIR "/port_data";  // Default: "/Server/data/port_data" Format:csv

using namespace std;
using namespace csv;

typedef struct {
  
} port_data_t;

static bool is_http = false;

static map<int, vector< vector<string> > > port_data;

////////////////////////////////////////////////////////////////////////////
static void inline output_string(ostream& out, const string& name, const string& value) 
{
  out << '"' << name << "\":\"" << value << '"'; 
}

////////////////////////////////////////////////////////////////////////////
static void inline output_u64(ostream& out, const string& name, const u64 value) 
{
  out << '"' << name << "\":" << value; 
}

static bool init_port_data() {
  ifstream in(data_file);
  if (!in.is_open()) {
    log_err(__FILE__": failed to load port data: %s\n", data_file);
    return false;
  }

  string line;
  vector<string> vec;

  while (getline(in,line)) {
    fill_vector_from_line(vec, line);
    if (vec.size()!=5)
      continue;
    int port = -1;
    try {
      port = stol(trim(vec[0]));
    } catch (std::exception const &e) {
      // log_err(__FILE__":%s\n", e.what());
      continue;
    }
    if (port<0||port>65535)
      continue;

    port_data[port].push_back(vec);
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  if (is_http) printf("Content-Type: application/javascript; charset=utf-8\r\n\r\n");

  cgicc::Cgicc cgi;

  if (!init_port_data()){
    cout<<"[]"<<endl;
    return;
  }

  std::stringstream portlist(cgi("portlist"));
  string str;
  bool first = true;
  cout << '[';
  while (std::getline(portlist, str, ',')) {
    int port = -1;
    try {
      port = stol(str);
    } catch (std::exception const &e) {
      // log_err(__FILE__":%s\n", e.what());
      continue;
    }

    if (port<0||port>65535)
      continue;

    if (port_data.count(port)) {
      const auto& p = port_data[port];
      for (u32 i=0;i<p.size();i++){
        const vector<string>& v = p[i];

        if (!first) cout << ","<<endl;
        first = false;

        cout<<"{";
        output_u64(cout, "port", port);
        cout<<",";
        output_string(cout, "protocol", v[1]);
        cout<<",";
        output_string(cout, "source", v[3]);
        cout<<",";
        output_string(cout, "desc", v[2]);
        cout<<",";
        output_string(cout, "activity", v[4]);
        cout<<"}";
      }
    }
    else {
      if (!first) cout << ","<<endl;
      first = false;

      cout<<"{\"port\":"<<port<<",\"protocol\":\"\",\"source\":\"\",\"desc\":\"\",\"activity\":\"\"}";
    }
    
  }
  cout << ']';
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
