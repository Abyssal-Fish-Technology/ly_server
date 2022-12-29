#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include <Cgicc.h>
#include "../common/strings.h"
#include "../common/csv.hpp"
#include <map>
#include <string>
#include <set>

const char data_file[] = SERVER_DATA_DIR "/ip_data";  // Default: "/Server/data/ip_data" Format:csv

using namespace std;
using namespace csv;


static bool is_http = false;

////////////////////////////////////////////////////////////////////////////
static void inline output_string(ostream& out, const string& name, const string& value) 
{
  out << '"' << name << "\":\"" << value << '"'; 
}



static bool init_ip_data(char* &data_ptr) {

  struct stat info;
  stat(data_file,&info);
  int size=info.st_size;

  FILE* file = fopen(data_file, "rb");
  if(file == NULL) {
    cout << "open error!" << endl;
    return false;
  }
  data_ptr = (char*)malloc(size*sizeof(char));
  if(data_ptr == NULL) {
    cout << "malloc error" << endl;
    return false;
  }
  int n = fread(data_ptr, 1, size, file);
  if(n != size) {
    cout << "read error" << endl;
    return false;
  }

  fclose(file);
  return true;
}

////////////////////////////////////////////////////////////////////////////
static void process()
{
  if (is_http) printf("Content-Type: application/javascript; charset=utf-8\r\n\r\n");

  char* ip_data_ptr;
  if (!init_ip_data(ip_data_ptr)){
    cout<<"[]"<<endl;
    return;
  }
  string data = ip_data_ptr;

  cgicc::Cgicc cgi;
  std::stringstream iplist(cgi("iplist"));
  //remove repeat ip
  set <string> ip_set;
  string ori_ip;
  while (std::getline(iplist, ori_ip, ',')) {
    ip_set.insert(ori_ip);
  } 

  set <string> ::iterator iter;
  bool first = true;
  cout << '[';
  for (iter=ip_set.begin(); iter!=ip_set.end(); ++iter) {
    const string& ip = *iter;
    //check
    if (ip.empty()) {
      continue;
    }
    //find
    string whole_ip = "\n" + ip + ",";
    int ip_head = data.find(whole_ip);
    //if hit
    if (ip_head >= 0) {
      int type_head = ip_head + whole_ip.size();
      int type_tail = data.find("\n", type_head);
      const string& type = data.substr(type_head, (type_tail - type_head));
      //output
      if (first) {
        first = false;
      }
      else {
        cout << ","<<endl;
      }
      cout<<"{";
      output_string(cout, "ip", ip);
      cout<<",";
      output_string(cout, "class", type);
      cout<<"}";
    }
  }
  cout << ']'<<endl;

  free(ip_data_ptr);
  return;
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
