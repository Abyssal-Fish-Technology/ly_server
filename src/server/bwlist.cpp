#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include "dbc.h"
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <dlfcn.h>
#include "../lib/config_bwlist.pb.cc"
#include "../lib/config_class.cpp"
#include "../lib/config_bwlist.cpp"

using namespace std;
using namespace cppdb;

static bool is_http = false;

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
	config::Config *conf;
	string type = "bwlist";

	setvbuf(stdout, NULL, _IOFBF, 81920);

	is_http = getenv("REMOTE_ADDR") != NULL;
	if (is_http) {
		std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";

		cgicc::Cgicc cgi;

		cppdb::session* sql = start_db_session();
		conf = CreateConfigInstance(type, sql);
		conf->Process(cgi);
		FreeConfigInstance(conf);
		delete sql;
	} else {
		return 1;
	}

	return 0;
}
