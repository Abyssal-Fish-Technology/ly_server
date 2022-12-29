#include "../common/common.h"
#include "../common/log.h"
#include "define.h"
#include "dbc.h"
#include <cppdb/frontend.h>
#include <Cgicc.h>
#include <dlfcn.h>
#include "../lib/config_class.h"

const char log_file[] = SERVER_LOG_DIR "/" __FILE__;

using namespace std;
using namespace cppdb;

static bool is_http = false;

typedef config::Config* (*pf_t1)(const std::string&, cppdb::session*);
typedef void (*pf_t2)(config::Config*);

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
	config::Config *conf;

	setvbuf(stdout, NULL, _IOFBF, 81920);

	is_http = getenv("REMOTE_ADDR") != NULL;
	if (is_http) {
		std::cout << "Content-Type: application/javascript; charset=UTF-8\r\n\r\n";

		cgicc::Cgicc cgi;
		void *handle;
		char *error;
		pf_t1 createConfigInstance;
		pf_t2 freeConfigInstance;

		string so = SERVER_LIB_DIR "/config_";
		string type = cgi("type");
		so+=type.substr(0, type.find('_'));
		so+=".so";
		handle = dlopen(so.c_str(), RTLD_NOW);
		if (!handle) {
			cout << "[]"<<endl;
			log_err("%s", dlerror());
			return 1;
		}
		dlerror();
		createConfigInstance = (pf_t1)dlsym(handle,"CreateConfigInstance");
		if ((error = dlerror()) != NULL){
			cout << "[]"<<endl;
			log_err("%s", error);
			dlclose(handle);
			return 1;
		}
		freeConfigInstance = (pf_t2)dlsym(handle,"FreeConfigInstance");
		if ((error = dlerror()) != NULL){
			cout << "[]"<<endl;
			log_err("%s", error);
			dlclose(handle);
			return 1;
		}

		cppdb::session* sql = start_db_session();
		conf = createConfigInstance(type, sql);
		conf->Process(cgi);
		freeConfigInstance(conf);
		dlclose(handle);
		delete sql;
	} else {
		return 1;
	}

	return 0;
}
