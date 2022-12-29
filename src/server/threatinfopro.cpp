#include "../common/common.h"
#include "../common/log.h"
#include "../common/ini.h"
#include "../common/tic.h"
#include "define.h"

#include <curl/curl.h>
#include <Cgicc.h>
#include <cgicc/HTTPContentHeader.h>
#include <cgicc/HTTPStatusHeader.h>

#define REMOTE_URL "/processor/threatinfopro"

using namespace std;
using namespace cgicc;

static bool dbg = false;

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
	((ostream*)stream)->write((const char*)ptr, size*nmemb);
	return size*nmemb;
}

long post_data(const string& url, const void* buf, size_t size, ostream* stream)
{
	CURL *curl;
	CURLcode res;
	curl = curl_easy_init();
	if (!curl) return -1;

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, size);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); //set timeout limit in seconds
	if (dbg)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	if (stream) {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, stream);
	}

	// not verify https
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	/* Check for errors */
	if(res != CURLE_OK)
		log_err("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

	long response_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

	/* always cleanup */
	curl_easy_cleanup(curl);

	return response_code;
}

static int fail(long code = 403, const string& data = "Parameters parsed error"){
	cout<<HTTPStatusHeader(code, "failed");
	cout<<data<<endl;

	return -1;
}

static int succeed(const string& data) {
	cout<<HTTPContentHeader("application/javascript;");
	cout<<data<<endl;

	return 0;
}

int main(int argc, char *argv[]) {
	bool is_http = getenv("REMOTE_ADDR") != NULL;

	Cgicc cgi;

	if ( !cgi("token").empty() )
		return fail();

	const CgiEnvironment & cgie = cgi.getEnvironment();

	Ini ini;
	ini.LoadFromFile(TIC_CONF);	
	string key = ini.Get("API_KEY","");
	string token = tic::generate_token_from_key(key);
	if (token=="")
		return fail(403, "token invalid");

	string postdata;
	if (cgie.getRequestMethod()=="GET")
		postdata = cgie.getQueryString();
	else if (cgie.getRequestMethod()=="POST")
		postdata = cgie.getPostData();
	else if ( !is_http && argc>1 ){
		postdata = argv[1];
		if (argc>2 && argv[2][0]=='D')
			dbg = true;
	}
	else
		return fail();

	postdata += "&token=";
	postdata += token;

	ostringstream os;
	string host = ini.Get("HOST","");
	string port = ini.Get("PORT","");
	string url = "https://" + host + ":" + port;
	url += REMOTE_URL;

	if (dbg) {
		cout<<"url: "<<url<<endl;
		cout<<"postdata: "<<postdata<<endl;
	}

	long code = post_data(url, postdata.c_str(), postdata.size(), &os);
	if (code==200)
		return succeed(os.str());
	else if (code>0)
		return fail(code, os.str());
	else
		return fail(500, "Server internal error");

}
