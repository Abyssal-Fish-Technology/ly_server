#include "../common/common.h"
#include "../common/log.h"
#include "../common/mo_req.h"
#include "define.h"
#include "dbc.h"
#include <cppdb/frontend.h>
#include <Cgicc.h>

using namespace std;
using namespace cppdb;
using namespace mo;

static cppdb::session* sql;
static bool is_http = false;
static mo::MoReq req;
stringstream output;

////////////////////////////////////////////////////////////////////////////
static void inline output_string(stringstream& out, const string& name, const string& value) 
{
  out << '"' << name << "\":\"" << value << '"'; 
}

////////////////////////////////////////////////////////////////////////////
static void inline output_u64(stringstream& out, const string& name, const u64 value) 
{
  out << '"' << name << "\":" << value; 
}

////////////////////////////////////////////////////////////////////////////
static bool op_add(MoReq* req){

  if (!sql) return false;

  cppdb::statement st = *sql << "insert into t_mo(moip,moport,protocol,pip,pport,modesc,tag,mogroupid,filter,devid,direction) value(?,?,?,?,?,?,?,?,?,?,?)";

  st<<req->moip();
  st<<req->moport();
  st<<req->protocol();
  st<<req->pip();
  st<<req->pport();
  st<<req->desc();
  st<<req->tag();
  st<<req->mogid();
  string filter = genMoFilter(req);
  st<<filter;
  if (req->has_devid()&&req->devid()!="")
    st<<atoll(req->devid().c_str());
  else
    st<<cppdb::null;
  st<<req->direction();

  try{
    st<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  system("/Server/bin/config_pusher >> /dev/null 2>&1");
  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_del(MoReq* req){
  if (!sql) return false;

  try {
    string id = req->moid();
    int count = 0;
    int c = 1;
    for (unsigned i = 0; i < id.size(); i++){
      if (id[i]==',')
        c++;
    }

    cppdb::result r = *sql << "SELECT COUNT(*) FROM `t_mo` WHERE `id` IN (" + req->moid() + ")";
    if (r.next())
      r >> count;
    if (count!=c)
      return false;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  string str;
  str="delete from t_mo where ( ";
  stAddWhere(str,"1 = 1");
  if (req->has_moid())
    stAddWhere(str,string("id in (") + req->moid() + ")");
  composeWhereSt(str, req);
  str+=" )";

  cppdb::statement st = *sql <<str;
  bindWhereSt(st, req);

  try{
    st<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  system("/Server/bin/config_pusher >> /dev/null 2>&1");

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_mod(MoReq* req){

  if (!sql) return false;

  string str;
  str="update t_mo set ";
  if (req->has_moip())
    stAddUpdateSet(str,"moip = ?");
  if (req->has_moport())
    stAddUpdateSet(str,"moport = ?");
  if (req->has_protocol())
    stAddUpdateSet(str,"protocol = ?");
  if (req->has_pip())
    stAddUpdateSet(str,"pip = ?");
  if (req->has_pport())
    stAddUpdateSet(str,"pport = ?");
  if (req->has_desc())
    stAddUpdateSet(str,"modesc = ?");
  if (req->has_tag())
    stAddUpdateSet(str,"tag = ?");
  if (req->has_mogid())
    stAddUpdateSet(str,"mogroupid = ?");
  if (req->has_devid())
    stAddUpdateSet(str,"devid = ?");
  if (req->has_direction())
    stAddUpdateSet(str,"direction = ?");

  str+=" where ( ";
  stAddWhere(str, string("id = ") + req->moid() );
  str+=" )";

  cppdb::statement st;
  try{
    st = *sql <<str;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  if (req->has_moip())
    st<<req->moip();
  if (req->has_moport())
    st<<req->moport();
  if (req->has_protocol())
    st<<req->protocol();
  if (req->has_pip())
    st<<req->pip();
  if (req->has_pport())
    st<<req->pport();
  if (req->has_desc())
    st<<req->desc();
  if (req->has_tag())
    st<<req->tag();
  if (req->has_mogid())
    st<<req->mogid();
  if (req->has_devid()){
    if (req->devid()=="")
      st<<cppdb::null;
    else
      st<<atoll(req->devid().c_str());
  }
  if (req->has_direction())
    st<<req->direction();

  try{
    st<<cppdb::exec;

    cppdb::result r = *sql<< string("select moip, moport, protocol, pip, pport, direction from t_mo where id = ") + req->moid();
    string moip, moport, proto, pip, pport, direction;

    if (!r.next())
      return false;
    r>>moip>>moport>>proto>>pip>>pport>>direction;
    MoReq tmp;
    tmp.set_moip(moip);
    tmp.set_moport(moport);
    tmp.set_protocol(proto);
    tmp.set_pip(pip);
    tmp.set_pport(pport);
    tmp.set_direction(direction);
    tmp.set_filter(req->filter());
    str = string("update t_mo set filter=? where id = ")+req->moid();
    st = *sql<<str<<genMoFilter(&tmp)<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  system("/Server/bin/config_pusher >> /dev/null 2>&1");

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_get(MoReq* req){
  if (!sql) return false;

  string str;
  str="select t1.id, moip, moport, protocol, pip, pport, modesc, tag, t2.name, addtime, filter, t1.devid, direction from t_mo t1, t_mogroup t2 where ( ";
  stAddWhere(str,"t1.mogroupid = t2.id");
  if (req->has_moid())
    stAddWhere(str,string("t1.id in (") + req->moid() + ")");
  if (req->has_mogid())
    stAddWhere(str,"t2.id = ?");
  composeWhereSt(str, req);
  str+=" ) order by t1.id";

  cppdb::statement st = *sql <<str;
  if (req->has_mogid())
    st<<req->mogid();
  bindWhereSt(st, req);

  try{
    cppdb::null_tag_type nullTag;
    cppdb::result r = st;
    string s;
    u32 u=0;
    struct tm t;
    bool first = true;

    while(r.next()){
      if (first)
        first=false;
      else
        output<<","<<endl;

      output<<"{";

      r>>u;
      output_u64(output, "id", u);
      output<<',';

      r>>s;
      output_string(output, "moip", s);
      output<<',';

      r>>s;
      output_string(output, "moport", s);
      output<<',';

      r>>s;
      output_string(output, "protocol", s);
      output<<',';

      r>>s;
      output_string(output, "pip", s);
      output<<',';

      r>>s;
      output_string(output, "pport", s);
      output<<',';

      r>>s;
      output_string(output, "desc", s);
      output<<',';

      r>>s;
      output_string(output, "tag", s);
      output<<',';

      r>>s;
      output_string(output, "mogroup", s);
      output<<',';

      r>>t;
      u=mktime(&t);
      output_u64(output, "addtime", u);
      output<<',';

      r>>s;
      output_string(output, "filter", s);
      output<<',';

      r>>cppdb::into(u,nullTag);
      if (nullTag==cppdb::null_value)
        output_string(output, "devid", "");
      else
        output_string(output, "devid", to_string(u));
      output<<',';

      r>>s;
      output_string(output, "direction", s);

      output<<"}";

      // output<<pb2json(rec);
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_gadd(MoReq* req){

  if (!sql) return false;
  try{
      *sql<<"insert into t_mogroup(name) value(?)"<<req->mogroup()<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_gdel(MoReq* req){
  int c=1;

  if (!sql) return false;
  try{
    if (req->has_mogroup()) {
      cppdb::result r = *sql<<"select count(*) from t_mo t1, t_mogroup t2 where ( t1.mogroupid=t2.id and t2.name=? )"<<req->mogroup();
      if (r.next())
        r>>c;
      if (c>0)
        return false;
    }
    if (req->has_mogid()) {
      cppdb::result r = *sql<<"select count(*) from t_mo where mogroupid=?"<<req->mogid();
      if (r.next())
        r>>c;
      if (c>0)
        return false;
    }

    string str = "delete from t_mogroup where (";
    if (req->has_mogid())
      stAddWhere(str, "id = ?");
    if (req->has_mogroup())
      stAddWhere(str, "name = ?");
    str += ")";

    cppdb::statement st = *sql <<str;
    if (req->has_mogid())
      st<<req->mogid();
    if (req->has_mogroup())
      st<<req->mogroup();
    st<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  return true;
}


static bool op_gmod(MoReq* req){
  if (!sql) return false;

  cppdb::statement st;
  try{
    st = *sql << "UPDATE `t_mogroup` SET `name` = ? WHERE `id` = ?" << req->mogroup() << req->mogid();
    st<<cppdb::exec;
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_gget(MoReq* req){
  if (!sql) return false;
  try{
    cppdb::result r;
    
    if ( !req->has_mogid() && !req->has_mogroup() )
      r=*sql<<"select * from t_mogroup";
    else{
      string str = "select * from t_mogroup where (";
      if (req->has_mogid())
        stAddWhere(str, "id = ?");
      if (req->has_mogroup())
        stAddWhere(str, "name = ?");
      str += ")";

      cppdb::statement st = *sql <<str;
      if (req->has_mogid())
        st<<req->mogid();
      if (req->has_mogroup())
        st<<req->mogroup();
      r=st;
    }

    string name;
    u32 id;
    bool first = true;

    while(r.next()){
      if (first)
        first=false;
      else
        output<<","<<endl;

      r.fetch("id",id);
      r.fetch("name",name);

      output<<'{';
      output_u64(output, "id", id);
      output<<',';
      output_string(output, "name", name);
      output<<'}';
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool op_get_filter(MoReq* req){

  if (!sql) return false;
  try{
    cppdb::result r;

    if ( !req->has_moid() )
      r=*sql<<"select * from t_mo";
    else{
      string str = "select * from t_mo where ( id = ? )";
      r=*sql <<"select * from t_mo where ( id = ? )"<<req->moid();
    }

    string filter;
    u64 id;
    bool first = true;

    while(r.next()){
      if (first)
        first=false;
      else
        output<<","<<endl;

      r.fetch("id",id);
      r.fetch("filter",filter);

      output<<'{';
      output_u64(output, "id", id);
      output<<',';
      output_string(output, "filter", filter);
      output<<'}';
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
static void process(MoReq* req)
{
  bool succeed = false;

  if (!validate_request(req)){
    output<<"[{failed}]"<<endl;
    return;
  }

  output<<'[';
  switch (req->op()){
    case MoReq::ADD:succeed = op_add(req);break;
    case MoReq::DEL:succeed = op_del(req);break;
    case MoReq::MOD:succeed = op_mod(req);break;
    case MoReq::GADD:succeed = op_gadd(req);break;
    case MoReq::GDEL:succeed = op_gdel(req);break;
    case MoReq::GMOD:succeed = op_gmod(req);break;
    case MoReq::GET:succeed = op_get(req);break;
    case MoReq::GGET:succeed = op_gget(req);break;
    case MoReq::GET_FILTER:succeed = op_get_filter(req);break;
    default:break;
  }

  switch (req->op()){
    case MoReq::ADD:
    case MoReq::DEL:
    case MoReq::MOD:
    case MoReq::GADD:
    case MoReq::GDEL:
    case MoReq::GMOD:
      if (!succeed)
        output<<"{failed}";
      else
        output<<"{executed}";
    default:break;
  }
  output<<']'<<endl;
}

////////////////////////////////////////////////////////////////////////////
void test(MoReq* req){
  req->set_op(MoReq::GET_FILTER);
  req->set_moid("1");
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  sql = NULL;
  is_http = getenv("REMOTE_ADDR") != NULL;
  output<<"Content-Type: application/json; charset=UTF-8\r\n\r\n";
  
  if (is_http) {
    cgicc::Cgicc cgi;
    ParseMoReqFromUrlParams(cgi, &req);
  } else {
    test(&req);
  }

  try {
    sql = start_db_session();
    process(&req);
  } catch (std::exception const &e) {
   log_err("%s\n", e.what());
  }
  cout<<output.str();
  if (sql){
    sql->close();
    delete sql;
  }
  return 0;
}
