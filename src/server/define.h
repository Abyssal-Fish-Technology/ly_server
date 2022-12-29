#ifndef SERVER_WORK_DIR
#  define SERVER_WORK_DIR		"/Server"
#endif

#define SERVER_TMP_DIR		SERVER_WORK_DIR"/tmp"
#define SERVER_DATA_DIR		SERVER_WORK_DIR"/data"
#define SERVER_LOG_DIR		SERVER_WORK_DIR"/log"
#define SERVER_COMMON_LOG	SERVER_LOG_DIR"/common"
#define SERVER_CMD_LOG		SERVER_LOG_DIR"/cmd"
#define SERVER_WWW_LOG		SERVER_LOG_DIR"/www"
#define SERVER_DB_NAME		"server"
#define SERVER_DB_USER		"root"
#define SERVER_DB_GROUP		"gl.server"
#define SERVER_LIB_DIR		SERVER_WORK_DIR"/lib"
#define SERVER_WWW_DIR		SERVER_WORK_DIR"/www/d"
#define DB_CONF "/etc/my.cnf.d/gl.server.cnf"
#define SYSLOGSENDER_CONF SERVER_WORK_DIR"/etc/syslogsender.conf"

#ifndef TIC_CONF
#define TIC_CONF		SERVER_WORK_DIR"/etc/tic.conf"
#define TISRS_CONF		SERVER_WORK_DIR"/etc/tisrs.conf"
#endif
