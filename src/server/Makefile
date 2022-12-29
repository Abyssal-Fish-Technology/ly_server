CXX=g++
INCS=-I/usr/include/mysql -I/usr/include/cppdb -I/usr/include/cgicc -I.
CXXFLAGS=-Wall -g -std=c++11 -lpthread

LDFLAGS+=-L/usr/lib64 -L/usr/lib -L/usr/local/lib
LDFLAGS+=-L/usr/lib64/mysql -L/usr/lib/mysql -L/usr/local/mysql/lib
LDFLAGS+=-L../common
LDLIBS+=-lcommon
LDLIBS+= -lcppdb -lcgicc -lcurl -lprotobuf -lmysqlclient -lpthread -ljson-c 
LDLIBS+=-lboost_regex
#LDLIBS+=-lboost_system -lboost_filesystem -lboost_thread-mt 

WWW_INSTALL_DIR=/Server/www/d
CMD_INSTALL_DIR=/Server/cmd
BIN_INSTALL_DIR=/Server/bin
SRCS=config_pusher.cpp gen_event.cpp gen_dns_event.cpp feature.cpp event_feature.cpp
SRCS+=mo.cpp internalip.cpp event.cpp bwlist.cpp 
SRCS+=locinfo.cpp geoinfo.cpp
SRCS+=portinfo.cpp ipinfo.cpp
SRCS+=config.cpp auth.cpp 
SRCS+=sctl.cpp 
SRCS+=evidence.cpp 

# LIBS= ../common/libcommon.a
OBJS=$(SRCS:.cpp=.o)
WWW_EXES=mo internalip event bwlist feature event_feature
WWW_EXES+=locinfo geoinfo
WWW_EXES+=portinfo ipinfo
WWW_EXES+=config auth  
WWW_EXES+=threatinfo threatinfopro 
WWW_EXES+=sctl 
WWW_EXES+=evidence 
CMD_EXES=
#BIN_EXES=config_pusher gen_event gen_dns_event
BIN_EXES=config_pusher gen_event
EXES=$(WWW_EXES) $(CMD_EXES) $(BIN_EXES)

-include ../local_debug.mk
-include local_debug.mk

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<
.cc.o:
	$(CXX) -c $(CXXFLAGS) $(INCS) $<

all:$(EXES)

dbc.o:dbc.cpp dbc.h
	 $(CXX) -c dbc.cpp $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LIBS) $(LDLIBS)

syslog_sender.o:syslog_sender.cpp syslog_sender.h
	 $(CXX) -c syslog_sender.cpp $(INCS) $(CXXFLAGS) $(LDFLAGS) $(LIBS) $(LDLIBS)

feature:feature.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

event_feature:event_feature.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

config_pusher:config_pusher.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@
	
mo:mo.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

internalip:internalip.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LDLIBS) $(LIBS) -o $@

gen_event:gen_event.cpp dbc.o syslog_sender.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

event:event.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

asset:asset.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

config:config.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LDLIBS) $(LIBS) -ldl -o $@

auth:auth.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

sctl:sctl.cpp dbc.o
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

locinfo:locinfo.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

geoinfo:geoinfo.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

portinfo:portinfo.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

ipinfo:ipinfo.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@
	
bwlist:bwlist.cpp dbc.o
	$(MAKE) -C ../lib config_bwlist.pb.cc
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LIBS) $(LDLIBS) -o $@

threatinfo:threatinfo.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LDLIBS) $(LIBS) -o $@

threatinfopro:threatinfopro.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LDLIBS) $(LIBS) -o $@

evidence:evidence.o dbc.o $(PB_OBJS) 
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(LDLIBS) $(LIBS) -o $@

install:all
	mkdir -p $(WWW_INSTALL_DIR)
	mkdir -p $(BIN_INSTALL_DIR)
#	cp $(CMD_EXES) $(CMD_INSTALL_DIR)
	cp $(WWW_EXES) $(WWW_INSTALL_DIR)
	cp $(BIN_EXES) $(BIN_INSTALL_DIR)

clean:
	rm -f *.o a.out *~ core* $(OBJS) $(EXES) $(PB_SRCS) $(PB_HDRS) $(PB_OBJS)
	
