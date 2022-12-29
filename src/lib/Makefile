CXX=g++
INCS=-I/usr/include/mysql -I/usr/include/cppdb -I/usr/include/cgicc -I.
CXXFLAGS=-Wall -fPIC -shared -g -std=c++0x
LDLIBS+=-lcppdb -lcgicc -lcurl -lprotobuf
LDLIBS+=-lboost_system -lboost_filesystem -lboost_thread-mt -lboost_regex -lpthread
LIBS+=-L../common -lcommon

TARGET_LIBS=config_event.so config_mo.so config_internalip.so config_internalsrv.so config_agent.so config_bwlist.so config_user.so 
PBS=config_event.proto config_agent.proto config_bwlist.proto config_user.proto
PB_SRCS=$(PBS:.proto=.pb.cc)
PB_HDRS=$(PBS:.proto=.pb.h)
PB_OBJS=$(PB_SRCS:.cc=.o)

LIB_INSTALL_DIR=/Server/lib

-include ../local_debug.mk
-include local_debug.mk

all:$(PBS) $(PB_OBJS) $(TARGET_LIBS)

$(PB_SRCS):$(PBS)
	protoc $^ --cpp_out=.

config_event.so:config_class.cpp config_event.cpp config_event.pb.cc
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

config_mo.so:config_class.cpp config_mo.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

config_internalip.so:config_class.cpp config_internalip.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

config_internalsrv.so:config_class.cpp config_internalsrv.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

config_agent.so:config_class.cpp config_agent.cpp config_agent.pb.cc
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

config_bwlist.so:config_class.cpp config_bwlist.cpp config_bwlist.pb.cc
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

config_user.so:config_class.cpp config_user.cpp config_user.pb.cc 
	$(CXX) $^ $(CXXFLAGS) $(INCS) $(LIBS) $(LDLIBS) -o $@

install:all
	mkdir -p $(LIB_INSTALL_DIR)
	cp $(TARGET_LIBS) $(LIB_INSTALL_DIR)

clean:
	rm -f *.o a.out *~ core* $(TARGET_LIBS)
	rm -f $(PB_SRCS) $(PB_HDRS)
