
boost_home = `echo $(BOOST_HOME)`
mysql_home = `echo $(MYSQL_HOME)`

header_dir = -I../base -I./ -I../deps/tinyxml -I$(boost_home)
lib_dir = -L../deps/tinyxml -L$(boost_home)/stage/lib -L../base
LIBS = -lseal -lmysqlcppconn -lpthread -llog4cxx -lboost_system -lboost_thread -lboost_chrono -ltinyxml
LIBSEAL = ../base/libseal.a




CXXFLAGS = $(SEAL_COMPILE_OPT)  -Wall -D_GNU_SOURCE -D_REENTRANT $(header_dir)
CXXLFLAGS = $(SEAL_COMPILE_OPT) -Wall $(lib_dir) $(LIBS)

objects = client.o ClientConn.o Game.o NetworkManager.o

SRCS = $(objects:%.o=%.cpp)
DEPS = $(objects:%.o=.%.d)

ALL_TARGETS = client

all: $(ALL_TARGETS)

include $(DEPS)
$(DEPS): .%.d: %.cpp
	@$(CXX) -M $(CXXFLAGS) $< > $@.$$$$; sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; rm -f $@.$$$$

$(objects): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(ALL_TARGETS): $(objects) $(LIBSEAL) Makefile
	$(CXX) $(objects) -o $@ $(CXXLFLAGS)

clean:
	@rm -rf *.o .*.d* $(ALL_TARGETS) core *~
