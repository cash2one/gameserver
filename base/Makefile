
compile_debug = -g -Wall
compile_relase = -g -Wall -O2

boost_home = `echo $(BOOST_HOME)`
mysql_home = `echo $(MYSQL_HOME)`

compile_opt = $(compile_debug) $(SEAL_COMPILE_OPT)

HEADER_DIR = -I./ -I$(boost_home) -I../deps/tinyxml
LIB_DIR = -L$(boost_home)/stage/lib -L../deps/tinyxml
#LIBS = -lboost_system -lpthread -lboost_thread -llog4cxx -lmysqlcppconn -lrt
LIBS = -lpthread -llog4cxx -lmysqlcppconn -lboost_system -lboost_thread -ltinyxml

#CXX = g++
CXXFLAGS = $(compile_opt) $(HEADER_DIR) -D_REENTRANT -D_GNU_SOURCE
CXXLFLAGS = $(compile_opt) $(LIB_DIR) $(LIBS)

objects = common.o x_logger.o x_service.o server.o x_simple_db_table.o 
objects += x_config.o x_subnetservice.o io_service_pool.o tcp_task.o task_state.o
#x_subnetservice.o
sources = $(objects:%.o=%.cpp)
deps = $(objects:%.o=.%.d)

#libseal = libseal.a

all_targets = libseal.a

.PHONY: all clean

all: $(all_targets)

include $(deps)
$(deps): .%.d: %.cpp
	@$(CXX) -M $(CXXFLAGS) $< > $@.$$$$; \
		sed 's,\($*\).o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

$(objects): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

#因为这个导致libseal.a 产生不出来
#$(CXX) $(objects) -o $@ $(CXXLFLAGS)
$(all_targets): $(objects) Makefile
	@rm -rf $(all_targets)
	@ar cru $(all_targets) $(objects)
	@ranlib $(all_targets)

clean:
	@rm -rf *.o .*.d $(all_targets) core *~
