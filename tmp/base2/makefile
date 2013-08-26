
compile_debug = -g -Wall -Werror $(LOKI_OPTIONS)
compile_relase = -g -Wall -O2 -Werror $(LOKI_OPTIONS)

compile_opt = $(compile_debug)

HEADER_DIR = -I/home/liuqing/boost_1_52_0
LIB_DIR = -L/home/liuqing/boost_1_52_0/stage/lib
LIBS = -lboost_system -lpthread -lboost_thread

CXX = g++
CXXFLAGS = $(compile_opt) $(HEADER_DIR) -D_REENTRANT 
CXXLFLAGS = $(compile_opt) $(LIB_DIR) $(LIBS)

objects = connection.o io_service_pool.o server.o main.o
sources = $(objects:%.o=%.cpp)
deps = $(objects:%.o=.%.d)

all_targets = main

.PHONY: all clean

all: $(all_targets)

include $(deps)
$(deps): .%.d: %.cpp
	@$(CXX) -M $(CXXFLAGS) $< > $@.$$$$; \
		sed 's,\($*\).o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

$(objects): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(all_targets): $(objects)
	$(CXX) $(objects) -o $@ $(CXXLFLAGS)

clean:
	@rm -rf *.o .*.d $(all_targets) core *~
