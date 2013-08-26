BUILD_DIR_ROOT = $(PWD)
#BUILD_STRING = `data +%Y%m%d` " build"`cat $(BUILD_DIR_ROOT)/.build`
BUILD_STRING = 
VERSIONSTRING = `if [ $(VERSION_STRING) ];then echo &(VERSION_STRING); else echo "0.0.0"; fi`
SEAL_DEBUG_OPT = -g -Werror -D_USE_CMD_NAMESPACE  $(LOKI_OPTIONS) -DVS=$(VERSIONSTRING)  \
	`mysql_config --cflags`
SEAL_DIST_OPT = -g -O2 -Werror -D_USE_CMD_NAMESPACE  -DVS=$(VERSIONSTRING) $(LOKI_OPTIONS) \
	`mysql_config --cflags`


#SUB_DIRS = base/EncDec base tools GatewayServer SessionServer ScenesServer RecordServer MiniServer SuperServer BillServer tools MonitorServer AllZoneServer
SUB_DIRS = deps/tinyxml base FLServer SuperServer RecordServer BillServer SessionServer SceneServer GatewayServer

#TEST_SUB_DIRS = base/EncDec base tools
ALL_SUB_DIRS = $(SUB_DIRS) 

NJOBS = `if [ ""=="$(NCPUS)" ]; then echo ""; else echo "-j$(NCPUS)"; fi`
#DMUCS_HOST_IP=`hostname -i | sed s,.$$$$,,`"0"
DMUCS_HOST_IP=172.17.102.30
export CXX=g++

.PHONY: all debug debug_nogm ctags doc distclean clean sql svn build release_cp dist_tar dist map distall dist_tar_gm dist_gm map_gm distall_gm $(ALL_SUB_DIRS) ChangeLog client

all: debug client

super:
	@export CXX='gethost -s $(DMUCS_HOST_IP) distcc /usr/bin/g++'; \
				for dir in $(SUB_DIRS); \
				do \
				SEAL_COMPILE_OPT='$(SEAL_DEBUG_OPT) -DBUILD_STRING=$(BUILD_STRING)' PIC_FLAG='-fDIC' $(MAKE) $(NJOBS) -C $$dir || exit 1; \
				done

debug:
	@for dir in $(SUB_DIRS); \
		do \
		SEAL_COMPILE_OPT='$(SEAL_DEBUG_OPT) -DBUILD_STRING=$(BUILD_STRING)' $(MAKE) $(NJOBS) -C $$dir || exit 1; \
		done

client:
	SEAL_COMPILE_OPT='$(SEAL_DEBUG_OPT) -DBUILD_STRING=$(BUILD_STRING)' $(MAKE) $(NJOBS) -C ./client/ || exit 1;

debug_dist:
	@for dir in $(SUB_DIRS); \
		do \
		SEAL_COMPILE_OPT='$(SEAL_DIST_OPT) -DBUILD_STRING=$(BUILD_STRING)' $(MAKE) $(NJOBS) -C $$dir || exit 1; \
		done


test:
	@for dir in $(TEST_SUB_DIRS); \
		do \
		SEAL_COMPILE_OPT='$(SEAL_DEBUG_OPT) -DBUILD_STRING=$(BUILD_STRING)' $(MAKE) $(NJOBS) -C $$dir || exit 1; \
		done

sql:
	@$(MAKE) -C sql

ChangeLog:
	@rm ChangeLog
	@svn log -v | ./gnuifiy-changelog.pl > ChangeLog

doc:
	@doxygen Doxyfile.pub

alldoc:
	@doxygen

distclean:
	@find . -iname .\*.d -exec rm \{\} \;

clean:
	@for dir in $(ALL_SUB_DIRS); \
		do \
		$(MAKE) -C $$dir clean; \
		done

#ctags:
#	@find . -type f -name "*.cpp" -o -name ".c" -o -name "*.h" -o -name "*.hpp" | xargs ctags

ctags:
	@ctags-exuberant -R 

#@ctags -R "*.c" "*.cpp" "*.h"
#@ctags  */*.c */*.cpp */*.h


