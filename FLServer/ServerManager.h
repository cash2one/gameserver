#pragma once

#include "common.h"
#include <boost/thread/mutex.hpp>
#include <boost/unordered_map.hpp>
//#include <boost/smart_ptr.hpp>
using namespace boost;

class ServerTask;

class ServerManager : boost::noncopyable
{

public:
	~ServerManager() {}

	static ServerManager &getInstance() {
		if (NULL == instance)
			instance = new ServerManager();
		return *instance;
	}

	static void delInstance() { SAFE_DELETE(instance); }

	bool uniqueAdd(shared_ptr<ServerTask> task);
	bool uniqueRemove(shared_ptr<ServerTask> task);
	bool broadcast(const GameZone_t &gameZone,const void *pstrCmd,int nCmdLen);

private:

	ServerManager() {}
	static ServerManager *instance;

	typedef boost::unordered_map<GameZone_t, shared_ptr<ServerTask> > ServerTaskContainer;
	typedef ServerTaskContainer::iterator ServerTaskContainer_iterator;
	typedef ServerTaskContainer::const_iterator ServerTaskContainer_const_iterator;
	typedef ServerTaskContainer::value_type ServerTaskContainer_value_type;

	boost::mutex mlock;
	ServerTaskContainer taskUniqueContainer;

};
