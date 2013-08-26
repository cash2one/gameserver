#include "ServerManager.h"
#include "ServerTask.h"
//#include "FLServer.h"

using namespace boost;

ServerManager *ServerManager::instance = NULL;

bool ServerManager::uniqueAdd(shared_ptr<ServerTask> task)
{
	mutex::scoped_lock scope_lock(mlock);
	ServerTaskContainer_const_iterator it;
	it = taskUniqueContainer.find(task->getZoneID());
	if (it != taskUniqueContainer.end()) {
		Xlogger->error("ServerManager::uniqueAdd");
		return false;
	}
	taskUniqueContainer.insert(ServerTaskContainer_value_type(task->getZoneID(),task));
	return true;
}

bool ServerManager::uniqueRemove(shared_ptr<ServerTask> task) {
	mutex::scoped_lock scope_lock(mlock);
	ServerTaskContainer_iterator it;
	it = taskUniqueContainer.find(task->getZoneID());
	if (it != taskUniqueContainer.end()) {
		taskUniqueContainer.erase(it);
	}
	else
		Xlogger->error("ServerManager::uniqueRemove");
	return true;
}

bool ServerManager::broadcast(const GameZone_t &gameZone,const void *pstrCmd,int nCmdLen)
{
	mutex::scoped_lock scope_lock(mlock);
	ServerTaskContainer_iterator it = taskUniqueContainer.find(gameZone);
	if (it != taskUniqueContainer.end()) {
		return it->second->sendCmd(pstrCmd,nCmdLen);
	}
	else
		return false;
}

