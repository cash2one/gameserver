#include "ServerManager.h"
#include "SessionTask.h"

ServerManager *ServerManager::instance = NULL;

void ServerManager::addServer(shared_ptr<SessionTask> task) {
	if (task) {
		mutex.lock();    
		container.push_front(task);
		mutex.unlock();
	}
}

void ServerManager::removeServer(shared_ptr<SessionTask> task) {
	if (task) {
		mutex.lock();    
		container.remove(task);
		mutex.unlock();
	}
}

shared_ptr<SessionTask> ServerManager::getServer(WORD wdServerID) {
	Containter_const_iterator it;
	shared_ptr<SessionTask> retval;

	mutex.lock();
	for(it = container.begin(); it != container.end(); it++) {
		if ((*it)->getID() == wdServerID) {
			retval = *it;
			break;
		}
	}
	mutex.unlock();

	return retval;
}

bool ServerManager::uniqueAdd(shared_ptr<SessionTask> task) {
	boost::mutex::scoped_lock lock(mutex);

	SessionTaskHashmap_const_iterator it = taskUniqueContainer.find(task->getID());
	if (it != taskUniqueContainer.end()) {
		Xlogger->error("ServerManager::uniqueAdd");
		return false;
	}
	taskUniqueContainer.insert(SessionTaskHashmap_pair(task->getID(),task));
	return true;
}

bool ServerManager::uniqueVerify(const WORD wdServerID) {
	//less error probe
	boost::mutex::scoped_lock lock(mutex);

	SessionTaskHashmap_const_iterator it = taskUniqueContainer.find(wdServerID);
	if (it != taskUniqueContainer.end()) {
		return false;
	}
	return true;
}

bool ServerManager::uniqueRemove(shared_ptr<SessionTask> task) {
	boost::mutex::scoped_lock lock(mutex);

	SessionTaskHashmap_iterator it = taskUniqueContainer.find(task->getID());
	if (it != taskUniqueContainer.end()) {
		taskUniqueContainer.erase(it);
		return true;
	}
	else {
		Xlogger->error("ServerManager::uniqueRemove");
		return false;
	}
}

bool ServerManager::broadcast(const void *pstrCmd,int nCmdLen)
{
	bool retval = true;

	boost::mutex::scoped_lock lock(mutex);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++)
	{
		if (!(*it)->sendCmd(pstrCmd,nCmdLen))
			retval = false;
	}

	return retval;
}

bool ServerManager::broadcastByID(const WORD wdServerID,const void *pstrCmd,int nCmdLen)
{
	bool retval = false;

	boost::mutex::scoped_lock lock(mutex);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++)
	{
		if ((*it)->getID() == wdServerID)
		{
			retval = (*it)->sendCmd(pstrCmd,nCmdLen);
			break;
		}
	}

	return retval;
}

bool ServerManager::broadcastByType(const WORD wdType,const void *pstrCmd,int nCmdLen)
{
	bool retval = true;

	boost::mutex::scoped_lock lock(mutex);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++)
	{    
		if ((*it)->getType() == wdType && !(*it)->sendCmd(pstrCmd,nCmdLen))
			retval = false;
	}

	return retval;
}

void ServerManager::execEvery() {
	boost::mutex::scoped_lock lock(mutex);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++) {
		(*it)->doCmd();
	}
}

