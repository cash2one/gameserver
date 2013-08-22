#include "BillTaskManager.h"
#include "BillTask.h"

BillTaskManager *BillTaskManager::instance = NULL;

bool BillTaskManager::uniqueAdd(shared_ptr<BillTask> task) {
	boost::mutex::scoped_lock lock(mutex);

	BillTaskHashmap_const_iterator it = taskUniqueContainer.find(task->getID());
	if (it != taskUniqueContainer.end())
	{
		Xlogger->error("BillTaskManager::uniqueAdd");
		return false;
	}
	taskUniqueContainer.insert(BillTaskHashmap_pair(task->getID(),task));
	return true;
}

bool BillTaskManager::uniqueRemove(shared_ptr<BillTask> task) {
	boost::mutex::scoped_lock lock(mutex);

	BillTaskHashmap_iterator it = taskUniqueContainer.find(task->getID());
	if (it != taskUniqueContainer.end()) {
		taskUniqueContainer.erase(it);
		return true;
	}
	else
	{
		Xlogger->error("BillTaskManager::uniqueRemove");
		return false;
	}
}

bool BillTaskManager::broadcastByID(const uint32_t dwServerID, const void *pstrCmd, const int nCmdLen) {
	bool retval = false;
	boost::mutex::scoped_lock lock(mutex);
    BillTaskHashmap_iterator it = taskUniqueContainer.find(dwServerID);
	if (it != taskUniqueContainer.end()) {
		retval = it->second->sendCmd(pstrCmd, nCmdLen);
	}
	return retval;
}

void BillTaskManager::broadcast(const void *pstrCmd, const int nCmdLen) {
	boost::mutex::scoped_lock lock(mutex);
    BillTaskHashmap_iterator it = taskUniqueContainer.begin();
	while (it != taskUniqueContainer.end()) {
		it->second->sendCmd(pstrCmd, nCmdLen);
		++it;
	}
}

shared_ptr<BillTask> BillTaskManager::getTaskByID(const uint32_t dwServerID) {
	boost::mutex::scoped_lock lock(mutex);
	shared_ptr<BillTask> ret;
    BillTaskHashmap_iterator it = taskUniqueContainer.find(dwServerID);
	if (it != taskUniqueContainer.end()) {
		ret = it->second;
	}
	return ret;
}

void BillTaskManager::execEvery() {
	boost::mutex::scoped_lock lock(mutex);
    BillTaskHashmap_iterator it = taskUniqueContainer.begin();
	while (it != taskUniqueContainer.end()) {
		it->second->doCmd();
		++it;
	}
}
