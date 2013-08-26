#include "ServerManager.h"

#include "ServerTask.h"
//#include "SuperServer.h"

ServerManager *ServerManager::instance = NULL;

void ServerManager::addServer(shared_ptr<ServerTask> task) {
	if (task) {
		boost::mutex::scoped_lock lock(mutex_container);
		container.push_front(task);
	}
}

void ServerManager::removeServer(shared_ptr<ServerTask> task) {
	if (task) {
		boost::mutex::scoped_lock lock(mutex_container);
		container.remove(task);
	}
}

shared_ptr<ServerTask> ServerManager::getServer(WORD wdServerID) {
	Containter_const_iterator it;
	shared_ptr<ServerTask> retval;

	boost::mutex::scoped_lock lock(mutex_container);
	for(it = container.begin(); it != container.end(); it++) {
		if ((*it)->getID() == wdServerID) {
			retval = *it;
			break;
		}
	}

	return retval;
}

bool ServerManager::uniqueAdd(shared_ptr<ServerTask> task) {
	boost::mutex::scoped_lock lock(mutex_hashmap);

	ServerTaskHashmap_const_iterator it = taskUniqueContainer.find(task->getID());
	if (it != taskUniqueContainer.end()) {
		Xlogger->error("ServerManager::uniqueAdd");
		return false;
	}
	taskUniqueContainer.insert(ServerTaskHashmap_pair(task->getID(),task));
	return true;
}

/**
 * \brief 验证这个服务器是否已经启动
 *
 * \param wdServerID 服务器编号
 * \return 验证是否成功
 */
bool ServerManager::uniqueVerify(const WORD wdServerID)
{
	//less error probe
	boost::mutex::scoped_lock lock(mutex_hashmap);

	ServerTaskHashmap_const_iterator it = taskUniqueContainer.find(wdServerID);
	if (it != taskUniqueContainer.end())
	{
		return false;
	}
	return true;
}

/**
 * \brief 从唯一性容器中删除一个连接任务
 *
 * \param task 服务器连接任务
 * \return 删除是否成功
 */
bool ServerManager::uniqueRemove(shared_ptr<ServerTask> task)
{
	boost::mutex::scoped_lock lock(mutex_hashmap);

	ServerTaskHashmap_iterator it = taskUniqueContainer.find(task->getID());
	if (it != taskUniqueContainer.end())
	{
		taskUniqueContainer.erase(it);
		return true;
	}
	else
	{
		Xlogger->error("ServerManager::uniqueRemove");
		return false;
	}
}

/**
 * \brief 向容器中所有的服务器广播指令
 *
 * \param pstrCmd 待广播的指令
 * \param nCmdLen 指令长度
 * \return 广播是否成功
 */
bool ServerManager::broadcast(const void *pstrCmd,int nCmdLen)
{
	bool retval = true;

	boost::mutex::scoped_lock lock(mutex_container);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++)
	{
		if (!(*it)->sendCmd(pstrCmd,nCmdLen))
			retval = false;
	}

	return retval;
}

/**
 * \brief 根据服务器编号广播指令
 *
 * \param wdServerID 待广播指令的服务器编号
 * \param pstrCmd 待广播的指令
 * \param nCmdLen 指令长度
 * \return 广播是否成功
 */
bool ServerManager::broadcastByID(const WORD wdServerID,const void *pstrCmd,int nCmdLen)
{
	bool retval = false;

	boost::mutex::scoped_lock lock(mutex_container);
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

/**
 * \brief 根据服务器类型广播指令
 *
 * \param wdType 待广播指令的服务器类型
 * \param pstrCmd 待广播的指令
 * \param nCmdLen 指令长度
 * \return 广播是否成功
 */
bool ServerManager::broadcastByType(const WORD wdType,const void *pstrCmd,int nCmdLen)
{
	bool retval = true;

	boost::mutex::scoped_lock lock(mutex_container);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++)
	{    
		if ((*it)->getType() == wdType && !(*it)->sendCmd(pstrCmd,nCmdLen))
			retval = false;
	}

	return retval;
}

/**
 * \brief 统计一个区的在线人数
 * \return 得到一个区的当前总在线人数
 */
const DWORD ServerManager::caculateOnlineNum()
{
	boost::mutex::scoped_lock lock(mutex_container);

	DWORD retval = 0;
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++)
	{
		if ((*it)->getType() == GATEWAYSERVER)
			retval += (*it)->getOnlineNum();
	}

	return retval;
}

/**
 * \brief 收到notifyOther回复
 * \param srcID 源服务器编号
 * \param wdServerID 目的服务器编号
 */
void ServerManager::responseOther(const WORD srcID,const WORD wdServerID) {
	boost::mutex::scoped_lock lock(mutex_hashmap);

	ServerTaskHashmap_const_iterator it = taskUniqueContainer.find(srcID);
	if (it != taskUniqueContainer.end()) {
		if (it->second)
			it->second->responseOther(wdServerID);
	}
	else {
		Xlogger->error("ServerManager::responseOther find srcid=%u",srcID);
	}
}

/*
void ServerManager::execEvery() {
	boost::mutex::scoped_lock lock(mutex);
	for(Containter_const_iterator it = container.begin(); it != container.end(); it++) {
		(*it)->doCmd();
	}
}
*/

void ServerManager::checkSequence(){
	//add lock will cause dead lock, later deal it
	boost::mutex::scoped_lock lock(mutex_hashmap);

	ServerTaskHashmap_iterator it = taskUniqueContainer.begin();
	while (it != taskUniqueContainer.end()) {
		shared_ptr<ServerTask> ptr = it->second;
		if (ptr->get_state_name() == "wait") {
			Xlogger->debug("%s",__PRETTY_FUNCTION__);
			ptr->checkDependency();
		}
		++it;
	}
}
