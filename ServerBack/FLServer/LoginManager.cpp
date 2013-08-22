#include "LoginManager.h"
#include "FLServer.h"
#include "LoginTask.h"
#include "flcmd.h"
#include "GYListManager.h"

#define MAX_GATEWAYUSER 4000

LoginManager *LoginManager::instance = NULL;
DWORD LoginManager::maxGatewayUser=MAX_GATEWAYUSER;

bool LoginManager::add(shared_ptr<LoginTask> task) {
	Xlogger->debug("LoginManager::add");
	if (task) {
		task->genTempID();

		boost::mutex::scoped_lock scope_lock(mlock);

		LoginTaskHashmap_const_iterator it = loginTaskSet.find(task->getTempID());
		if (it != loginTaskSet.end()) {
			return false;
		}
		loginTaskSet.insert(LoginTaskHashmap_pair(task->getTempID(),task));
		return true;
	}
	else
		return false;
}

bool LoginManager::remove(shared_ptr<LoginTask> task) {
	Xlogger->debug("LoginManager::remove");
	if (task) {
		boost::mutex::scoped_lock scope_lock(mlock);
		loginTaskSet.erase(task->getTempID());
		return true;
	}
	return false;
}

bool LoginManager::broadcast(const DWORD loginTempID,const void *pstrCmd,int nCmdLen) {
	Xlogger->debug("LoginManager::broadcast");
	boost::mutex::scoped_lock scope_lock(mlock);
	LoginTaskHashmap_iterator it = loginTaskSet.find(loginTempID);
	if (it != loginTaskSet.end())
		return it->second->sendCmd(pstrCmd,nCmdLen);
	else
		return false;
}

void LoginManager::verifyReturn(const Cmd::t_NewLoginSession &session)
{
	boost::mutex::scoped_lock scope_lock(mlock);

	LoginTaskHashmap_iterator it = loginTaskSet.find(session.loginTempID);
	if (it != loginTaskSet.end())
	{
		shared_ptr<LoginTask> task = it->second;

		switch(session.state)
		{
			case 0:
				{
					Xlogger->debug("login success ,allocator gateway :gameZone = %u",session.gameZone);
					GYList * gy = GYListManager::getInstance().getAvl(session.gameZone);
					if (NULL == gy) {
						task->LoginReturn(Cmd::LOGIN_RETURN_GATEWAYNOTAVAILABLE);
						Xlogger->debug("gateway is not open");
					}
					else if (gy->wdNumOnline >= (maxGatewayUser - 10)) {
						task->LoginReturn(Cmd::LOGIN_RETURN_USERMAX);
						Xlogger->error("user num is full, current num = %d",gy->wdNumOnline);
					}
					else
					{
						//CEncrypt                      e;
						Cmd::FL::t_NewSession_Session tCmd;

						// [ranqd delete] 未成功登陆的用户不记数，等待网关返回
						//	gy->wdNumOnline++;

						tCmd.session             = session;
						tCmd.session.wdGatewayID = gy->wdServerID;

						//生成des加密密钥                
						//e.random_key_des(&tCmd.session.des_key);
						/*
						   Xlogger->info("生成密钥:%02x %02x %02x %02x %02x %02x %02x %02x",tCmd.session.des_key[0],tCmd.session.des_key[1],tCmd.session.des_key[2],tCmd.session.des_key[3],tCmd.session.des_key[4],tCmd.session.des_key[5],tCmd.session.des_key[6],tCmd.session.des_key[7]);
						 */
						/*
						   for (int i=0; i<sizeof(tCmd.session.des_key); i++)
						   tCmd.session.des_key[i] = (DWORD)randBetween(0,255);
						 */
						//bcopy(gy->pstrIP,tCmd.session.pstrIP,sizeof(tCmd.session.pstrIP),sizeof(tCmd.session.pstrIP));
						tCmd.session.dwpstrIP = gy->dwpstrIP;
						tCmd.session.wdPort = gy->wdPort;
						//ServerManager::getInstance().broadcast(session.gameZone,&tCmd,sizeof(tCmd));
					}
				}
				break;
			case 1:
				//帐号处于锁定状态
				task->LoginReturn(Cmd::LOGIN_RETURN_LOCK);
				Xlogger->error("帐号已锁定");
				break;
			case 4:
				//帐号处于待激活状态
				task->LoginReturn(Cmd::LOGIN_RETURN_WAITACTIVE);
				Xlogger->error("帐号待激活");
				break;
			default:
				break;
		}
	}
}

/**
* \brief 返回错误代码到指定的客户端
* \param loginTempID 指定的客户端连接临时编号
* \param retcode 待返回的代码
* \param tm 返回信息以后是否断开连接,缺省是断开连接
*/
void LoginManager::loginReturn(const DWORD loginTempID,const BYTE retcode,const bool tm)
{
	Xlogger->debug("LoginManager::loginReturn");
	boost::mutex::scoped_lock scope_lock(mlock);
	LoginTaskHashmap_iterator it = loginTaskSet.find(loginTempID);
	if (it != loginTaskSet.end())
		it->second->LoginReturn(retcode,tm);
}

/**
* \brief 对容器中的所有元素调用回调函数
* \param cb 回调函数实例
*/
void LoginManager::execAll(LoginTaskCallback &cb)
{
	Xlogger->debug("LoginManager::execAll");
	boost::mutex::scoped_lock scope_lock(mlock);
	for(LoginTaskHashmap_iterator it = loginTaskSet.begin(); it != loginTaskSet.end(); ++it)
	{
		cb.exec(it->second.get());
	}
}

