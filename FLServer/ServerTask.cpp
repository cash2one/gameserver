#include "ServerTask.h"
#include "ServerACL.h"
#include "flcmd.h"
#include "ServerManager.h"
#include "GYListManager.h"
#include "LoginManager.h"

void ServerTask::handle_verify(const void* ptr, const uint32_t len) {
	using namespace Cmd::FL;
	t_LoginFL *ptCmd = (t_LoginFL *)ptr;
	if (CMD_LOGIN == ptCmd->cmd && PARA_LOGIN == ptCmd->para) {
		bool mcheck = ServerACL::getSingleton().check( get_remote_ip().c_str(), ptCmd->port, gameZone, name);
		if (mcheck) {
			Xlogger->debug("client connection verified(%s:%d)", get_remote_ip().c_str(), ptCmd->port);
			if (uniqueAdd())
			{
				set_state(state_okay_);

				t_LoginFL_OK cmd;
				cmd.gameZone = gameZone;
				strncpy(cmd.name, name.c_str(), sizeof(cmd.name) - 1);

				t_RQGYList_FL tRQ;
				sendCmd(&cmd,sizeof(cmd)) && sendCmd(&tRQ,sizeof(tRQ));
				Xlogger->debug("%s, t_RQGYList_FL", __PRETTY_FUNCTION__);
				return ;
			}
		}
	}
	Xlogger->error("client connection verify failed (%s:%d)", get_remote_ip().c_str(), ptCmd->port);
	handle_error(boost::system::error_code());
}

bool ServerTask::uniqueAdd() {
	return ServerManager::getInstance().uniqueAdd(boost::dynamic_pointer_cast<ServerTask>(shared_from_this()));
}

bool ServerTask::uniqueRemove() {
	GYListManager::getInstance().disableAll(gameZone);
	return ServerManager::getInstance().uniqueRemove(boost::dynamic_pointer_cast<ServerTask>(shared_from_this()));
}

bool ServerTask::msgParse(const Cmd::t_NullCmd *pNullCmd, const DWORD nCmdLen) {
	using namespace Cmd::FL;

	switch(pNullCmd->cmd)
	{
	case CMD_GYLIST:
		if (msgParse_gyList(pNullCmd,nCmdLen)) return true;
		break;
	case CMD_SESSION:
		if (msgParse_session(pNullCmd,nCmdLen)) return true;
		break;
	}
	Xlogger->debug("%s:(%d,%d,%d)",__PRETTY_FUNCTION__, pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool ServerTask::msgParse_gyList(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::FL;

	switch(pNullCmd->para)
	{
	case PARA_FL_GYLIST:
		{
			t_GYList_FL *ptCmd = (t_GYList_FL *)pNullCmd;
			GYList gy;

			Xlogger->info("PARA_FL_GYLIST:zoneid=%d(gameid=%d,zone=%d),%d,ip=%s,port=%d,onlines=%d,state=%d,version=%d",
					gameZone.id, gameZone.game, gameZone.zone,
					ptCmd->wdServerID,ptCmd->dwpstrIP,ptCmd->wdPort,
					ptCmd->wdNumOnline, ptCmd->state, ptCmd->zoneGameVersion);
			gy.wdServerID = ptCmd->wdServerID;
			gy.dwpstrIP = ptCmd->dwpstrIP;
			gy.wdPort = ptCmd->wdPort;
			gy.wdNumOnline = ptCmd->wdNumOnline;
			gy.state = ptCmd->state;
			gy.zoneGameVersion = ptCmd->zoneGameVersion;

			return GYListManager::getInstance().put(gameZone,gy);
		}
		break;
	}

	Xlogger->error("ServerTask::msgParse_gyList(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool ServerTask::msgParse_session(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::FL;

	switch(pNullCmd->para)
	{
	case PARA_SESSION_NEWSESSION:
		{
			t_NewSession_Session *ptCmd = (t_NewSession_Session *)pNullCmd;
			using namespace Cmd;
			stServerReturnLoginSuccessCmd tCmd;

			Xlogger->info("PARA_SESSION_NEWSESSION:%d,%d,%d,%d",
					ptCmd->session.accid,ptCmd->session.loginTempID,ptCmd->session.dwpstrIP,ptCmd->session.wdPort);
			tCmd.dwUserID = ptCmd->session.accid;
			tCmd.loginTempID = ptCmd->session.loginTempID;
			tCmd.dwpstrIP = ptCmd->session.dwpstrIP;
			tCmd.wdPort = ptCmd->session.wdPort;
			bzero(tCmd.key, sizeof(tCmd.key));
			//the key hide in the random nums
			/*
			for (int i=0; i<sizeof(tCmd.key); i++)
				tCmd.key[i] = randBetween(0,255);
				*/

			//the logic need to be rewriten
			/*
			do
				tCmd.key[58] = randBetween(0,248);
			while((tCmd.key[58]>49)&&((tCmd.key[58]<59)));
			*/

			//bcopy(ptCmd->session.des_key,&tCmd.key[tCmd.key[58]],sizeof(ZES_cblock),sizeof(tCmd.key) - tCmd.key[58]);

			Xlogger->debug("client login success");
			return LoginManager::getInstance().broadcast(ptCmd->session.loginTempID,&tCmd,sizeof(tCmd));
		}
		break;
	case PARA_SESSION_IDINUSE:
		{
			t_idinuse_Session *ptCmd = (t_idinuse_Session *)pNullCmd;
			using namespace Cmd;

			Xlogger->warn("PARA_SESSION_IDINUSE accid = %d",ptCmd->accid);
			LoginManager::getInstance().loginReturn(ptCmd->loginTempID,LOGIN_RETURN_IDINUSE);
			return true;
		}
		break;
	}
	Xlogger->error("ServerTask::msgParse_session(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

void ServerTask::handle_msg(const void* ptr, const uint32_t len) {
	msgParse((const Cmd::t_NullCmd*)ptr,len);
	async_read();
}
