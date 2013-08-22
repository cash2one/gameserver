#include "ServerTask.h"
#include "SuperServer.h"
#include "ServerManager.h"

#include "supercmd.h"
#include "flcmd.h"
#include "gmtoolcmd.h"
#include <vector>
#include "FLClient.h"
#include "task_state.h"

static boost::unordered_map<int,std::vector<int> > serverSequence;

void initServerSequence() {   
	serverSequence[UNKNOWNSERVER]  =  std::vector<int>();
	serverSequence[SUPERSERVER]  =  std::vector<int>();
	serverSequence[LOGINSERVER]  =  std::vector<int>();
	serverSequence[RECORDSERVER]  =  std::vector<int>();
	//serverSequence[MINISERVER]  =  std::vector<int>();

	int data0[] = { RECORDSERVER };
	serverSequence[SESSIONSERVER]  =  std::vector<int>(data0,data0 + sizeof(data0) / sizeof(int));
	int data1[] = { RECORDSERVER,SESSIONSERVER};
	serverSequence[SCENESSERVER]  =  std::vector<int>(data1,data1 + sizeof(data1) / sizeof(int));
	int data2[] = { RECORDSERVER,BILLSERVER,SESSIONSERVER,SCENESSERVER};
	serverSequence[GATEWAYSERVER]  =  std::vector<int>(data2,data2 + sizeof(data2) / sizeof(int));

}

ServerTask::~ServerTask() {
}

bool ServerTask::verify(WORD wdType,const char *_pstrIP) {
	using namespace Cmd::Super;
	pstrIP = _pstrIP;

	std::vector<const Cmd::Super::ServerEntry *> tempses;
	const std::vector<Cmd::Super::ServerEntry>& total = SuperService::getInstance().ses_;
	SuperService::getInstance().get_recordset(wdType,pstrIP,tempses);
	size_t retcode = tempses.size();
	if (retcode == 0){
		Xlogger->error("the db table doesn't have record");
		return false;
	}
	if (retcode > 1 && (wdType == BILLSERVER || wdType == SESSIONSERVER))
	{
		Xlogger->error("this type of server can only have one, type=%u,num=%u",wdType,retcode);
		return false;
	}
	size_t i = 0;
	for(;i<retcode;++i)
	{
		if (ServerManager::getInstance().uniqueVerify(tempses[i]->wdServerID)){
			se_ = *tempses[i];
			break;
		}
	}
	if (i == retcode){
		Xlogger->error("server have startup completely,there is no availabe record");
		return false;
	}

	uint8_t buff[MAX_MSG_SIZE] = {0};
	t_Startup_Response *pCmd = (t_Startup_Response *)(buff);
	constructInPlace(pCmd);
	pCmd->wdServerID = se_.wdServerID;
	pCmd->wdPort = se_.wdPort;
	memcpy(pCmd->pstrExtIP, se_.pstrExtIP, sizeof(se_.pstrExtIP));
	pCmd->wdExtPort = se_.wdExtPort;
	pCmd->wdNetType = se_.wdNetType;
	pCmd->wdSize = total.size();

	const size_t msgLength = sizeof(*pCmd)+pCmd->wdSize*sizeof(Cmd::Super::ServerEntry);
	if (msgLength > MAX_MSG_SIZE){
		Xlogger->error("msg too long, maybe serverlist too long");
		return false;
	}
	for(size_t i = 0; i < pCmd->wdSize; ++i) {
		pCmd->entry[i] = total[i];
	}

	//send serverlist table to all subserver, for simple startup
	if (!sendCmd(pCmd, msgLength)) {
		Xlogger->error("send cmd to server failed");
		return false;
	}

	//calc the dependency
	for (size_t i=0;i < total.size();++i) {
		for (size_t j=0;j < serverSequence[se_.wdServerType].size();++j) {
			if (total[i].wdServerType == serverSequence[se_.wdServerType][j]) {
				ses.insert(Container::value_type(total[i], false));
			}
		}
	}

	return true; 
}

void ServerTask::handle_verify(const void* cmd, const uint32_t len) {
	const Cmd::Super::t_Startup_Request *ptCmd = (const Cmd::Super::t_Startup_Request *)cmd;
	if (Cmd::Super::CMD_STARTUP == ptCmd->cmd && Cmd::Super::PARA_STARTUP_REQUEST == ptCmd->para) {
		if (verify(ptCmd->wdServerType,ptCmd->pstrIP)) {
			Xlogger->debug("%s : success", __PRETTY_FUNCTION__);
			//state_wait_sync_.reset(new state_wait_sync(shared_from_this()));
			if (uniqueAdd())
			{
				state_wait_.reset(new state_wait(shared_from_this()));
				set_state(state_wait_);
				return ;
			}
		}
	}
	Xlogger->debug("%s : failed", __PRETTY_FUNCTION__);
}

bool ServerTask::verifyTypeOK(const WORD wdType,std::vector<shared_ptr<ServerTask> > &sv) {
	Xlogger->info("ServerTask::verifyTypeOK(wdType=%u)",wdType);

	std::vector<const Cmd::Super::ServerEntry*> tempses;
	SuperService::getInstance().get_recordset_by_type(wdType,tempses);
	const size_t retcode = tempses.size();

	bool retval = true;
	for(size_t i = 0; i < retcode; i++) {
		shared_ptr<ServerTask>  pServer = ServerManager::getInstance().getServer(tempses[i]->wdServerID);
		if (!pServer) {
			retval = false;
			break;
		}
		else {
			sv.push_back(pServer);
		}
	}

	return retval;
}

/**
* \brief 通知所有依赖的服务器
* \return 通知是否成功
*/
bool ServerTask::notifyOther(WORD dstID)
{
	Xlogger->info("ServerTask::notifyOther(dstID =%u)",dstID);
	using namespace Cmd::Super;

	t_Startup_ServerEntry_NotifyOther Cmd;

	bzero(&Cmd.entry,sizeof(Cmd.entry));
	Cmd.entry.wdServerID = se_.wdServerID;
	Cmd.entry.wdServerType = se_.wdServerType;
	strncpy(Cmd.entry.pstrIP,pstrIP.c_str(),MAX_IP_LENGTH - 1);
	Cmd.entry.wdPort = wdPort;
	Cmd.entry.state = state;

	for(Container::iterator it = ses.begin(); it != ses.end(); ++it) {
		if (dstID == it->first.wdServerID) {
			shared_ptr<ServerTask>  pDst = ServerManager::getInstance().getServer(dstID);
			if (pDst) {
				pDst->sendCmd(&Cmd,sizeof(Cmd));
			}
			break;
		}
	}

	return true;
}
/**
* \brief 通知所有依赖的服务器
* \return 通知是否成功
*/
bool ServerTask::notifyOther()
{
	using namespace Cmd::Super;
	bool retval = true;

	Xlogger->debug("ServerTask::notifyOther()");

	t_Startup_ServerEntry_NotifyOther Cmd;
	Cmd.entry = se_;

	for(Container::iterator it = ses.begin(); it != ses.end(); ++it)
	{
		Cmd.srcID = it->first.wdServerID;
		bool curval = ServerManager::getInstance().broadcastByID(Cmd.srcID,&Cmd,sizeof(Cmd));
		Xlogger->info("ServerTask::notifyOther()srcid=%u = %u ?",Cmd.srcID,curval);
		retval &= curval;
	}
	return retval;
}

void ServerTask::responseOther(const WORD wdServerID)
{
	Xlogger->info("ServerTask::responseOther(%u)",wdServerID);
	for(Container::iterator it = ses.begin(); it != ses.end(); ++it)
	{
		if (it->first.wdServerID == wdServerID)
		{
			Xlogger->debug("get response from %d: local id=%u",it->first.wdServerID, getID());
			it->second = true;
		}
	}
}

bool ServerTask::checkDependency() {
	using namespace Cmd::Super;

	for(Container::iterator it = ses.begin(); it != ses.end(); ++it) {
		shared_ptr<ServerTask>  pDst = ServerManager::getInstance().getServer(it->first.wdServerID);
		if (!pDst) {
			return false;
		}
	}
	t_Startup_ServerEntry_NotifyMe Cmd;
	sendCmd(&Cmd, sizeof(Cmd));

	state_wait_sync_.reset(new state_wait_sync(shared_from_this()));
	set_state(state_wait_sync_);
	return true;
}

void ServerTask::handle_wait_sync(const void* ptr, const uint32_t len)
{
	Xlogger->debug("ServerTask::waitSync");
	using namespace Cmd::Super;
	const Cmd::Super::t_Startup_OK *ptCmd = (const Cmd::Super::t_Startup_OK *)ptr;    
	if (CMD_STARTUP == ptCmd->cmd && PARA_STARTUP_OK == ptCmd->para && se_.wdServerID == ptCmd->wdServerID) {
		Xlogger->debug("client connect sync success (%u,%u)",ptCmd->wdServerID,se_.wdServerID);
		set_state(state_okay_);
		return ;
	}
	Xlogger->error("client connect sync failed (%u,%u)",ptCmd->wdServerID,se_.wdServerID);
}

int ServerTask::recycleConn()
{
	//rightnow for simple to comment this;
	/*
	if( getType() == GATEWAYSERVER)
	{
		Cmd::Verify::t_Gateway_Stop send;
		send.wdGateID = getID();
		VerClientManager::getInstance().broadcast(&send,sizeof(send));
	}
	*/
	return 1;
}

/**
* \brief 添加到全局容器中
*
* 实现了虚函数<code>x_tcptask::addToContainer</code>
*
*/
void ServerTask::addToContainer()
{
	ServerManager::getInstance().addServer(boost::dynamic_pointer_cast<ServerTask>(shared_from_this()));
	//can notify other servers below
}

/**
* \brief 从全局容器中删除
*
* 实现了虚函数<code>x_tcptask::removeToContainer</code>
*
*/
void ServerTask::removeFromContainer()
{
	//if gatewayserver is closed, notify login server to close gateway
	if (GATEWAYSERVER == se_.wdServerType)
	{
		Cmd::FL::t_GYList_FL tCmd;

		tCmd.wdServerID = se_.wdServerID;
		tCmd.dwpstrIP = 0;
		tCmd.wdPort = 0;
		tCmd.wdNumOnline = 0;
		tCmd.state = state_maintain;
		tCmd.zoneGameVersion = 0;

		Xlogger->info("gatewayserver is shutdown,send state_maintain to FLServer !");

		//FLClientManager::getInstance().broadcast(&tCmd,sizeof(tCmd));
	}

	ServerManager::getInstance().removeServer(boost::dynamic_pointer_cast<ServerTask>(shared_from_this()));
}

/**
* \brief 添加到唯一性验证容器中
*
* 实现了虚函数<code>x_tcptask::uniqueAdd</code>
*
*/
bool ServerTask::uniqueAdd()
{
	return ServerManager::getInstance().uniqueAdd(boost::dynamic_pointer_cast<ServerTask>(shared_from_this()));
}

/**
* \brief 从唯一性验证容器中删除
*
* 实现了虚函数<code>x_tcptask::uniqueRemove</code>
*
*/
bool ServerTask::uniqueRemove()
{
	return ServerManager::getInstance().uniqueRemove(boost::dynamic_pointer_cast<ServerTask>(shared_from_this()));
}

/**
* \brief 解析来自管理服务器的关于启动的指令
*
* \param pNullCmd 待处理的指令
* \param nCmdLen 指令长度
* \return 解析是否成功
*/
bool ServerTask::msgParse_Startup(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::Super;

	switch(pNullCmd->para)
	{
	case PARA_STARTUP_SERVERENTRY_NOTIFYOTHER://1,4
		{    
			Xlogger->debug("super server recv : PARA_STARTUP_SERVERENTRY_NOTIFYOTHER");
			t_Startup_ServerEntry_NotifyOther *ptCmd = (t_Startup_ServerEntry_NotifyOther *)pNullCmd;  
			ServerManager::getInstance().responseOther(ptCmd->entry.wdServerID,ptCmd->srcID);
			return true;
		}
		break;
	case PARA_RESTART_SERVERENTRY_NOTIFYOTHER:
		{
			t_Restart_ServerEntry_NotifyOther *notify = (t_Restart_ServerEntry_NotifyOther*)pNullCmd;
			shared_ptr<ServerTask>  pSrc = ServerManager::getInstance().getServer(notify->srcID);
			if (pSrc)
			{
				pSrc->notifyOther(notify->dstID);
				return true;
			}
		}
		break;
	case PARA_STARTUP_TEST:
		{
			Xlogger->debug("[test] get msg from subserver: id=%u,type=%u",getID(),getType());
			return true;
		}
		break;
	default:
		break;
	}

	Xlogger->error("ServerTask::msgParse_Startup(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

/**
* \brief 解析来自计费服务器的指令
*
* \param pNullCmd 待处理的指令
* \param nCmdLen 指令长度
* \return 处理是否成功
*/
bool ServerTask::msgParse_Bill(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::Super;

	switch(pNullCmd->para)
	{
		/*
	case PARA_BILL_IDINUSE:
		{
			//FLServer -> Super ->FLServer
			t_idinuse_Bill *ptCmd = (t_idinuse_Bill *)pNullCmd;
			Cmd::FL::t_idinuse_Session tCmd;

			tCmd.accid = ptCmd->accid;
			tCmd.loginTempID = ptCmd->loginTempID;
			tCmd.wdLoginID = ptCmd->wdLoginID;
			bcopy(ptCmd->name,tCmd.name,sizeof(tCmd.name),sizeof(tCmd.name));
			//FLClientManager::getInstance().sendTo(tCmd.wdLoginID,&tCmd,sizeof(tCmd));

			return true;
		}
		break;
		*/
		/*
		   new net charge
	case PARA_BILL_GETTOKEN:
		{
		}
		break;
		*/
	default:
		break;
	}

	Xlogger->error("ServerTask::msgParse_Bill(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

/**
* \brief 解析来自网关服务器的指令
*
* \param pNullCmd 待处理的指令
* \param nCmdLen 指令长度
* \return 处理是否成功
*/
bool ServerTask::msgParse_Gateway(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::Super;

	switch(pNullCmd->para)
	{
		case PARA_GATEWAY_NEWSESSION:
			{
				t_NewSession_Gateway *ptCmd = (t_NewSession_Gateway *)pNullCmd;
				Cmd::FL::t_NewSession_Session tCmd;

				tCmd.session = ptCmd->session;
				//FLClientManager::getInstance().sendTo(tCmd.session.wdLoginID,&tCmd,sizeof(tCmd));
				SuperService::getInstance().flClient->sendCmd(&tCmd, sizeof(tCmd));
				return true;
			}
			break;
	case PARA_GATEWAY_GYLIST:
		{
			//gateway -> super ->FL
			t_GYList_Gateway *ptCmd = (t_GYList_Gateway *)pNullCmd;
			Cmd::FL::t_GYList_FL tCmd;
			Xlogger->debug("%s,%d, Cmd::FL::t_GYList_FL",__PRETTY_FUNCTION__,__LINE__);


			///!what is this ??
			//通知网关,已经收到网关注册信息
			/*
			t_notifyFinish_Gateway gCmd;
			sendCmd(&gCmd,sizeof(gCmd));
			*/
			//!

			OnlineNum = ptCmd->wdNumOnline;

			/*
			Xlogger->info("GYList:%d,%s:%d,onlines=%u,state=%d",
					ptCmd->wdServerID,ptCmd->pstrIP,ptCmd->wdPort,ptCmd->wdNumOnline,ptCmd->state);
					*/

			//strncpy(tCmd.pstrIP,ptCmd->pstrIP,sizeof(tCmd.pstrIP)-1);
			tCmd.dwpstrIP = ptCmd->dwpstrIP;
			tCmd.wdServerID      = ptCmd->wdServerID;
			tCmd.wdPort          = ptCmd->wdPort;
			tCmd.wdNumOnline     = ptCmd->wdNumOnline;
			tCmd.state           = ptCmd->state;
			tCmd.zoneGameVersion = ptCmd->zoneGameVersion;
			SuperService::getInstance().flClient->sendCmd(&tCmd, sizeof(tCmd));
			//FLClientManager::getInstance().broadcast(&tCmd,sizeof(tCmd));

			return true;
		}
		break;
	/*
	case PARA_CHARNAME_GATEWAY:
		{
			//gateway -> super ->Rolereg
			t_Charname_Gateway *ptCmd = (t_Charname_Gateway *)pNullCmd;        
			Xlogger->debug("角色名称指令：%u,%s,%u",ptCmd->accid,ptCmd->name,ptCmd->state);
			//for simple, comment
			//if (!RoleregCache::getInstance().msgParse_loginServer(ptCmd->wdServerID,ptCmd->accid,ptCmd->name,ptCmd->state))
			{
				if (ptCmd->state & ROLEREG_STATE_TEST)
				{
					Xlogger->error("请求失败，不允许创建角色：%u,%s",ptCmd->accid,ptCmd->name);
					t_Charname_Gateway tCmd;
					bcopy(ptCmd,&tCmd,sizeof(tCmd),sizeof(tCmd));
					tCmd.state |= ROLEREG_STATE_HAS;  //设置已经存在标志
					sendCmd(&tCmd,sizeof(tCmd));
				}
				if (ptCmd->state & (ROLEREG_STATE_WRITE | ROLEREG_STATE_CLEAN))
				{
					//for simple, comment
					//RoleregCache::getInstance().add(*ptCmd);
				}
			}
			return true;
		}
		break;
	*/
	}

	Xlogger->error("ServerTask::msgParse_Gateway(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

/**
* \brief 解析GM工具的指令
*
* \param pNullCmd 待处理的指令
* \param nCmdLen 指令长度
* \return 处理是否成功
*/
bool ServerTask::msgParse_GmTool(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::GmTool;

	/*
	switch(pNullCmd->para)
	{
	case PARA_LOG_GMTOOL:
		{
			t_Log_GmTool * rev = (t_Log_GmTool *)pNullCmd;
			rev->zone = SuperService::getInstance().getZoneID();
			////---InfoClientManager::getInstance().broadcastOne(rev,nCmdLen);
			return true;
		}
		break;
	case PARA_CHAT_GMTOOL:
		{
			t_Chat_GmTool * rev = (t_Chat_GmTool *)pNullCmd;
			rev->zone = SuperService::getInstance().getZoneID();
			strncpy(rev->server,SuperService::getInstance().getZoneName().c_str(),MAX_NAMESIZE);

			////---InfoClientManager::getInstance().broadcastOne(rev,nCmdLen);
			return true;
		}
		break;
	case PARA_MSG_GMTOOL:
		{
			t_Msg_GmTool * rev = (t_Msg_GmTool *)pNullCmd;
			rev->zone = SuperService::getInstance().getZoneID();
			////---InfoClientManager::getInstance().broadcastOne(rev,sizeof(t_Msg_GmTool));
			return true;
		}
		break;
	case PARA_NEW_MSG_GMTOOL:
		{
			t_NewMsg_GmTool * rev = (t_NewMsg_GmTool *)pNullCmd;
			rev->zone = SuperService::getInstance().getZoneID();
			////---InfoClientManager::getInstance().broadcastOne(rev,sizeof(t_NewMsg_GmTool));
			return true;
		}
		break;
	case PARA_PUNISH_GMTOOL:
		{
			t_Punish_GmTool * rev = (t_Punish_GmTool *)pNullCmd;
			rev->zone = SuperService::getInstance().getZoneID();
			strncpy(rev->server,SuperService::getInstance().getZoneName().c_str(),MAX_NAMESIZE);
			////---InfoClientManager::getInstance().broadcastOne(rev,sizeof(t_Punish_GmTool));
			return true;
		}
		break;
	}
	*/

	return false;
}

bool ServerTask::msgParse_CountryOnline(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::Super;

	//for simple, comment
	/*
	switch(pNullCmd->para)
	{
	case PARA_COUNTRYONLINE:
		{
			t_CountryOnline * rev = (t_CountryOnline *)pNullCmd;
			BYTE pBuffer[x_socket::MAX_DATASIZE];
			Cmd::Info::t_Country_OnlineNum *cmd = (Cmd::Info::t_Country_OnlineNum *)pBuffer;
			constructInPlace(cmd);
			cmd->rTimestamp = rev->rTimestamp;
			cmd->GameZone = SuperService::getInstance().getZoneID();
			cmd->OnlineNum = rev->OnlineNum;

			for(DWORD i = 0; i < cmd->OnlineNum; i++)
			{
				cmd->CountryOnline[i].country = rev->CountryOnline[i].country;
				cmd->CountryOnline[i].num = rev->CountryOnline[i].num;
			}
			return true;////---InfoClientManager::getInstance().sendTo(rev->infoTempID,cmd,sizeof(Cmd::Info::t_Country_OnlineNum) + cmd->OnlineNum * sizeof(Cmd::Info::t_Country_OnlineNum::Online));
		}
		break;
	}
	*/

	return false;
}

/**
* \brief 解析来自各个服务器连接的指令
*
* \param pNullCmd 待处理的指令
* \param nCmdLen 指令长度
* \return 处理是否成功
*/
bool ServerTask::msgParse(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	//here can back up msg,for debug
	switch(pNullCmd->cmd)
	{
	case Cmd::Super::CMD_STARTUP:
		if (msgParse_Startup(pNullCmd,nCmdLen))
		{
			return true;
		}
		break;
	case Cmd::Super::CMD_BILL:
		if (msgParse_Bill(pNullCmd,nCmdLen))
		{
			return true;
		}
		break;
	case Cmd::Super::CMD_GATEWAY:
		if (msgParse_Gateway(pNullCmd,nCmdLen))
		{
			return true;
		}
		break;
	case Cmd::GmTool::CMD_GMTOOL:
		if (msgParse_GmTool(pNullCmd,nCmdLen))
		{
			return true;
		}
		break;
	case Cmd::Super::CMD_COUNTRYONLINE:
		if (msgParse_CountryOnline(pNullCmd,nCmdLen))
		{
			return true;
		}
		break;
	case Cmd::Super::CMD_SESSION:
		{
			switch(pNullCmd->para)
			{
			case Cmd::Super::PARA_SHUTDOWN:
				{
					SuperService::getInstance().Terminate();
					Xlogger->info("Session请求停机维护");
					return true;
				}
				break;
			}
		}
		break;
	}

	Xlogger->error("ServerTask::msgParse(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

void ServerTask::handle_msg(const void* ptr, const uint32_t len) {
	msgParse((const Cmd::t_NullCmd*)ptr,len);
	async_read();
}

void ServerTask::close()
{
	/*
	state_wait_.reset();
	state_wait_sync_.reset();
	*/
	tcp_task::close();
}
