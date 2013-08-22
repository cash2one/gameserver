#include "FLClient.h"
#include "SuperServer.h"
#include "ServerManager.h"

WORD FLClient::tempidAllocator = 0;

FLClient::FLClient(boost::asio::io_service & ios):tcp_client(ios) ,tempid(++tempidAllocator),netType(NetType_near) { }

FLClient::~FLClient() {
  Xlogger->debug("FLClient::~FLClient");
}

/*
void FLClient::addToContainer()
{
  Xlogger->debug("FLClient::addToContainer");
  FLClientManager::getInstance().add(this);
}

void FLClient::removeFromContainer()
{
  Xlogger->debug("FLClient::removeFromContainer");
  FLClientManager::getInstance().remove(this);
}
*/

/*
bool FLClient::connect() {
  if (!x_tcp_clientTask::connect())
    return false;

  using namespace Cmd::FL;
  t_LoginFL cmd;
  strncpy(cmd.strIP,SuperService::getInstance().getIP(),sizeof(cmd.strIP));
  cmd.port = SuperService::getInstance().getPort();
  return sendCmd(&cmd,sizeof(cmd));
}
*/

bool FLClient::msgParse_gyList(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::FL;

	switch(pNullCmd->para)
	{
		case PARA_FL_RQGYLIST:
			{
				Xlogger->debug("PARA_FL_RQGYLIST");
				Cmd::Super::t_RQGYList_Gateway tCmd;
				return ServerManager::getInstance().broadcastByType(GATEWAYSERVER,&tCmd,sizeof(tCmd));
			}
			break;
	}

	Xlogger->error("FLClient::msgParse_gyList(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool FLClient::msgParse_session(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd::FL;

	switch(pNullCmd->para)
	{
		case PARA_SESSION_NEWSESSION:
			{
				t_NewSession_Session *ptCmd = (t_NewSession_Session *)pNullCmd;
				Cmd::Super::t_NewSession_Bill tCmd;

				tCmd.session = ptCmd->session;
				tCmd.session.wdLoginID = tempid;
				//bcopy(&ptCmd->session,&tCmd.session,sizeof(tCmd.session));

				return ServerManager::getInstance().broadcastByType(BILLSERVER,&tCmd,sizeof(tCmd));
			}
			break;
	}

	Xlogger->error("FLClient::msgParse_session(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool FLClient::cmdMsgParse(const Cmd::t_NullCmd* pNullCmd, const uint32_t nCmdLen) {
	using namespace Cmd::FL;

	switch(pNullCmd->cmd)
	{
		case CMD_LOGIN:
			{
				if (pNullCmd->para == PARA_LOGIN_OK) {
					t_LoginFL_OK *ptCmd = (t_LoginFL_OK *)pNullCmd;
					Xlogger->debug("login FLServer success, zoneid=%u(gameid=%u,zone=%u),name=%s,nettype=%u",
							ptCmd->gameZone.id, ptCmd->gameZone.game, ptCmd->gameZone.zone, ptCmd->name, ptCmd->netType);
					netType = (ptCmd->netType == 0 ? NetType_near : NetType_far);
					SuperService::getInstance().setZoneID(ptCmd->gameZone);
					SuperService::getInstance().setZoneName(ptCmd->name);
					return true;
				}
			}
			break;
		case CMD_GYLIST:
			{
				if (msgParse_gyList(pNullCmd,nCmdLen))
					return true;
			}
			break;
		case CMD_SESSION:
			{
				if (msgParse_session(pNullCmd,nCmdLen))
					return true;
			}
			break;
	}

	Xlogger->error("FLClient::msgParse(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}
