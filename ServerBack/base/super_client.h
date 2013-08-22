#pragma once

#include "common.h"
#include "tcp_client.h"
#include "x_logger.h"
#include "supercmd.h"

class super_client : public tcp_client
{
public:
	bool verified;
	super_client(boost::asio::io_service &ios):tcp_client(ios){
   		verified = false;
	}
	~super_client(){
		Xlogger->debug("%s", __PRETTY_FUNCTION__);
	}
	//push cmd to queue
	virtual void msg_parse(const void *cmd, const uint32_t len)
	{
		const Cmd::t_NullCmd *pNullCmd = (const Cmd::t_NullCmd *)cmd;
		if (verified)
			msgParse(pNullCmd, len);
		else
			cmdMsgParse(pNullCmd, len);
		//async_read_msg();
		//Xlogger->error("SuperClient::msgParse(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len)
	try{
		switch(cmd->cmd)
		{
			case Cmd::Super::CMD_STARTUP:
				if (msgParse_Startup(cmd,len)) return true;
				break;
			default:
				if (x_subnetservice::getSingletonPtr()->msgParse_SuperService(cmd, len)) return true;
				break;
		}
		return false;
	}
	catch(boost::system::system_error& error){
		Xlogger->error("%s: what=",error.what());
		x_subnetservice::getSingleton().Terminate();
		return false;
	}
	bool msgParse_Startup(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
	{
		using namespace Cmd::Super;

		switch(pNullCmd->para)
		{
			case PARA_GAMETIME:
				{
					t_GameTime *ptCmd = (t_GameTime *)pNullCmd;

					Xlogger->trace("PARA_GAMETIME %lu",ptCmd->qwGameTime);
					Seal::qwGameTime = ptCmd->qwGameTime;
					return true;
				}
				break;
			case PARA_STARTUP_RESPONSE:
				{
					t_Startup_Response *ptCmd = (t_Startup_Response *)pNullCmd;

					Xlogger->trace("PARA_STARTUP_RESPONSE %u,%u,%u,%u",ptCmd->wdServerID,ptCmd->wdPort,ptCmd->wdExtPort,ptCmd->wdNetType);
					const size_t msgLength = sizeof(*ptCmd)+ptCmd->wdSize*sizeof(Cmd::Super::ServerEntry);
					if (msgLength > nCmdLen) {
						Xlogger->debug("PARA_STARTUP_RESPONSE msg length error");
						return false;
					}
					x_subnetservice::getSingletonPtr()->setServerInfo(ptCmd);
					//verified = true;
					return true;
				}
				break;
			case PARA_STARTUP_SERVERENTRY_NOTIFYME:
				{
					//t_Startup_ServerEntry_NotifyMe *ptCmd = (t_Startup_ServerEntry_NotifyMe *)pNullCmd;

					/*
					Xlogger->trace("PARA_STARTUP_SERVERENTRY_NOTIFYME size = %d ",ptCmd->size );
					for(uint16_t i = 0; i < ptCmd->size; i++)
					{
						x_subnetservice::getSingletonPtr()->addServerEntry(ptCmd->entry[i]);
					}
					*/
					verified = true;
					return true;
				}

				break;
			case PARA_STARTUP_SERVERENTRY_NOTIFYOTHER:
				{
					t_Startup_ServerEntry_NotifyOther *ptCmd = (t_Startup_ServerEntry_NotifyOther *)pNullCmd;

					Xlogger->debug("PARA_STARTUP_SERVERENTRY_NOTIFYOTHER");
					x_subnetservice::getSingletonPtr()->addServerEntry(ptCmd->entry);
					async_write(ptCmd,nCmdLen);
					return true;
				}
				break;
			default:
				Xlogger->error("SuperClient::msgParse_Startup(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
				break;
		}

		//Xlogger->error("SuperClient::msgParse_Startup(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
		return false;
	}
};
