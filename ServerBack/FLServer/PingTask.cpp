#include "command.h"
#include "PingTask.h"
#include "flcmd.h"

bool PingTask::verify_msg(const Cmd::t_NullCmd* cmd, const uint32_t len) {
	using namespace Cmd;
	stLoginPing *ptCmd = (stLoginPing *)cmd;
	if (PING_USERCMD == ptCmd->byCmd && LOGIN_PING_PARA == ptCmd->byParam)  
		dwClientVersion = ptCmd->version;
		Xlogger->debug("%s : success", __PRETTY_FUNCTION__);
		set_state(WAIT_SYNC);
		return true;
	}
	return false;
}

int PingTask::recycleConn() {
	Xlogger->debug("PingTask::recycleConn");
	return 1;
}

bool PingTask::msgParse(const Cmd::t_NullCmd *ptNull,const DWORD nCmdLen)
{
	using namespace Cmd;
	const stNullUserCmd *pNullCmd = (const stNullUserCmd *)ptNull;

	if (PING_USERCMD == pNullCmd->byCmd)
	{
		switch(pNullCmd->byParam)
		{
		case REQUEST_PING_LIST_PARA:
			{

				stRequestPingList* pingCmd = (stRequestPingList*)pNullCmd;
				GameZone_t gameZone;
				gameZone.id = pingCmd->id;
				//BYTE buf[x_socket::MAX_DATASIZE];

				//stPingList *retCmd=(stPingList *)buf;
				//constructInPlace(retCmd);

				stPingList retCmd;

				GYListManager::getInstance().full_ping_list(&retCmd,gameZone);
				//          sendCmd(retCmd,(retCmd->size*sizeof(Cmd::ping_element)+sizeof(Cmd::stRequestPingList)));
				Xlogger->info("PING_USERCMD,zone=%d,ip=%d",retCmd.zone_id,retCmd.ping_list.gateway_ip);
				sendCmd(&retCmd,sizeof(retCmd));
				return true;
			}
			break;
		}
	}

	Xlogger->error("PingTask::msgParse(%d,%d,%d)",ptNull->cmd,ptNull->para,nCmdLen);
	return false;
}

void PingTask::msg_parse(const void* ptr, const uint32_t len) {
	msgParse((const Cmd::t_NullCmd*)ptr,len);
	async_read_msg();
}
