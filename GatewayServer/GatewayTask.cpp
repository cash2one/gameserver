#include "GatewayTask.h"
#include "GatewayServer.h"

void GatewayTask::handle_msg(const void* ptr, const uint32_t len){
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	async_read();
}

bool GatewayTask::verifyLogin(const Cmd::stNullUserCmd *ptCmd)
{
	//Xlogger->info("GatewayTask::verifyLogin(id=%d type=%u)",ptCmd->wdServerID,ptCmd->wdServerType);
	using namespace Cmd;

	if (LOGON_USERCMD == ptCmd->byCmd  && USER_VERIFY_VER_PARA == ptCmd->byParam) {
		return true;
	}

	return false;
}

void GatewayTask::handle_verify(const void* pstrCmd, const uint32_t len) {
	using namespace Cmd;
	if (verifyLogin((const Cmd::stNullUserCmd *)pstrCmd)) {
		Xlogger->debug("%s ok", __PRETTY_FUNCTION__);
		if (uniqueAdd())
		{
			set_state(state_okay_);
			return ;
		}
	}
	Xlogger->debug("%s failed", __PRETTY_FUNCTION__);
}

