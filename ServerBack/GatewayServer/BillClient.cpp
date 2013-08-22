#include "BillClient.h"
#include "GatewayServer.h"
#include "LoginSessionManager.h"
using namespace Cmd;

bool BillClient::cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len)
{
	using namespace Cmd::Bill;
	using namespace Cmd;
	switch(cmd->para) {
		case Cmd::Bill::CMD_GATE:
			{
				switch(cmd->para) {
					case PARA_GATE_NEWSESSION:
						{
							const Cmd::Bill::t_NewSession_Gateway *ptCmd = (const Cmd::Bill::t_NewSession_Gateway*)cmd;
							Cmd::Super::t_NewSession_Gateway tCmd;
							Xlogger->info("PARA_GATE_NEWSESSION %d,%d,%d:%d",ptCmd->session.accid,ptCmd->session.loginTempID,
									ptCmd->session.dwpstrIP,ptCmd->session.wdPort);

							LoginSessionManager::getSingleton().put(ptCmd->session);
							tCmd.session = ptCmd->session;
							return GatewayService::getInstance().sendCmdToSuperServer(&tCmd,sizeof(tCmd));
						}
						break;
				}
			}
			break;
	}
	return false;
}
