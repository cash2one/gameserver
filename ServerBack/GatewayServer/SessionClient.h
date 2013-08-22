#pragma once

#include "common.h"
#include "tcp_client.h"
#include "x_logger.h"
#include "sessioncmd.h"

class SessionClient : public tcp_client
{
public:
	SessionClient(boost::asio::io_service &ios):tcp_client(ios){
	}
	~SessionClient(){
		Xlogger->debug("%s", __PRETTY_FUNCTION__);
	}
	//push cmd to queue
	virtual void msg_parse(const void *cmd, const uint32_t len)
	{
		const Cmd::t_NullCmd *pNullCmd = (const Cmd::t_NullCmd *)cmd;
		msgParse(pNullCmd, len);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len){
		using namespace Cmd::Session;
		switch(cmd->cmd)
		{
			case Cmd::Session::CMD_GATE:
				{
					switch(cmd->para){
						case Cmd::Session::PARA_GATE_SESSION_TEST:
							{
								Xlogger->debug("sessionclient:get response from sessionserver");
								return true;
							}
							break;
						default:
							break;
					}
				}
				break;
			default:
				break;
		}
		return false;
	}
};
