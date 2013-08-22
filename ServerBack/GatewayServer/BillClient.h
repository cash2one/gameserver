#pragma once

#include "common.h"
#include "x_nullcmd.h"
#include "tcp_client.h"
#include "billcmd.h"
#include "supercmd.h"

using namespace Cmd;

class BillClient : public tcp_client
{
public:
	BillClient(boost::asio::io_service &ios):tcp_client(ios){ }
	~BillClient(){
		Xlogger->debug("%s", __PRETTY_FUNCTION__);
	}
	//push cmd to queue
	virtual void msg_parse(const void *cmd, const uint32_t len)
	{
		const Cmd::t_NullCmd *pNullCmd = (const Cmd::t_NullCmd *)cmd;
		msgParse(pNullCmd, len);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len);
	/*
	{
		using namespace Cmd::Bill;
		switch(cmd->cmd)
		{
			case Cmd::Bill::CMD_GATE:
				{
					switch(cmd->para){
						case Cmd::Bill::PARA_GATE_SESSION_TEST:
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
	*/
};
