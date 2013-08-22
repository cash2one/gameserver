#pragma once

#include "common.h"
#include "tcp_client.h"
#include "recordcmd.h"

class RecordClient : public tcp_client
{
public:
	RecordClient(boost::asio::io_service &ios):tcp_client(ios){
	}
	~RecordClient(){
		Xlogger->debug("%s", __PRETTY_FUNCTION__);
	}
	//push cmd to queue
	virtual void msg_parse(const void *cmd, const uint32_t len)
	{
		const Cmd::t_NullCmd *pNullCmd = (const Cmd::t_NullCmd *)cmd;
		msgParse(pNullCmd, len);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len){
		switch(cmd->cmd)
		{
			default:
				break;
		}
	}
};
