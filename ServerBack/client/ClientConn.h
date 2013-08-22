#pragma once

#include "common.h"
#include "tcp_client.h"
#include "x_logger.h"
#include "command.h"

class ClientConn : public tcp_client
{
public:
	ClientConn(boost::asio::io_service &ios):tcp_client(ios){
	}
	~ClientConn(){
		Xlogger->debug("%s", __PRETTY_FUNCTION__);
	}
	//push cmd to queue
	virtual void msg_parse(const void *cmd, const uint32_t len);
	virtual bool cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len);
};
