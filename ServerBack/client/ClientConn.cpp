#include "ClientConn.h"

//push cmd to queue
void ClientConn::msg_parse(const void *cmd, const uint32_t len)
{
	const Cmd::t_NullCmd *pNullCmd = (const Cmd::t_NullCmd *)cmd;
	msgParse(pNullCmd, len);
}
bool ClientConn::cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len){
	switch(cmd->cmd)
	{
		default:
			break;
	}
}
