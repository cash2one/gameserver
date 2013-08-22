#pragma once
#include "command.h"	//common.h: GameZone_t
#include "tcp_task.h"
#include <string>

class ServerTask : public tcp_task
{

public:
	DWORD old;
	ServerTask(io_service & io) : tcp_task(io){ }

	~ServerTask() { }

	virtual void handle_verify(const void* ptr, const uint32_t len);
	//int verifyConn();
	bool uniqueAdd();
	bool uniqueRemove();
	bool msgParse(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
	virtual void handle_msg(const void* ptr, const uint32_t len);

	/*void setZoneID(const GameZone_t &gameZone)
	{
	this->gameZone = gameZone;
	}*/

	const GameZone_t &getZoneID() const { return gameZone; }
private:

	GameZone_t gameZone;
	std::string name;

	bool msgParse_gyList(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
	bool msgParse_session(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);

};
