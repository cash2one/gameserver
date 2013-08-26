#pragma once

#include "common.h"
#include "tcp_task.h"
#include "command.h"
using namespace Cmd;

class GatewayTask : public tcp_task
{
  public:
    GatewayTask(io_service& ios) : tcp_task(ios) {
    }

    virtual ~GatewayTask() {}

	void handle_verify(const void* ptr, const uint32_t len);
	//void handle_wait_sync(const void* ptr, const uint32_t len);
	//bool wait_sync_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);

	virtual void handle_msg(const void * ptr, const uint32_t len);

private:

    bool verifyLogin(const Cmd::stNullUserCmd *ptCmd);
};
