#pragma once

#include "common.h"
#include "tcp_task.h"
#include "scenecmd.h"
#include "x_msgqueue.h"
using namespace Cmd;

class SceneTask : public tcp_task, public MessageQueue
{
  public:
    SceneTask(io_service& ios) : tcp_task(ios) {
      wdServerID = 0;
      wdServerType = UNKNOWNSERVER;
    }

    virtual ~SceneTask() {}

	void handle_verify(const void* ptr, const uint32_t len);
	//void handle_wait_sync(const void* ptr, const uint32_t len);
	//bool verify_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);
	//bool wait_sync_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);
    int recycleConn();

    const WORD getID() const { return wdServerID; }
    const WORD getType() const { return wdServerType; }

	virtual bool cmdMsgParse(const Cmd::t_NullCmd *,const uint32_t);
	virtual void handle_msg(const void * ptr, const uint32_t len);

private:
    WORD wdServerID;          /**< 服务器编号,一个区唯一的 */
    WORD wdServerType;          /**< 服务器类型 */

    bool verifyLogin(const Cmd::Scene::t_LoginScene *ptCmd);
    bool msgParse_Gateway(const Cmd::t_NullCmd *,const DWORD);
    bool msgParse_Scene(const Cmd::t_NullCmd*,const DWORD);
};
