#pragma once

#include "common.h"
#include "tcp_task.h"
#include "billcmd.h"
#include "x_msgqueue.h"
#include <boost/thread/mutex.hpp>
using namespace Cmd;

class BillTask : public tcp_task, public MessageQueue
{
  public:
    BillTask(io_service& ios) : tcp_task(ios) {
      wdServerID = 0;
      wdServerType = UNKNOWNSERVER;
    }

    virtual ~BillTask() {}

	void handle_verify(const void* ptr, const uint32_t len);
	void handle_msg(const void* ptr, const uint32_t len);
	//void handle_wait_sync(const void* ptr, const uint32_t len);
	//bool wait_sync_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);
    int recycleConn();

	bool uniqueAdd();
	bool uniqueRemove();

    const WORD getID() const { return wdServerID; }
    const WORD getType() const { return wdServerType; }

	virtual bool cmdMsgParse(const Cmd::t_NullCmd *,const uint32_t);

	bool sendCmdToUser(const uint32_t id, const void* pstrCmd, const uint32_t len);
	bool sendCmdToScene(const uint32_t id, const void* pstrCmd, const uint32_t len);
private:
    WORD wdServerID;          /**< 服务器编号,一个区唯一的 */
    WORD wdServerType;          /**< 服务器类型 */

	boost::mutex mlock;

    bool verifyLogin(const Cmd::Bill::t_LoginBill *ptCmd);
	/*
    bool msgParse_Gateway(const Cmd::t_NullCmd *,const DWORD);
    bool getSelectInfo(DWORD accid, DWORD countryid);
    bool msgParse_Scene(const Cmd::t_NullCmd *,const DWORD);
    bool msgParse_Session(const Cmd::t_NullCmd*,const DWORD);
	*/
};
