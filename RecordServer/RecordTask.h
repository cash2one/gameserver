#pragma once

#include "common.h"
#include "tcp_task.h"
#include "recordcmd.h"
#include "x_msgqueue.h"
using namespace Cmd;

class RecordTask : public tcp_task//, public MessageQueue
{
  public:
    RecordTask(io_service& ios) : tcp_task(ios) {
      wdServerID = 0;
      wdServerType = UNKNOWNSERVER;
    }

    virtual ~RecordTask() {}

	void handle_verify(const void* ptr, const uint32_t len);
	void handle_msg(const void* ptr, const uint32_t len);
	//void handle_wait_sync(const void* ptr, const uint32_t len);
	bool verify_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);
	//bool wait_sync_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);
    int recycleConn();

    const WORD getID() const { return wdServerID; }

    const WORD getType() const { return wdServerType; }

	virtual bool cmdMsgParse(const Cmd::t_NullCmd *,const uint32_t);

private:
    WORD wdServerID;          /**< 服务器编号,一个区唯一的 */
    WORD wdServerType;          /**< 服务器类型 */

    bool verifyLogin(const Cmd::Record::t_LoginRecord *ptCmd);
    bool msgParse_Gateway(const Cmd::t_NullCmd *,const DWORD);
    bool getSelectInfo(DWORD accid, DWORD countryid);
    bool msgParse_Scene(const Cmd::t_NullCmd *,const DWORD);
    bool msgParse_Session(const Cmd::t_NullCmd*,const DWORD);

	/*
    bool readCharBase(const Cmd::Record::t_ReadUser_SceneRecord *rev);
    bool saveCharBase(const Cmd::Record::t_WriteUser_SceneRecord *rev);
	*/

    //static const dbCol charbase_define[];

	/*
#ifdef _TEST_DATA_LOG
    static const dbCol chartest_define[];
    bool readCharTest(Cmd::Record::t_Read_CharTest_SceneRecord *rev);
    bool insertCharTest(Cmd::Record::t_Insert_CharTest_SceneRecord *rev);
    bool updateCharTest(Cmd::Record::t_Update_CharTest_SceneRecord *rev);
    bool deleteCharTest(Cmd::Record::t_Delete_CharTest_SceneRecord *rev);
#endif
*/
};
