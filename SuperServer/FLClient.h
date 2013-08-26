#pragma once

#include "x_nullcmd.h"
#include "common.h"
#include "tcp_client.h"

class FLClient : public tcp_client
{
  public:

    FLClient(boost::asio::io_service & ios);
    ~FLClient();

    int checkRebound();
    void addToContainer();
    void removeFromContainer();
	//push cmd to queue
	virtual void msg_parse(const void *cmd, const uint32_t len)
	{
		const Cmd::t_NullCmd *pNullCmd = (const Cmd::t_NullCmd *)cmd;
		msgParse(pNullCmd, len);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd* cmd, const uint32_t len);

    /**
     * \brief 获取临时编号
     * \return 临时编号
     */
    const WORD getTempID() const
    {
      return tempid;
    }

    const NetType getNetType() const
    {
      return netType;
    }

  private:

    const WORD tempid;
    static WORD tempidAllocator;
    NetType netType;

    bool msgParse_gyList(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
    bool msgParse_session(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);

};
