#include "x_tcptask.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
//#include <assert.h>

bool x_tcptask::sendCmd(const void *pstrCmd,int nCmdLen)
{
	return mSocket.sendCmd(pstrCmd,nCmdLen,buffered);
}

bool x_tcptask::sendCmdNoPack(const void *pstrCmd,int nCmdLen)
{
	return mSocket.sendCmdNoPack(pstrCmd,nCmdLen,buffered);
}

bool x_tcptask::ListeningRecv(bool needRecv)
{
	int retcode = 0;
	if (needRecv) {
		retcode = mSocket.recvToBuf_NoPoll();
	}
	//struct timeval tv_2;
	if (-1 == retcode)
	{
		Xlogger->debug("x_tcptask::ListeningRecv -1");  
		return false;
	}
	else
	{
		do
		{
			BYTE pstrCmd[x_socket::MAX_DATASIZE];
			int nCmdLen = mSocket.recvToCmd_NoPoll(pstrCmd,sizeof(pstrCmd));
			if (nCmdLen <= 0)
				break;
			else
			{
				Cmd::t_NullCmd *pNullCmd = (Cmd::t_NullCmd *)pstrCmd;
				if (Cmd::CMD_NULL == pNullCmd->cmd && Cmd::PARA_NULL == pNullCmd->para)
				{
					clearTick();
				}
				else
				{
					msgParse(pNullCmd,nCmdLen);
				}
			}
		}
		while(true);
	}

	return true;
}

/**
* \brief 发送缓冲中的数据到套接口,再调用这个之前保证已经对套接口进行了轮询
*
* \return 发送是否成功,true表示发送成功,false表示发送失败,可能需要断开连接
*/
bool x_tcptask::ListeningSend()
{
	return mSocket.sync();
}

/**
* \brief 把TCP连接任务交给下一个任务队列,切换状态
*
*/
void x_tcptask::getNextState()
{
	zTCPTask_State old_state = getState();

	switch(old_state)
	{
	case notuse:
		setState(verify);
		break;
	case verify:
		setState(sync);
		break;
	case sync:
		buffered = true;	//!!
		addToContainer();
		setState(okay);
		break;
	case okay:
		removeFromContainer();
		setState(recycle);
		break;
	case recycle:
		setState(notuse);
		break;
	}

	Xlogger->debug("%s(%s:%u),%s -> %s)",__FUNCTION__, getIP(),getPort(),getStateString(old_state),getStateString(getState()));
}

/**
* \brief 重值连接任务状态,回收连接
*
*/
void x_tcptask::resetState()
{
	zTCPTask_State old_state = getState();

	switch(old_state)
	{
	case notuse:
		/*
		* whj 
		* 如果sync情况下添加到okay管理器失败会出现okay状态resetState的可能性
		*/
		//case okay:
	case recycle:
		//不可能的
		Xlogger->fatal("x_tcptask::resetState:不可能 recycle -> recycle");
		break;
	case verify:
	case sync:
	case okay:
		break;
	}

	setState(recycle);
	Xlogger->debug("%s(%s:%u),%s -> %s)",__FUNCTION__,getIP(),getPort(),getStateString(old_state),getStateString(getState()));
}

void x_tcptask::checkSignal(const double ct)
{
	if (ifCheckSignal() && checkInterval(ct))
	{
		if (checkTick())
		{
			//测试信号在指定时间范围内没有返回
			Xlogger->error("套接口检查测试信号失败");
			Terminate(x_tcptask::terminate_active);
		}
		else
		{
			//send test signal
			Cmd::t_NullCmd tNullCmd;
			if (sendCmd(&tNullCmd,sizeof(tNullCmd)))
				setTick();
		}
	}
}

