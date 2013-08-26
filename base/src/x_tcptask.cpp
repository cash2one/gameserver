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
* \brief ���ͻ����е����ݵ��׽ӿ�,�ٵ������֮ǰ��֤�Ѿ����׽ӿڽ�������ѯ
*
* \return �����Ƿ�ɹ�,true��ʾ���ͳɹ�,false��ʾ����ʧ��,������Ҫ�Ͽ�����
*/
bool x_tcptask::ListeningSend()
{
	return mSocket.sync();
}

/**
* \brief ��TCP�������񽻸���һ���������,�л�״̬
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
* \brief ��ֵ��������״̬,��������
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
		* ���sync�������ӵ�okay������ʧ�ܻ����okay״̬resetState�Ŀ�����
		*/
		//case okay:
	case recycle:
		//�����ܵ�
		Xlogger->fatal("x_tcptask::resetState:������ recycle -> recycle");
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
			//�����ź���ָ��ʱ�䷶Χ��û�з���
			Xlogger->error("�׽ӿڼ������ź�ʧ��");
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

