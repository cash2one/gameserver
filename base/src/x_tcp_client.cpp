#include "x_tcp_client.h"
#include <strings.h>
#include <boost/timer.hpp>
#include <boost/thread.hpp>

typedef boost::chrono::milliseconds ms;
/**
* \brief 建立一个到服务器的TCP连接
*
*
* \return 连接是否成功
*/
bool x_tcp_client::connect()
{
#ifdef _LQ_DEBUG
	Xlogger->debug("x_tcp_client::connect");
#endif
	int retcode;
	int nSocket;
	struct sockaddr_in addr;

	nSocket = ::socket(PF_INET,SOCK_STREAM,0);
	if (INVALID_SOCKET == nSocket)
	{
		Xlogger->debug("%s:%u",__PRETTY_FUNCTION__,__LINE__);
		return false;
	}

	//set buffer size should be before connect
	int window_size = 128 * 1024;
	retcode = ::setsockopt(nSocket,SOL_SOCKET,SO_RCVBUF,(char*)&window_size,sizeof(window_size));
	if (0 != retcode)
	{
		::close(nSocket);
		return false;
	}
	retcode = ::setsockopt(nSocket,SOL_SOCKET,SO_SNDBUF,(char*)&window_size,sizeof(window_size));
	if (0 != retcode)
	{
		::close(nSocket);
		return false;
	}

	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip.c_str());
	addr.sin_port = htons(port);

	retcode = ::connect(nSocket,(struct sockaddr *) &addr,sizeof(addr));
	if (-1 != retcode)
	{
		Xlogger->error("connect to (%s:%u) failed",ip.c_str(),port);
		::close(nSocket);
		return false;
	}

	pSocket.reset(new x_socket(nSocket,&addr));
	if (!pSocket)
	{
		Xlogger->debug("%s:%u",__PRETTY_FUNCTION__,__LINE__);
		::close(nSocket);
		return false;
	}

	Xlogger->debug("connect to (%s:%u) success",ip.c_str(),port);

	return true;
}

bool x_tcp_client::sendCmd(const void *pstrCmd,const int nCmdLen)
{
#ifdef _DEBUG
	Xlogger->debug("x_tcp_client::sendCmd");
#endif 
	if (!pSocket) 
		return false;
	else
	{
		return pSocket->sendCmd(pstrCmd,nCmdLen);
	}
}

void x_tcp_client::operator()()
{
#ifdef _DEBUG
	Xlogger->error("x_tcp_client::remoteport= %u localport = %u",pSocket->getPort(),pSocket->getLocalPort());
#endif //_DEBUG
	while(!is_final())
	{
		BYTE pstrCmd[x_socket::MAX_DATASIZE];
		int nCmdLen = pSocket->recvToCmd(pstrCmd,x_socket::MAX_DATASIZE,false);
		if (nCmdLen > 0) 
		{
			Cmd::t_NullCmd *pNullCmd = (Cmd::t_NullCmd *)pstrCmd;
			if (Cmd::CMD_NULL == pNullCmd->cmd && Cmd::PARA_NULL == pNullCmd->para)
			{
				//Xlogger->debug("client receive test signal");
				if (!sendCmd(pstrCmd,nCmdLen))
				{
					Xlogger->error("send error::remoteport= %u localport = %u",pSocket->getPort(),pSocket->getLocalPort());
					//send cmd failed, quit loop, end thread
					break;
				}
			}
			else
				msgParse(pNullCmd,nCmdLen);
		}
		else if (-1 == nCmdLen)
		{
			Xlogger->error("receive cmd failed, close socket");
			break;
		}
	}
}

bool x_tcp_buffer_client::sendCmd(const void *pstrCmd,const int nCmdLen)
{
	if (pSocket)
 		return pSocket->sendCmd(pstrCmd,nCmdLen,_buffered);
	else
		return false;
}

bool x_tcp_buffer_client::ListeningRecv()
{
#ifdef _DEBUG
	Xlogger->debug("x_tcp_buffer_client::ListeningRecv");
#endif //_DEBUG
	int retcode = pSocket->recvToBuf_NoPoll();
	if (-1 == retcode) {
		Xlogger->debug("%s:%u",__PRETTY_FUNCTION__,__LINE__);
	   	return false;
	}
	while(true)
	{
		BYTE pstrCmd[x_socket::MAX_DATASIZE];
		int nCmdLen = pSocket->recvToCmd_NoPoll(pstrCmd,sizeof(pstrCmd));
		if (nCmdLen <= 0) break;
		else
		{
			Cmd::t_NullCmd *pNullCmd = (Cmd::t_NullCmd *)pstrCmd;
			if (Cmd::CMD_NULL == pNullCmd->cmd && Cmd::PARA_NULL == pNullCmd->para)
			{
				Xlogger->debug("%s:%u, receive test cmd",__PRETTY_FUNCTION__,__LINE__);
				if (!sendCmd(pstrCmd,nCmdLen)) return false;
			}
			else msgParse(pNullCmd,nCmdLen);
		}
	}
	return true;
}

bool x_tcp_buffer_client::ListeningSend()
{  
#ifdef _DEBUG
	Xlogger->debug("x_tcp_buffer_client::ListeningSend");
#endif //_DEBUG
	if (pSocket)
		return pSocket->sync();
	else
		return false;
}

void x_tcp_buffer_client::sync()
{
#ifdef _DEBUG
	Xlogger->debug("x_tcp_buffer_client::sync");
#endif //_DEBUG
	if (pSocket)
		pSocket->force_sync();
}

void x_tcp_buffer_client::operator()()
{
	_buffered = true;
	int epfd = epoll_create(256);
	int epfd_r = epoll_create(256);
	pSocket->add_epoll(epfd, EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLPRI, NULL);
	pSocket->add_epoll(epfd_r, EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLPRI, NULL);
	struct epoll_event ep_event, ep_event_r;
	ep_event.events = 0;
	ep_event_r.events = 0;

	boost::timer timer1;
	boost::timer timer2;

	while(!is_final())
	{
		boost::this_thread::sleep_for(ms(2));

		if (timer1.elapsed() >= 0.002)	//second 
		{
			timer1.restart();
			if (epoll_wait(epfd_r, &ep_event_r,1,0) > 0)
			{
				if (ep_event_r.events & (EPOLLERR | EPOLLPRI))
				{
					Xlogger->error("%s, socket error",__PRETTY_FUNCTION__);
					break;
				}
				else
				{
					if (ep_event_r.events & EPOLLIN)
					{
						if (!ListeningRecv())
						{
							Xlogger->error("%s, read error",__PRETTY_FUNCTION__);
							break;
						}
					}
				}
				ep_event_r.events = 0;
			}
		}

		if (timer2.elapsed() >= (usleep_time/1000))
		{
			timer2.restart();
			if (epoll_wait(epfd, &ep_event, 1, 0) > 0)
			{
				if (ep_event.events & (EPOLLERR | EPOLLPRI))
				{
					Xlogger->error("%s, socket error",__PRETTY_FUNCTION__);
					break;
				}
				else
				{
					if (ep_event.events & EPOLLIN)
					{
						if (!ListeningRecv())
						{
							Xlogger->error("%s, read error",__PRETTY_FUNCTION__);
							break;
						}
					}
					if (ep_event.events & EPOLLOUT)
					{
						if (!ListeningSend())
						{
							Xlogger->error("%s, write error",__PRETTY_FUNCTION__);
							break;
						}
					}
				}
				ep_event.events = 0;
			}
		}
	}

	//make sure send all the buffer data
	sync();
	_buffered = false;
}

