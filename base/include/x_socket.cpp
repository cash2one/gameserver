#include <fcntl.h>
#include "x_socket.h"
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <zlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <iostream>

template <>
t_BufferCmdQueue::ByteBuffer()
: _maxSize(trunkSize),_offPtr(0),_currPtr(0),_buffer(_maxSize) { }

template <>
t_StackCmdQueue::ByteBuffer()
: _maxSize(PACKET_ZIP_BUFFER),_offPtr(0),_currPtr(0) { }

x_socket::x_socket(const int sock, const struct sockaddr_in *addr)
{

	assert(INVALID_SOCKET != sock);

	this->sock = sock;
	bzero(&this->addr,sizeof(struct sockaddr_in));
	if (NULL == addr) 
	{
		socklen_t len = sizeof(struct sockaddr);
		getpeername(this->sock,(struct sockaddr *)&this->addr,&len);
	}
	else 
	{
		bcopy(addr,&this->addr,sizeof(struct sockaddr_in));
	}
	bzero(&this->local_addr,sizeof(struct sockaddr_in));
	{
		socklen_t len = sizeof(struct sockaddr_in);
		getsockname(this->sock,(struct sockaddr *)&this->local_addr,&len);
	}

	setNonblock();

	rd_msec = T_RD_MSEC;
	wr_msec = T_WR_MSEC;
	_rcv_raw_size = 0;
	_current_cmd = 0; 

	set_flag(INCOMPLETE_READ | INCOMPLETE_WRITE);
}

x_socket::~x_socket()
{
	::shutdown(sock,SHUT_RDWR);
	TEMP_FAILURE_RETRY(::close(sock));
	sock = INVALID_SOCKET;
}

#define success_unpack() \
	if(_rcv_raw_size >= packetMinSize())\
	{\
		uint32_t nRecordLen = packetSize(_rcv_queue.rd_buf());\
		if(_rcv_raw_size >= nRecordLen)\
		{\
			int retval = nRecordLen - PH_LEN;\
			bcopy(_rcv_queue.rd_buf()+PH_LEN,pstrCmd,retval);\
			_rcv_queue.rd_flip(nRecordLen);\
			_rcv_raw_size -= nRecordLen;\
			return retval;\
		}\
	}


int x_socket::recvToCmd(void* pstrCmd,const int nCmdLen,const bool wait)
{
	success_unpack();

	do{
		int retval = recvToBuf();
		if(-1 == retval || (0 ==retval && !wait))
			return retval;

		success_unpack();
	}while(true);
	return 0;
}

int x_socket::sendRawData(const void *pBuffer, const int nSize)
{
	int retcode = 0;
	if(isset_flag(INCOMPLETE_WRITE))
	{
		clear_flag(INCOMPLETE_WRITE);
		goto do_select;
	}

	retcode = TEMP_FAILURE_RETRY(::send(sock, pBuffer, nSize, MSG_NOSIGNAL));
	if(retcode == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
	{
do_select:
		retcode = waitForWrite();
		if(1 ==retcode)
			retcode = TEMP_FAILURE_RETRY(::send(sock, pBuffer, nSize, MSG_NOSIGNAL));
		else
			return retcode;
	}

	if(retcode >0 && retcode < nSize)
		set_flag(INCOMPLETE_WRITE);

	return retcode;
}

bool x_socket::sendRawDataIM(const void* pBuffer, const int nSize)
{
	if(NULL == pBuffer || nSize <= 0)
		return false;

	int offset = 0;
	do
	{
		int retcode = sendRawData(&((char*)pBuffer)[offset], nSize - offset);
		if( -1 == retcode)
			return false;
		offset += retcode;
	}while( offset < nSize);
	return (offset == nSize);
}

bool x_socket::sendCmd(const void* pstrCmd, const int nCmdLen,const bool buffer)
{
	if(NULL == pstrCmd || nCmdLen <= 0)
		return false;
	bool retval = true;
	if(buffer)
	{
		mutex.lock();
		_snd_queue.put((const BYTE*)pstrCmd,nCmdLen);
		_current_cmd = nCmdLen;
		mutex.unlock();
	}
	else
	{
		mutex.lock();
		retval = sendRawDataIM(pstrCmd,nCmdLen);
		mutex.unlock();
	}
	return retval;
}

bool x_socket::sendCmdNoPack(const void* pstrCmd,const int nCmdLen,const bool buffer)
{
	if(NULL == pstrCmd || nCmdLen <= 0)
		return false;
	bool retval = true;
	if(buffer)
	{
		boost::mutex::scoped_lock lock(mutex);
		_snd_queue.put((BYTE*)pstrCmd,nCmdLen);
		_current_cmd = nCmdLen;
	}
	else
	{
		boost::mutex::scoped_lock lock(mutex);
		retval = sendRawDataIM(pstrCmd,nCmdLen);
	}
	return retval;
}

bool x_socket::sync()
{
	boost::mutex::scoped_lock lock(mutex);
	if(_snd_queue.rd_ready())
	{
		int retcode = sendRawData_NoPoll(_snd_queue.rd_buf(),_snd_queue.rd_size());
		if(retcode > 0)
			_snd_queue.rd_flip(retcode);
		else if( -1 == retcode)
			return false;
	}
	return true;
}

void x_socket::force_sync()
{
	mutex.lock();
	if(_snd_queue.rd_ready())
	{
		sendRawDataIM(_snd_queue.rd_buf(),_snd_queue.rd_size());
		_snd_queue.reset();
	}
	mutex.unlock();
}

int x_socket::checkIOForRead()
{
	struct pollfd pfd;

	pfd.fd = sock;
	pfd.events = POLLIN | POLLERR | POLLPRI;
	pfd.revents = 0;

	int retcode = TEMP_FAILURE_RETRY(::poll(&pfd,1,0));
	if(retcode >0 && 0 == (pfd.revents & POLLIN))
		retcode = -1;

	return retcode;
}

int x_socket::checkIOForWrite()
{
	struct pollfd pfd;

	pfd.fd = sock;
	pfd.events = POLLOUT | POLLERR | POLLPRI;
	pfd.revents = 0;

	int retcode = TEMP_FAILURE_RETRY(::poll(&pfd,1,0));
	if(retcode > 0 && 0 ==(pfd.events & POLLOUT))
		retcode = -1;

	return retcode;
}

const char* x_socket::getIPByIfName(const char* ifName)
{
	int s;
	struct ifreq ifr;
	const char* none_ip = "0.0.0.0";

	if(NULL == ifName)
		return none_ip;
	s = ::socket(AF_INET,SOCK_DGRAM,0);
	if( -1 == s)
		return none_ip;

	bzero(ifr.ifr_name,sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name,ifName,sizeof(ifr.ifr_name)-1);
	if(-1 == ioctl(s,SIOCGIFADDR,&ifr))
	{
		TEMP_FAILURE_RETRY(::close(s));
		return none_ip;
	}
	TEMP_FAILURE_RETRY(::close(s));
	return inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
}

#define success_recv() \
	do{ \
		if((uint32_t)retcode < _rcv_queue.wr_size()) \
		{ \
			set_flag(INCOMPLETE_READ); \
		}\
		_rcv_queue.wr_flip(retcode); \
		_rcv_raw_size += retcode;\
	}while(0)

int x_socket::recvToBuf_NoPoll()
{
	int retcode = 0;
	_rcv_queue.wr_reserve(MAX_DATABUFFERSIZE);
	retcode = TEMP_FAILURE_RETRY(::recv(sock,_rcv_queue.wr_buf(),_rcv_queue.wr_size(),MSG_NOSIGNAL));
	if( retcode ==-1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 0;
	if(retcode > 0)
		success_recv();
	if(retcode == 0)
		return -1;	//EOF
	return retcode;
}

int x_socket::recvToCmd_NoPoll(void *pstrCmd,const int nCmdLen)
{
	success_unpack();
	return 0;
}

int x_socket::sendRawData_NoPoll(const void* pBuffer, const int nSize)
{
	int retcode = TEMP_FAILURE_RETRY(::send(sock,pBuffer,nSize,MSG_NOSIGNAL));
	if(retcode ==-1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 0;	//should retry
	if(retcode > 0 && retcode < nSize)
		set_flag(INCOMPLETE_WRITE);

	return retcode;
}

bool x_socket::setNonblock()
{
	int fd_flags;
	int nodelay = 1;

	if(::setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(void*)&nodelay,sizeof(nodelay)))
		return false;

	fd_flags = ::fcntl(sock,F_GETFL,0);

#if defined(O_NONBLOCK)
	fd_flags |= O_NONBLOCK;
#elif defined(O_NDELAY)
	fd_flags |= O_NDELAY;
#elif defined(FNDELAY)	
	fd_flags |= O_FNDELAY;
#else
	return false;
#endif

	if(::fcntl(sock,F_SETFL,fd_flags) == -1)
		return false;
	return true;
}

int x_socket::waitForRead()
{
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLIN | POLLERR | POLLPRI;
	pfd.revents = 0;

	int retcode = TEMP_FAILURE_RETRY(::poll(&pfd,1,rd_msec));
	if(retcode > 0 && 0 == (pfd.revents & POLLIN))
		retcode =-1;
	return retcode;
}

int x_socket::waitForWrite()
{
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLOUT | POLLERR | POLLPRI;
	pfd.revents = 0;

	int retcode = TEMP_FAILURE_RETRY(::poll(&pfd,1, wr_msec));
	if(retcode >0 && 0 == (pfd.revents & POLLOUT))
		retcode = -1;
	return retcode;
}

int x_socket::recvToBuf()
{
	int retcode = 0;

	if(isset_flag(INCOMPLETE_READ))
	{
		clear_flag(INCOMPLETE_READ);
		goto do_select;
	}
	_rcv_queue.wr_reserve(MAX_DATABUFFERSIZE);
	retcode = TEMP_FAILURE_RETRY(::recv(sock,_rcv_queue.wr_buf(),_rcv_queue.wr_size(),MSG_NOSIGNAL));
	if(retcode == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
	{
do_select:
		retcode = waitForRead();
		if(1 == retcode)
			retcode = TEMP_FAILURE_RETRY(::recv(sock,_rcv_queue.wr_buf(),_rcv_queue.wr_size(),MSG_NOSIGNAL));
		else
			return retcode;
	}
	if(retcode > 0)
		success_recv();

	if(0 == retcode)
		return -1;	//eof
	return retcode;
}

void x_socket::add_epoll(int efd,uint32_t events,void* ptr)
{
	struct epoll_event ev;
	ev.events = events;
	ev.data.ptr = ptr;
	if( -1 == epoll_ctl(efd,EPOLL_CTL_ADD,sock,&ev))
	{
		char buf[100];
		bzero(buf,sizeof(buf));
		strerror_r(errno,buf,sizeof(buf));
		Xlogger->fatal("%s:%s",__FUNCTION__,buf);
	}
}

void x_socket::del_epoll(int efd,uint32_t events)
{
	struct epoll_event ev;
	ev.events = events;
	ev.data.ptr = NULL;
	if( -1 == epoll_ctl(efd,EPOLL_CTL_DEL,sock,&ev))
	{
		char buf[100];
		bzero(buf,sizeof(buf));
		strerror_r(errno,buf,sizeof(buf));
		Xlogger->fatal("%s:%s",__FUNCTION__,buf);
	}
}
