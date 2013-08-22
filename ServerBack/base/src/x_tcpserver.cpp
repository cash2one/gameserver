#include "common.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>	//for socklen_t
#include <sys/epoll.h>	//for epoll
#include "x_tcpserver.h"
//#include "x_socket.h"

x_tcpserver::x_tcpserver(const std::string &name)
: name(name),
	sock(-1)
{
	efd = epoll_create(1);
	assert(-1 != efd);
}

x_tcpserver::~x_tcpserver() 
{
	if (-1 != sock) 
	{
		::shutdown(sock,SHUT_RD);
		TEMP_FAILURE_RETRY(::close(sock));
		sock = -1;
	}
}

bool x_tcpserver::bind(const std::string &name,const uint16_t port)
{
	Xlogger->debug(__PRETTY_FUNCTION__);

	struct sockaddr_in addr;

	if (INVALID_SOCKET != sock) 
	{
		Xlogger->error("server may have already initialized");
		return false;
	}

	sock = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if (INVALID_SOCKET == sock) 
	{
		Xlogger->error("create socket failed");
		return false;
	}

	int reuse = 1;
	if (-1 == ::setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&reuse,sizeof(reuse))) 
	{
		Xlogger->error("cannot set socket reusable");
		::close(sock);
		sock = INVALID_SOCKET;
		return false;
	}

	//set send and recieve buffer
	socklen_t window_size = 128 * 1024;
	if (-1 == ::setsockopt(sock,SOL_SOCKET,SO_RCVBUF, &window_size,sizeof(window_size)))
	{
		::close(sock);
		return false;
	}
	if (-1 == ::setsockopt(sock,SOL_SOCKET,SO_SNDBUF,&window_size,sizeof(window_size)))
	{
		::close(sock);
		sock = INVALID_SOCKET;
		return false;
	}

	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	int retcode = ::bind(sock,(struct sockaddr *) &addr,sizeof(addr));
	if (-1 == retcode) 
	{
		Xlogger->error("cannot bind server port %u",port);
		::close(sock);
		sock = INVALID_SOCKET;
		return false;
	}

	retcode = ::listen(sock,MAX_WAITQUEUE);
	if (-1 == retcode) 
	{
		Xlogger->error("cannot listen server port");
		::close(sock);
		sock = INVALID_SOCKET;
		return false;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	retcode = epoll_ctl(efd,EPOLL_CTL_ADD, sock,&ev);
	if (retcode!=0)
	{
		Xlogger->error("epoll_ctl_add error");
		::close(sock);
		sock = INVALID_SOCKET;
		return false;
	}

	Xlogger->info("initialise ok %s:%u",name.c_str(),port);

	return true;
}

int x_tcpserver::accept(struct sockaddr_in *addr)
{
	socklen_t len = sizeof(struct sockaddr_in);
	bzero(addr,sizeof(struct sockaddr_in));

	struct epoll_event ev;
	int rc = epoll_wait(efd,&ev, 1, T_MSEC);
	if (1 == rc && (ev.events & EPOLLIN))
		return TEMP_FAILURE_RETRY(::accept(sock, (sockaddr *)addr, &len));

	return -1;
}

