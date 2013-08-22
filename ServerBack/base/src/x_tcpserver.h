#pragma once

#include <boost/utility.hpp>
#include <string>
#include <netinet/in.h>	//for sockaddr_in
/**
* \brief zTCPServer类，封装了服务器监听模块，可以方便的创建一个服务器对象，等待客户端的连接
*
*/
class x_tcpserver: private boost::noncopyable
{

public:

	x_tcpserver(const std::string &name);
	~x_tcpserver();
	bool bind(const std::string &name,const uint16_t port);
	int accept(struct sockaddr_in *addr);

private:

	static const int T_MSEC =2100;      /**< 轮询超时，毫秒 */
	static const int MAX_WAITQUEUE = 2000;  /**< 最大等待队列 */

	std::string name;            /**< 服务器名称 */
	int sock;                /**< 套接口 */
	int efd;					//epoll
}; 
