#pragma once

#include "common.h"
#include <boost/utility.hpp>
#include <string>
#include "x_thread_functor.h"
#include "x_socket.h"
#include <boost/smart_ptr.hpp>

/**
* \brief TCP客户端
*
* 封装了一些TCP客户端的逻辑，比如建立连接等等，在实际应用中，需要派生这个类，并重载解析指令的函数msgParse
*
*/
class x_tcp_client : public x_processor , public x_thread_functor
{
public:

	/**
	* \brief 构造函数，创建实例对象，初始化对象成员
	*
	*
	* \param name 名称
	* \param ip 地址
	* \param port 端口
	*/
	x_tcp_client( const std::string &ip = "127.0.0.1", const uint16_t port = 80)
		: ip(ip),port(port){}

	/**
	* \brief 析构函数，销毁对象
	*
	*/
	~x_tcp_client() 
	{
		close();
	}

	bool connect();

	/**
	* \brief 建立一个到服务器的TCP连接，指定服务器的IP地址和端口
	*
	*
	* \param ip 服务器的IP地址
	* \param port 服务器的端口
	* \return 连接是否成功
	*/
	bool connect(const char *ip,const uint16_t port)
	{
		this->ip = ip;
		this->port = port;
		return connect();
	}

	/**
	* \brief 关闭客户端连接
	*
	*/
	virtual void close()
	{
		/*
		if( pSocket != NULL )
		{
			if(pSocket->SafeDelete( false ))
				delete pSocket;
			pSocket = NULL;
		}
		*/
	}

	virtual bool sendCmd(const void *pstrCmd,const int nCmdLen);

	/**
	* \brief 设置服务器IP地址
	*
	*
	* \param ip 设置的服务器IP地址
	*/
	void setIP(const char *ip)
	{
		this->ip = ip;
	}

	/**
	* \brief 获取服务器IP地址
	*
	*
	* \return 返回地址
	*/
	const char *getIP() const
	{
		return ip.c_str();
	}

	/**
	* \brief 设置服务器端口
	*
	*
	* \param port 设置的服务器端口
	*/
	void setPort(const uint16_t port)
	{
		this->port = port;
	}

	/**
	* \brief 获取服务器端口
	*
	*
	* \return 返回端口
	*/
	const uint16_t getPort() const
	{
		return port;
	}

	virtual void operator()();
	//指令分析
	//static CmdAnalysis analysis;

protected:

	std::string ip;                  /**< 服务器地址 */
	uint16_t port;              /**< 服务器端口 */
	boost::scoped_ptr<x_socket> pSocket;                /**< 底层套接口 */


}; 

class x_tcp_buffer_client : public x_tcp_client
{

public:

	x_tcp_buffer_client(
		const std::string &ip = "127.0.0.1",
		const uint16_t port = 80,
		const int usleep_time = 50000) 
		: x_tcp_client(ip,port),usleep_time(usleep_time),_buffered(false) { }

	void close()
	{
		sync();
		x_tcp_client::close();
	}

	virtual void operator()();
	bool sendCmd(const void *pstrCmd,const int nCmdLen);
	void setUsleepTime(const int utime)
	{
		usleep_time = utime;
	}

private :

	bool ListeningRecv();
	bool ListeningSend();
	void sync();

	int usleep_time;
	volatile bool _buffered;
};

