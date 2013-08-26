﻿#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/timeb.h>
#include "x_socket.h"
#include <boost/enable_shared_from_this.hpp>
#include <boost/timer.hpp>
#include <boost/utility.hpp>

class x_tcptaskpool;

/**
* \brief 定义一个任务类，是线程池的工作单元
*
*/
class x_tcptask : public x_processor, private boost::noncopyable, public boost::enable_shared_from_this<x_tcptask>
{

public:

	/**
	* \brief 连接断开方式
	*
	*/
	enum TerminateMethod
	{
		terminate_no,              /**< 没有结束任务 */
		terminate_active,            /**< 客户端主动断开连接，主要是由于服务器端检测到套接口关闭或者套接口异常 */
		terminate_passive,            /**< 服务器端主动断开连接 */
	};

	/**
	* \brief 构造函数，用于创建一个对象
	*
	*
	* \param pool 所属连接池指针
	* \param sock 套接口
	* \param addr 地址
	* \param compress 底层数据传输是否支持压缩
	* \param checkSignal 是否发送网络链路测试信号
	*/
	x_tcptask(
		//x_tcptaskpool *pool,
		const int sock,
		const struct sockaddr_in *addr = NULL,
		const bool checkSignal = true) :mSocket(sock,addr),_checkSignal(checkSignal),tick(false)
	{
		terminate = terminate_no;
		terminate_wait = false; 
		fdsradd = false; 
		buffered = false;
		state = notuse;
	}

	/**
	* \brief 析构函数，用于销毁一个对象
	*
	*/
	virtual ~x_tcptask() {}

	void add_epoll(int efd, uint32_t events, void* ptr){
		mSocket.add_epoll(efd,events,ptr);
	}

	void del_epoll(int efd, uint32_t events){
		mSocket.del_epoll(efd,events);
	}

	/**
	* \brief 填充pollfd结构
	* \param pfd 待填充的结构
	* \param events 等待的事件参数
	*/
	void fillPollFD(struct pollfd &pfd,short events)
	{
		mSocket.fillPollFD(pfd,events);
	}

	/**
	* \brief 检测是否验证超时
	*
	*
	* \param ct 当前系统时间
	* \param interval 超时时间，毫秒
	* \return 检测是否成功
	*/
	bool checkVerifyTimeout(const double interval = 2.0) const
	{
		return (lifeTime.elapsed() > interval);
	}

	/**
	* \brief 检查是否已经加入读事件
	*
	* \return 是否加入
	*/
	bool isFdsrAdd()
	{
		return fdsradd;
	}
	/**
	* \brief 设置加入读事件标志
	*
	* \return 是否加入
	*/
	bool fdsrAdd()
	{
		fdsradd=true;
		return fdsradd;
	}

	virtual int verifyConn()
	{
		return 1;
	}

	/**
	* \brief 等待其它线程同步验证这个连接，有些线程池不需要这步，所以不用重载这个函数，缺省始终返回成功
	*
	* \return 等待是否成功，1表示成功，可以进入下一步操作，0，表示还要继续等待，-1表示等待失败或者等待超时，需要断开连接
	*/
	virtual int waitSync()
	{
		return 1;
	}

	/**
	* \brief 回收是否成功，回收成功以后，需要删除这个TCP连接相关资源
	*
	* \return 回收是否成功，1表示回收成功，0表示回收不成功
	*/
	virtual int recycleConn()
	{
		return 1;
	}

	/**
	* \brief 一个连接任务验证等步骤完成以后，需要添加到全局容器中
	*
	* 这个全局容器是外部容器
	*
	*/
	virtual void addToContainer() {}

	/**
	* \brief 连接任务退出的时候，需要从全局容器中删除
	*
	* 这个全局容器是外部容器
	*
	*/
	virtual void removeFromContainer() {}

	/**
	* \brief 添加到外部容器，这个容器需要保证这个连接的唯一性
	*
	* \return 添加是否成功
	*/
	virtual bool uniqueAdd()
	{
		return true;
	}

	/**
	* \brief 从外部容器删除，这个容器需要保证这个连接的唯一性
	*
	* \return 删除是否成功
	*/
	virtual bool uniqueRemove()
	{
		return true;
	}

	/**
	* \brief 设置唯一性验证通过标记
	*
	*/
	void setUnique()
	{
		uniqueVerified = true;
	}

	/**
	* \brief 判断是否已经通过了唯一性验证
	*
	* \return 是否已经通过了唯一性标记
	*/
	bool isUnique() const
	{
		return uniqueVerified;
	}

	/**
	* \brief 判断是否被其它线程设置为等待断开连接状态
	*
	* \return true or false
	*/
	bool isTerminateWait()
	{
		return terminate_wait; 
	}


	/**
	* \brief 判断是否被其它线程设置为等待断开连接状态
	*
	* \return true or false
	*/
	void TerminateWait()
	{
		terminate_wait=true; 
	}

	/**
	* \brief 判断是否需要关闭连接
	*
	* \return true or false
	*/
	bool isTerminate() const
	{
		return terminate_no != terminate;
	}

	/**
	* \brief 需要主动断开客户端的连接
	*
	* \param method 连接断开方式
	*/
	virtual void Terminate(const TerminateMethod method = terminate_passive)
	{
		terminate = method;
		clearTick();
	}

	virtual bool sendCmd(const void *,int);
	bool sendCmdNoPack(const void *,int);
	virtual bool ListeningRecv(bool);
	virtual bool ListeningSend();

	/**
	* \brief 连接任务状态
	*
	*/
	enum zTCPTask_State
	{
		notuse    =  0,            /**< 连接关闭状态 */
		verify    =  1,            /**< 连接验证状态 */
		sync    =  2,            /**< 等待来自其它服务器的验证信息同步 */
		okay    =  3,            /**< 连接处理阶段，验证通过了，进入主循环 */
		recycle    =  4              /**< 连接退出状态，回收 */
	};

	/**
	* \brief 获取连接任务当前状态
	* \return 状态
	*/
	const zTCPTask_State getState() const
	{
		return state;
	}

	/**
	* \brief 设置连接任务状态
	* \param state 需要设置的状态
	*/
	void setState(const zTCPTask_State state)
	{
		this->state = state;
	}

	void getNextState();
	void resetState();

	/**
	* \brief 获得状态的字符串描述
	*
	*
	* \param state 状态
	* \return 返回状态的字符串描述
	*/
	const char *getStateString(const zTCPTask_State state) const
	{
		const char *retval = NULL;

		switch(state)
		{
		case notuse:
			retval = "notuse";
			break;
		case verify:
			retval = "verify";
			break;
		case sync:
			retval = "sync";
			break;
		case okay:
			retval = "okay";
			break;
		case recycle:
			retval = "recycle";
			break;
		default:
			retval = "none";
			break;
		}

		return retval;
	}

	/**
	* \brief 返回连接的IP地址
	* \return 连接的IP地址
	*/
	const char *getIP() const
	{
		return mSocket.getIP();
	}
	const uint32_t getAddr() const
	{
		return mSocket.getAddr();
	}

	const uint16_t getPort()
	{
		return mSocket.getPort();
	}

	/**
	* \brief 是否发送网络连接链路测试信号
	* \return true or false
	*/
	const bool ifCheckSignal() const
	{
		return _checkSignal;
	}

	/**
	* \brief 检测测试信号发送间隔
	*
	* \return 检测是否成功
	*/
	bool checkInterval(const double ct)
	{
		if(_tick_timer.elapsed() < ct)
		{
			_tick_timer.restart();
			return true;
		}
		else
			return false;
	}

	/**
	* \brief 检查测试信号，如果测试信号在规定时间内返回，那么重新发送测试信号，没有返回的话可能TCP连接已经出错了
	*
	* \return true，表示检测成功；false，表示检测失败 
	*/
	bool checkTick() const
	{
		return tick;
	}

	/**
	* \brief 测试信号已经返回了
	*
	*/
	void clearTick()
	{
		tick = false;
	}

	/**
	* \brief 发送测试信号成功
	*
	*/
	void setTick()
	{
		tick = true;
	}

	void checkSignal(const double ct);

	//static CmdAnalysis analysis;
protected:

	bool buffered;                  /**< 发送指令是否缓冲 */
	x_socket mSocket;                /**< 底层套接口 */

	zTCPTask_State state;              /**< 连接状态 */

private:

	TerminateMethod terminate;            /**< 是否结束任务 */
	bool terminate_wait;              /**< 其它线程设置等待断开连接状态,由pool线程设置断开连接状态 */
	bool fdsradd;                  /**< 读事件添加标志 */
	boost::timer lifeTime;                /**< 连接创建时间记录 */

	bool uniqueVerified;              /**< 是否通过了唯一性验证 */
	const bool _checkSignal;            /**< 是否发送链路检测信号 */
	boost::timer _tick_timer;
	bool tick;
	//uint8_t check_count;  loki removed for simple and because it is tcp connection


};
