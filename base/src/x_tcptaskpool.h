#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <list>
#include <unistd.h>
#include <sys/timeb.h>
#include "x_socket.h"
#include "x_tcptask.h"
#include <boost/thread.hpp>

using boost::shared_ptr;

class x_verify_thread_functor;
class x_sync_thread_functor;
class x_okay_thread_functor;
class x_recycle_thread_functor;

/**
* \brief 连接线程池类，封装了一个线程处理多个连接的线程池框架
*
*/
class x_tcptaskpool : private boost::noncopyable, public boost::enable_shared_from_this<x_tcptaskpool>
{
public:

	/**
	* \brief 构造函数
	* \param maxConns 线程池并行处理有效连接的最大数量
	* \param state 初始化的时候连接线程池的状态
	*/
	explicit x_tcptaskpool(const int maxConns,const int state,const int us=50000) : maxConns(maxConns),state(state)
	{
		setUsleepTime(us);
		maxThreadCount = minThreadCount;
	};

	/**
	* \brief 析构函数，销毁一个线程池对象
	*
	*/
	~x_tcptaskpool()
	{
		//final();
	}

	/**
	* \brief 获取连接线程池当前状态
	*
	* \return 返回连接线程池的当前状态
	*/
	const int getState() const
	{
		return state;
	}

	/**
	* \brief 设置连接线程池状态
	*
	* \param state 设置的状态标记位
	*/
	void setState(const int state)
	{
		this->state |= state;
	}

	/**
	* \brief 清楚连接线程池状态
	*
	* \param state 清楚的状态标记位
	*/
	void clearState(const int state)
	{
		this->state &= ~state;
	}

	const int getSize() const;
	inline const int getMaxConns() const { return maxConns; }
	bool addVerify(shared_ptr<x_tcptask> task);
	bool addSync(shared_ptr<x_tcptask> task);
	bool addOkay(shared_ptr<x_tcptask> task);
	void addRecycle(shared_ptr<x_tcptask> task);
	static void  setUsleepTime(int time)
	{
		usleep_time=time;
	}

	bool init();
	void final();

private:
	const int maxConns;                    /**< 线程池并行处理连接的最大数量 */
	static const int maxVerifyThreads = 4;          /**< 最大验证线程数量 */
	//zThreadGroup verifyThreads;                /**< 验证线程，可以有多个 */
	//zSyncThread *syncThread;                /**< 等待同步线程 */
	static const int minThreadCount = 1;          /**< 线程池中同时存在主处理线程的最少个数 */
	int maxThreadCount;                    /**< 线程池中同时存在主处理线程的最大个数 */
	//zThreadGroup okayThreads;                /**< 处理主线程，多个 */
	//zRecycleThread *recycleThread;              /**< 连接回收线程 */
	int state;                        /**< 连接池状态 */

	boost::thread_group verifyThreads; 
	std::vector<boost::shared_ptr<x_verify_thread_functor> > verifyThreadFunctors;

	boost::scoped_ptr<boost::thread> syncThread;
	boost::shared_ptr<x_sync_thread_functor> syncThreadFunctor;

	boost::thread_group okayThreads;
	std::vector<boost::shared_ptr<x_okay_thread_functor> > okayThreadFunctors;

	boost::scoped_ptr<boost::thread> recycleThread;
	boost::shared_ptr<x_recycle_thread_functor> recycleThreadFunctor;
public:
	static int usleep_time;                    /**< 循环等待时间 */
};
