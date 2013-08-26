/**
* \brief 实现线程池类,用于处理多连接服务器
*
* 
*/
#include <zebra/srvEngine.h>

#include <assert.h>
//#include <ext/pool_allocator.h>

#include <iostream>

/**
* \brief 检测TCP连接状况,如果未连接,尝试连接
*
*/
class zCheckconnectThread : public zThread
{
private:
	x_tcp_clientTaskPool *pool;
public:
	zCheckconnectThread(
		x_tcp_clientTaskPool *pool,
		const std::string &name = std::string("zCheckconnectThread"))
		: zThread(name),pool(pool)
	{
	}
	virtual void run()
	{
		while(!isFinal())
		{
			zThread::sleep(4);
			zTime ct;
			pool->timeAction(ct);
		}
	}
};

/**
* \brief 连接任务链表
*
*/
//typedef std::list<x_tcp_clientTask *,__gnu_cxx::__pool_alloc<x_tcp_clientTask *> > x_tcp_clientTaskContainer;
typedef std::list<x_tcp_clientTask *> x_tcp_clientTaskContainer;

/**
* \brief 连接任务链表叠代器
*
*/
typedef x_tcp_clientTaskContainer::iterator x_tcp_clientTask_IT;

typedef std::vector<struct pollfd> pollfdContainer;

class x_tcp_clientTaskQueue
{
public:
	x_tcp_clientTaskQueue() :_size(0) {}
	virtual ~x_tcp_clientTaskQueue() {}
	inline void add(x_tcp_clientTask *task)
	{
		mlock.lock();
		_queue.push(task);
		_size++;
		mlock.unlock();
	}
	inline void check_queue()
	{
		mlock.lock();
		while(!_queue.empty())
		{
			x_tcp_clientTask *task = _queue.front();
			_queue.pop();
			_add(task);
		}
		_size = 0;
		mlock.unlock();
	}
protected:
	virtual void _add(x_tcp_clientTask *task) = 0;
	uint32_t _size;
private:
	zMutex mlock;
	//std::queue<x_tcp_clientTask *,std::deque<x_tcp_clientTask *,__gnu_cxx::__pool_alloc<x_tcp_clientTask *> > > _queue;
	std::queue<x_tcp_clientTask *> _queue;
};

/**
* \brief 处理TCP连接的验证,如果验证不通过,需要回收这个连接
*
*/
class zCheckwaitThread : public zThread,public x_tcp_clientTaskQueue
{

private:

	x_tcp_clientTaskPool *pool;
	x_tcp_clientTaskContainer tasks;  /**< 任务列表 */
	x_tcp_clientTaskContainer::size_type task_count;          /**< tasks计数(保证线程安全*/
	pollfdContainer pfds;

	/**
	* \brief 添加一个连接任务
	* \param task 连接任务
	*/
	void _add(x_tcp_clientTask *task)
	{
		Xlogger->debug("zCheckwaitThread::_add");

		struct pollfd pfd;
		task->fillPollFD(pfd,POLLIN | POLLPRI);
		tasks.push_back(task);
		task_count = tasks.size();
		pfds.push_back(pfd);
	}

	void remove(x_tcp_clientTask_IT &it,int p)
	{
		Xlogger->debug("zCheckwaitThread::remove");
		int i=0;
		pollfdContainer::iterator iter;
		for(iter = pfds.begin(),i = 0; iter != pfds.end(); iter++,i++)
		{
			if (i == p)
			{
				pfds.erase(iter);
				it = tasks.erase(it);
				task_count = tasks.size();
				break;
			}
		}
	}

public:

	/**
	* \brief 构造函数
	* \param pool 所属的连接池
	* \param name 线程名称
	*/
	zCheckwaitThread(
		x_tcp_clientTaskPool *pool,
		const std::string &name = std::string("zCheckwaitThread"))
		: zThread(name),pool(pool)
	{
		task_count = 0;
	}

	/**
	* \brief 析构函数
	*
	*/
	~zCheckwaitThread()
	{
	}

	virtual void run();

};

/**
* \brief 等待接受验证指令,并进行验证
*
*/
void zCheckwaitThread::run()
{
	Xlogger->debug("zCheckwaitThread::run");

	x_tcp_clientTask_IT it,next;
	pollfdContainer::size_type i;

	while(!isFinal())
	{
		check_queue();

		if (tasks.size() > 0)
		{
			if( WaitRecvAll( &pfds[0],pfds.size(), 0 ) <= 0 ) continue;

			for(i = 0,it = tasks.begin(); it != tasks.end();)
			{
				x_tcp_clientTask *task = *it;

				if ( pfds[i].revents & POLLPRI )
				{
					//套接口出现错误
					printf("套接口出现错误remove\n");
					remove(it,i--);
					task->resetState();
				}
				else if( pfds[i].revents & POLLIN )
				{
					switch(task->checkRebound())
					{
					case 1:
						//验证成功,获取下一个状态
						remove(it,i);
						if (!pool->addMain(task))
							task->resetState();
						break;
					case -1:
						//验证失败,回收任务
						printf("验证失败remove\n");
						remove(it,i);
						task->resetState();
						break;
					default:
						it ++;
						i  ++;
						//超时,下面会处理
						break;
					}
				}
				else
				{
					i ++;
					it ++;
				}
			}
		}

		zThread::msleep(50);
	}

	if(tasks.size() == 0)
		return;
	//把所有等待验证队列中的连接加入到回收队列中,回收这些连接
	for(i = 0,it = tasks.begin(); it != tasks.end();)
	{
		x_tcp_clientTask *task = *it;
		remove(it,i);
		task->resetState();
	}
}

/**
* \brief TCP连接的主处理线程,一般一个线程带几个TCP连接,这样可以显著提高效率
*
*/
class x_tcp_clientTaskThread : public zThread,public x_tcp_clientTaskQueue
{

private:

	x_tcp_clientTaskPool *pool;
	x_tcp_clientTaskContainer tasks;  /**< 任务列表 */
	x_tcp_clientTaskContainer::size_type task_count;          /**< tasks计数(保证线程安全*/

	pollfdContainer pfds;

	zMutex m_Lock;
	/**
	* \brief 添加一个连接任务
	* \param task 连接任务
	*/
	void _add(x_tcp_clientTask *task)
	{

		struct pollfd pfd;
		m_Lock.lock();
		task->fillPollFD(pfd,POLLIN | POLLOUT | POLLPRI);
		tasks.push_back(task);
		task_count = tasks.size();
		pfds.push_back(pfd);
		m_Lock.unlock();
	}


	void remove(x_tcp_clientTask_IT &it,int p)
	{
		int i;
		pollfdContainer::iterator iter;
		m_Lock.lock();
		for(iter = pfds.begin(),i = 0; iter != pfds.end(); iter++,i++)
		{
			if (i == p)
			{
				pfds.erase(iter);
				it = tasks.erase(it);
				task_count = tasks.size();
				break;
			}
		}
		m_Lock.unlock();
	}

public:

	static const x_tcp_clientTaskContainer::size_type connPerThread = 256;  /**< 每个线程带的连接数量 */

	/**
	* \brief 构造函数
	* \param pool 所属的连接池
	* \param name 线程名称
	*/
	x_tcp_clientTaskThread(
		x_tcp_clientTaskPool *pool,
		const std::string &name = std::string("x_tcp_clientTaskThread"))
		: zThread(name),pool(pool)
	{
		task_count = 0;

	}

	/**
	* \brief 析构函数
	*
	*/
	~x_tcp_clientTaskThread()
	{
	}

	virtual void run();

	/**
	* \brief 返回连接任务的个数
	* \return 这个线程处理的连接任务数
	*/
	const x_tcp_clientTaskContainer::size_type size() const
	{
		return task_count + _size;
	}

};

/**
* \brief 主处理线程,回调处理连接的输入输出指令
*
*/
void x_tcp_clientTaskThread::run()
{
	Xlogger->debug("x_tcp_clientTaskThread::run");

	x_tcp_clientTask_IT it,next;
	pollfdContainer::size_type i;

	while(!isFinal())
	{
		check_queue();
		m_Lock.lock();
		if (!tasks.empty())
		{
			for(i = 0,it = tasks.begin(); it != tasks.end();)
			{
				x_tcp_clientTask *task = *it;

				if (task->isTerminate())
				{
					m_Lock.unlock();
					remove(it,i);
					m_Lock.lock();
					// state_okay -> state_recycle
					task->getNextState();
				}
				else
				{
					if (task->checkFirstMainLoop())
					{
						//如果是第一次加入处理,需要预先处理缓冲中的数据
						task->ListeningRecv(false);
					}
					i++;
					it++;
				}
			}

			if (!tasks.empty())
			{
				for(i = 0,it = tasks.begin(); it != tasks.end(); it++,i++)
				{
					x_tcp_clientTask *task = *it;

					bool UseIocp = task->UseIocp();
					if( UseIocp )
					{
						int retcode = task->WaitRecv( false );
						if ( retcode == -1 )
						{
							//套接口出现错误
							Xlogger->debug("%x_tcp_clientTaskThread::run: 套接口异常错误");
							task->Terminate(x_tcp_clientTask::TM_sock_error);
						}
						else if( retcode > 0 )
						{
							//套接口准备好了读取操作
							if (!task->ListeningRecv(true))
							{
								Xlogger->debug("x_tcp_clientTaskThread::run: 套接口读操作错误");
								task->Terminate(x_tcp_clientTask::TM_sock_error);
							}
						}
						retcode = task->WaitSend( false );
						if( retcode == - 1 )
						{
							//套接口出现错误
							Xlogger->debug("%x_tcp_clientTaskThread::run: 套接口异常错误");
							task->Terminate(x_tcp_clientTask::TM_sock_error);
						}
						else if( retcode == 1 )
						{
							//套接口准备好了写入操作
							if (!task->ListeningSend())
							{
								Xlogger->debug("x_tcp_clientTaskThread::run: 套接口写操作错误");
								task->Terminate(x_tcp_clientTask::TM_sock_error);
							}
						}
					}
					else
					{
						if( ::poll(&pfds[i],1,0) <= 0 ) continue;
						if ( pfds[i].revents & POLLPRI )
						{
							//套接口出现错误
							Xlogger->debug("%x_tcp_clientTaskThread::run: 套接口异常错误");
							task->Terminate(x_tcp_clientTask::TM_sock_error);
						}
						else
						{
							if( pfds[i].revents & POLLIN)
							{
								//套接口准备好了读取操作
								if (!task->ListeningRecv(true))
								{
									Xlogger->debug("x_tcp_clientTaskThread::run: 套接口读操作错误");
									task->Terminate(x_tcp_clientTask::TM_sock_error);
								}
							}
							if ( pfds[i].revents & POLLOUT)
							{
								//套接口准备好了写入操作
								if (!task->ListeningSend())
								{
									Xlogger->debug("x_tcp_clientTaskThread::run: 套接口写操作错误");
									task->Terminate(x_tcp_clientTask::TM_sock_error);
								}
							}
						}
					}
				}
			}			
		}
		else
		{
			int iii = 0;
		}
		m_Lock.unlock();
		zThread::usleep(pool->usleep_time);
	}

	//把所有任务队列中的连接加入到回收队列中,回收这些连接


	if(tasks.size() == 0)
		return ;

	for(i = 0,it = tasks.begin(); it != tasks.end();)
	{
		x_tcp_clientTask *task = *it;
		remove(it,i);
		// state_okay -> state_recycle
		task->getNextState();
	}
}



/**
* \brief 析构函数
*
*/
x_tcp_clientTaskPool::~x_tcp_clientTaskPool()
{
	if (checkconnectThread)
	{
		checkconnectThread->final();
		checkconnectThread->join();
		SAFE_DELETE(checkconnectThread);
	}
	if (checkwaitThread)
	{
		checkwaitThread->final();
		checkwaitThread->join();
		SAFE_DELETE(checkwaitThread);
	}

	taskThreads.joinAll();

	x_tcp_clientTask_IT it,next;


	if(tasks.size() > 0)
		for(it = tasks.begin(),next = it,next++; it != tasks.end(); it = next,next == tasks.end()? next : next++)
		{
			x_tcp_clientTask *task = *it;
			tasks.erase(it);
			SAFE_DELETE(task);
		}
}

x_tcp_clientTaskThread *x_tcp_clientTaskPool::newThread()
{
	std::ostringstream name;
	name << "x_tcp_clientTaskThread[" << taskThreads.size() << "]";
	x_tcp_clientTaskThread *taskThread = new x_tcp_clientTaskThread(this,name.str());
	if (NULL == taskThread)
		return NULL;
	if (!taskThread->start())
		return NULL;
	taskThreads.add(taskThread);
	return taskThread;
}

/**
* \brief 初始化线程池,预先创建各种线程
*
* \return 初始化是否成功
*/
bool x_tcp_clientTaskPool::init()
{
	checkconnectThread = new zCheckconnectThread(this); 
	if (NULL == checkconnectThread)
		return false;
	if (!checkconnectThread->start())
		return false;
	checkwaitThread = new zCheckwaitThread(this);
	if (NULL == checkwaitThread)
		return false;
	if (!checkwaitThread->start())
		return false;

	if (NULL == newThread())
		return false;

	return true;
}

/**
* \brief 把一个指定任务添加到池中
* \param task 待添加的任务
*/
bool x_tcp_clientTaskPool::put(x_tcp_clientTask *task)
{
	if (task)
	{
		mlock.lock();
		tasks.push_front(task);
		mlock.unlock();
		return true;
	}
	else
		return false;
}

/**
* \brief 定时执行的任务
* 主要是如果客户端断线尝试重连
*/
void x_tcp_clientTaskPool::timeAction(const zTime &ct)
{
	mlock.lock();
	for(x_tcp_clientTask_IT it = tasks.begin(); it != tasks.end(); ++it)
	{
		x_tcp_clientTask *task = *it;
		switch(task->getState())
		{
		case x_tcp_clientTask::close:
			if (task->checkStateTimeout(x_tcp_clientTask::close,ct,4)
				&& task->connect())
			{
				addCheckwait(task);
			}
			break;
		case x_tcp_clientTask::sync:
			break;
		case x_tcp_clientTask::okay:
			//已经在连接状态,发送网络测试信号
			task->checkConn();
			break;
		case x_tcp_clientTask::recycle:
			if (task->checkStateTimeout(x_tcp_clientTask::recycle,ct,4))
				task->getNextState();
			break;
		}
	}
	mlock.unlock();
}

/**
* \brief 把任务添加到等待连接认证返回的队列中
* \param task 待添加的任务
*/
void x_tcp_clientTaskPool::addCheckwait(x_tcp_clientTask *task)
{
	checkwaitThread->add(task);
	task->getNextState();
}

/**
* \brief 把任务添加到主处理循环中
* \param task 待添加的任务
* \return 添加是否成功
*/
bool x_tcp_clientTaskPool::addMain(x_tcp_clientTask *task)
{
	x_tcp_clientTaskThread *taskThread = NULL;
	for(uint32_t i = 0; i < taskThreads.size(); i++)
	{
		x_tcp_clientTaskThread *tmp = (x_tcp_clientTaskThread *)taskThreads.getByIndex(i);
		//Xlogger->debug("%u",tmp->size());
		if (tmp && tmp->size() < connPerThread)
		{
			taskThread = tmp;
			break;
		}
	}
	if (NULL == taskThread)
		taskThread = newThread();
	if (taskThread)
	{
		taskThread->add(task);
		task->getNextState();
		return true;
	}
	else
	{
		Xlogger->fatal("x_tcp_clientTaskPool::addMain: 不能得到一个空闲线程");
		return false;
	}
}

