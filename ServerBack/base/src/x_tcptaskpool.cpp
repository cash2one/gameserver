#include "x_tcptaskpool.h"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>
#include <boost/ref.hpp>
#include "x_thread_functor.h"
#include "x_nullcmd.h"

typedef boost::chrono::milliseconds ms;
typedef std::list<shared_ptr<x_tcptask> > x_list_tcptask;
typedef x_list_tcptask::iterator x_list_tcptask_it;
typedef std::vector<struct pollfd> pollfdContainer;

int x_tcptaskpool::usleep_time=50000;                    //loop wait time

class zTCPTaskQueue
{
public:
	zTCPTaskQueue() :_size(0) {}
	virtual ~zTCPTaskQueue() {}
	inline void add(shared_ptr<x_tcptask> task)
	{
		mlock.lock();
		_queue.push_back(task);
		++_size;
		mlock.unlock();
	}
	inline void check_queue()	//move the tcptask from x_tcptaskpool to thread
	{
		mlock.lock();
		while(!_queue.empty())
		{
			shared_ptr<x_tcptask> task = _queue.back();
			_queue.pop_back();
			_add(task);	//take attention !!!
		}
		_size = 0;
		mlock.unlock();
	}
protected:
	//take attention !!!
	//insert the the thread's container for process 
	virtual void _add(shared_ptr<x_tcptask> task) = 0;
	uint32_t _size;
private:
	boost::mutex mlock;
	//for x_tcptaskpool to add tcptask
	std::vector<shared_ptr<x_tcptask> > _queue;
};

class x_verify_thread_functor : public x_thread_functor, public zTCPTaskQueue
{
private:
	boost::shared_ptr<x_tcptaskpool> pool;
	x_list_tcptask tasks;  /**< 任务列表 */
	x_list_tcptask::size_type task_count;      /**< tasks计数(保证线程安全*/
	int efd;
	std::vector<struct epoll_event> epfds;

	boost::mutex mutex_;
	/**
	* \brief 添加一个连接任务
	* \param task 连接任务
	*/
	void _add(shared_ptr<x_tcptask> task)
	{
		//need more thought for the get()
		task->add_epoll(efd,EPOLLIN | EPOLLERR | EPOLLPRI, (void*)task.get());
		tasks.push_back(task);
		task_count = tasks.size();
	}

	void remove(shared_ptr<x_tcptask> task)
	{
		task->del_epoll(efd,EPOLLIN | EPOLLERR | EPOLLPRI);
		tasks.remove(task);	//erases elements in a list that match a specified value
		task_count = tasks.size();
	}
public:
	x_verify_thread_functor( boost::shared_ptr<x_tcptaskpool> _pool) :pool(_pool)
	{
		task_count = 0;
		efd = epoll_create(256);
		assert(-1 != efd);
		epfds.resize(256);
	}

	~x_verify_thread_functor() {
		TEMP_FAILURE_RETRY(::close(efd));
   	}

	virtual void operator()();

};

void x_verify_thread_functor::operator()()
{
	while(!is_final())
	{
		check_queue();
		if(!tasks.empty())
		{
			for(x_list_tcptask_it it = tasks.begin();  it != tasks.end();)
			{
				shared_ptr<x_tcptask> task = *it;
				if (task->checkVerifyTimeout())
				{
					//over time,recycle the connection
					it = tasks.erase(it);	//an iterator pointing to the next element (or end())
					task_count = tasks.size();
					task->resetState();
					pool->addRecycle(task);
				}
				else
				{
					++it;
				}
			}
			int retcode = epoll_wait(efd,&epfds[0],task_count,0);
			if(retcode > 0)
			{
				for(int i = 0;i < retcode; ++i)
				{
					shared_ptr<x_tcptask> task = ((x_tcptask*)epfds[i].data.ptr)->shared_from_this(); 
					if(epfds[i].events & (EPOLLERR | EPOLLPRI))
					{
						Xlogger->error("sokect error");
						remove(task);
						task->resetState();
						pool->addRecycle(task);
					}
					else if( epfds[i].events & EPOLLIN)
					{
						switch(task->verifyConn())
						{
							case 1: 
								//verify success
								remove(task);
								if(task->uniqueAdd())
								{
									task->setUnique();
									pool->addSync(task);
								}
								else
								{
									Xlogger->error("client unique verify failed");
									task->resetState();
									pool->addRecycle(task);
								}
								break;
							case 0://overtime
								break;
							case -1://vefiry failed,recycle task
								Xlogger->debug("client connection verify failed");
								remove(task);
								task->resetState();
								pool->addRecycle(task);
								break;
							default:
								break;
						}
					}
				}
			}
		}

		boost::this_thread::sleep_for(ms(50));
	}

	for(x_list_tcptask_it it = tasks.begin(); it != tasks.end();)
	{
		shared_ptr<x_tcptask> task = *it;
		it = tasks.erase(it);
		task->resetState();
		pool->addRecycle(task);
	}
}

class x_sync_thread_functor : public x_thread_functor,public zTCPTaskQueue
{
	private:
		boost::shared_ptr<x_tcptaskpool> pool;
		x_list_tcptask tasks;  /**< 任务列表 */

		void _add(shared_ptr<x_tcptask> task)
		{
			tasks.push_back(task);
		}
	public:
		x_sync_thread_functor( boost::shared_ptr<x_tcptaskpool> _pool) :pool(_pool) {} 

		~x_sync_thread_functor() {};

		//void run();
		virtual void operator()();

};

void x_sync_thread_functor::operator()()
{
	x_list_tcptask_it it;
	while(!is_final())
	{
		check_queue();
		if (!tasks.empty())
		{
			for(it = tasks.begin(); it != tasks.end();)
			{
				shared_ptr<x_tcptask> task = (*it);
				switch(task->waitSync())
				{
				case 1:
					it = tasks.erase(it);
					if (!pool->addOkay(task))
					{
						task->resetState();
						pool->addRecycle(task);
					}
					break;
				case 0://overtime wait for next turn to process
					++it;
					break;
				case -1:
					it = tasks.erase(it);
					task->resetState();
					pool->addRecycle(task);
					break;
				}
			}
		}
		boost::this_thread::sleep_for(ms(200));
	}

	for(it = tasks.begin(); it != tasks.end();)
	{
		shared_ptr<x_tcptask> task = *it;
		it = tasks.erase(it);
		task->resetState();
		pool->addRecycle(task);
	}
}

class x_okay_thread_functor : public x_thread_functor,public zTCPTaskQueue
{
private:
	//Timer  _one_sec_; // 秒定时器
	boost::shared_ptr<x_tcptaskpool> pool;
	x_list_tcptask tasks;  /**< 任务列表 */
	x_list_tcptask::size_type task_count;      /**< tasks计数(保证线程安全*/
	int efd;
	std::vector<struct epoll_event> epfds;

	void _add(shared_ptr<x_tcptask> task)
	{
		task->add_epoll(efd,EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLPRI,(void*)task.get());
		tasks.push_back(task);
		task_count = tasks.size();
		task->ListeningRecv(false);
	}
public:

	static const x_list_tcptask::size_type connPerThread = 512;  //per thread keep connection num

	x_okay_thread_functor( boost::shared_ptr<x_tcptaskpool> _pool):pool(_pool)
	{
		task_count = 0;
		efd = epoll_create(connPerThread);
		assert(-1 != efd);
		epfds.resize(connPerThread);
	}

	~x_okay_thread_functor()
	{
		TEMP_FAILURE_RETRY(::close(efd));
	}

	//void run();
	virtual void operator()();

	const x_list_tcptask::size_type size() const
	{
		return task_count + _size;
	}

};

void x_okay_thread_functor::operator()()
{
	/*
	x_list_tcptask_it it,next;
	pollfdContainer::size_type i;

	int time = pool->usleep_time;
	pollfdContainer::iterator iter_r;
	pollfdContainer pfds_r;
	x_list_tcptask tasks_r;    
	bool check=false;
	*/
	boost::timer _50_msec;
	int efd_r = epoll_create(256);
	assert(-1 != efd_r);
	std::vector<epoll_event> epfds_r;
	epfds_r.resize(256);
	uint32_t fds_count_r = 0;
	bool check = false;
	while(!is_final())
	{
		if (check)
		{
			check_queue();
			if (!tasks.empty())
			{
				for(x_list_tcptask_it it = tasks.begin(); it != tasks.end(); )
				{
					shared_ptr<x_tcptask> task = *it;
					task->checkSignal(1.2f);

					if (task->isTerminateWait())
					{
						task->Terminate();
					}
					if (task->isTerminate())
					{
						if(task->isFdsrAdd())
						{
							task->del_epoll(efd_r,EPOLLIN | EPOLLERR | EPOLLPRI);
							fds_count_r --;
						}
						it = tasks.erase(it);
						task_count = tasks.size();
						// state_sync -> state_okay
						/*
						* whj
						* 先设置状态再添加容器,
						* 否则会导致一个task同时在两个线程中的危险情况
						*/

						//add by liuqing, for accurate
						//maybe it is affact performance
						if (task->isUnique())
							task->uniqueRemove();
						//!
						task->getNextState();
						pool->addRecycle(task);
					}
					else
					{
						//epoll for read
						if(!task->isFdsrAdd())
						{
							task->add_epoll(efd_r, EPOLLIN | EPOLLERR | EPOLLPRI, (void*)task.get());
							task->fdsrAdd();
							++fds_count_r;
							if(fds_count_r > epfds_r.size())
								epfds_r.resize(fds_count_r + 16);
						}
						it ++;
					}
				}
			}
			check=false;
		}

		boost::this_thread::sleep_for(ms(2));
		if(fds_count_r)
		{
			int retcode = epoll_wait(efd_r,&epfds_r[0],fds_count_r ,0);
			if(retcode > 0)
			{
				for(int i=0;i<retcode;++i)
				{
					shared_ptr<x_tcptask> task = ((x_tcptask*)epfds_r[i].data.ptr)->shared_from_this();
					if(epfds_r[i].events & (EPOLLERR | EPOLLPRI))
					{
						task->Terminate(x_tcptask::terminate_active);
						check = true;
					}
					else
					{
						if(epfds_r[i].events & EPOLLIN)
						{
							if(!task->ListeningRecv(true))
							{
								task->Terminate(x_tcptask::terminate_active);
								check = true;
							}
						}
					}
					epfds_r[i].events = 0;
				}
			}
		}

		if (check)
		{
			continue;
		}
		if(_50_msec.elapsed() >= (pool->usleep_time/1000))
		{
			_50_msec.restart();
			if (!tasks.empty())
			{
				int retcode = epoll_wait(efd,&epfds[0],task_count,0);
				if(retcode > 0)
				{
					for(int i=0;i<retcode;++i)
					{
						shared_ptr<x_tcptask> task = ((x_tcptask*)epfds[i].data.ptr)->shared_from_this();
						if(epfds[i].events & (EPOLLERR | EPOLLPRI))
						{
							Xlogger->debug("socket error,(%s,%u)",task->getIP(),task->getPort());
							task->Terminate(x_tcptask::terminate_active);
						}
						else
						{
							if(epfds[i].events & EPOLLIN)
							{
								if(!task->ListeningRecv(true))
								{
									Xlogger->debug("socket read error,(%s,%u)",task->getIP(),task->getPort());
									task->Terminate(x_tcptask::terminate_active);
								}
							}
							if(epfds[i].events & EPOLLOUT)
							{
								{
									//just test for nothing
									Cmd::t_NullCmd cmd;
									task->sendCmd(&cmd,sizeof(cmd));
								}
								if(!task->ListeningSend())
								{
									Xlogger->debug("socket write error,(%s,%u)",task->getIP(),task->getPort());
									task->Terminate(x_tcptask::terminate_active);
								}
							}
						}
						epfds[i].events = 0;
					}
				}
			}
			check = true;
		}
	}

	for(x_list_tcptask_it it = tasks.begin(); it != tasks.end();)
	{
		shared_ptr<x_tcptask> task = *it;
		it = tasks.erase(it);
		task->getNextState();
		pool->addRecycle(task);
	}
}

class x_recycle_thread_functor : public x_thread_functor, public zTCPTaskQueue
{
private:
	boost::shared_ptr<x_tcptaskpool> pool;
	x_list_tcptask tasks;

	void _add(shared_ptr<x_tcptask> task)
	{
		tasks.push_back(task);
	}

public:
	x_recycle_thread_functor( shared_ptr<x_tcptaskpool> _pool) : pool(_pool) {} 
	~x_recycle_thread_functor() {};

	//void run();
	virtual void operator()();

};

void x_recycle_thread_functor::operator()()
{
	Xlogger->debug("x_recycle_thread_functor::run");
	x_list_tcptask_it it;
	while(!is_final())
	{		
		check_queue();

		if (!tasks.empty())
		{
			for(it = tasks.begin(); it != tasks.end();)
			{
				shared_ptr<x_tcptask> task = *it;
				switch(task->recycleConn())
				{
				case 1:
					//recycle process to release resource
					it = tasks.erase(it);
					if (task->isUnique())//is it redundancy
						task->uniqueRemove();
					task->getNextState();
					//SAFE_DELETE(task); because it is shared_ptr,it is not necessary to explicitly release memory,or it is not allowed.
					break;
				default:
					//recycle overtime,next turn to process
					++it;
					break;
				}
			}
		}

		boost::this_thread::sleep_for(ms(200));
	}

	for(it = tasks.begin(); it != tasks.end();)
	{
		shared_ptr<x_tcptask> task = *it;
		it = tasks.erase(it);
		if (task->isUnique())
			task->uniqueRemove();
		task->getNextState();
	}
}

const int x_tcptaskpool::getSize() const
{
	size_t n = 0;
	for(size_t i=0;i<okayThreadFunctors.size();++i)
	{
		n += okayThreadFunctors[i]->size();
	}
	return n;
}

//nofity for add to thread
bool x_tcptaskpool::addVerify(shared_ptr<x_tcptask> task)
{
	size_t n = verifyThreadFunctors.size();
	if(n == 0)
	{
		Xlogger->fatal("x_tcptaskpool::addVerify: no thread start");
		return false;
	}

	//simple hash algorithm
	static uint32_t hashcode = 0;
	shared_ptr<x_verify_thread_functor> pVerifyThread = verifyThreadFunctors[++hashcode % n];
	if (pVerifyThread)
	{
		task->getNextState();
		pVerifyThread->add(task);
		return true;
	}
	else
		return false;
}

bool x_tcptaskpool::addSync(shared_ptr<x_tcptask> task)
{
	Xlogger->debug("x_tcptaskpool::addSync");
	if(syncThreadFunctor && !syncThreadFunctor->is_final())
	{
		task->getNextState();
		syncThreadFunctor->add(task);
		return true;
	}
	else
		return false;
}

bool x_tcptaskpool::addOkay(shared_ptr<x_tcptask> task)
{
	//find the thread functor which contains the least connection.
	shared_ptr<x_okay_thread_functor> pmin ,nostart;
	for(size_t i = 0; i < okayThreadFunctors.size(); i++)
	{
		shared_ptr<x_okay_thread_functor> pOkayThread = okayThreadFunctors[i];
		if (pOkayThread)
		{
			if (!pOkayThread->is_final())
			{
				if (!pmin || pmin->size() > pOkayThread->size())
					pmin = pOkayThread;
			}
			/*
			else
			{
				//find a thread that is terminate
				nostart = pOkayThread;
				break;
			}
			*/
		}
	}
	if (pmin && pmin->size() < x_okay_thread_functor::connPerThread)
	{
		task->getNextState();
		// not yet reach the up limitation
		pmin->add(task);
		return true;
	}
	/*
	if (nostart)
	{
		//线程还没有运行,需要创建线程,再把添加到这个线程的处理队列中
		if (nostart->start())
		{
			Xlogger->debug("x_tcptaskpool创建工作线程");
			// state_sync -> state_okay
			task->getNextState();
			//这个线程同时处理的连接数还没有到达上限
			nostart->add(task);
			return true;
		}
		else
			Xlogger->fatal("x_tcptaskpool不能创建工作线程");
	}
	*/

	Xlogger->fatal("x_tcptaskpool can't find a thread functor to process");
	return false;
}

void x_tcptaskpool::addRecycle(shared_ptr<x_tcptask> task)
{
	recycleThreadFunctor->add(task);
}

bool x_tcptaskpool::init()
{
	Xlogger->debug(__PRETTY_FUNCTION__);

	for(int i = 0; i < maxVerifyThreads; i++)
	{
		shared_ptr<x_verify_thread_functor> pVerifyThreadFunctor(new x_verify_thread_functor(shared_from_this()));
		if (!pVerifyThreadFunctor)
			return false;

		if(verifyThreads.create_thread(boost::ref(*pVerifyThreadFunctor)))	//already added to the group
		{
			verifyThreadFunctors.push_back(pVerifyThreadFunctor);
		}
		else
			return false;
	}
	Xlogger->debug(" verifyThreads size=%lu",verifyThreads.size());

	syncThreadFunctor.reset(new x_sync_thread_functor(shared_from_this()));//implement
	if(!syncThreadFunctor)
		return false;
	syncThread.reset(new boost::thread(boost::ref(*syncThreadFunctor)));	//new thread
	if(!syncThread)
		return false;

	maxThreadCount = (maxConns + x_okay_thread_functor::connPerThread - 1) / x_okay_thread_functor::connPerThread;
	Xlogger->debug("max conn%d, max conn per thread %ld, thread num %d",maxConns,x_okay_thread_functor::connPerThread,maxThreadCount);
	for(int i = 0; i < maxThreadCount; i++)
	{
		shared_ptr<x_okay_thread_functor> pOkayThreadFunctor(new x_okay_thread_functor(shared_from_this()));
		if (!pOkayThreadFunctor)
			return false;

		//boost::bind
		if(okayThreads.create_thread(boost::ref(*pOkayThreadFunctor)))	//already added to the group
		{
			okayThreadFunctors.push_back(pOkayThreadFunctor);
		}
		else
			return false;
	}

	recycleThreadFunctor.reset(new x_recycle_thread_functor(shared_from_this()));//implement
	if(!recycleThreadFunctor)
		return false;
	recycleThread.reset(new boost::thread(boost::ref(*recycleThreadFunctor)));	//new thread
	if(!recycleThread)
		return false;

	return true;
}

void x_tcptaskpool::final()
{
	std::for_each(verifyThreadFunctors.begin(),verifyThreadFunctors.end(),boost::bind(&x_thread_functor::final,_1));
	if (verifyThreads.size())
		verifyThreads.join_all();

	if (syncThreadFunctor)
		syncThreadFunctor->final();
	if (syncThread)
		syncThread->join();

	std::for_each(okayThreadFunctors.begin(),okayThreadFunctors.end(),boost::bind(&x_thread_functor::final,_1));
	if (okayThreads.size())
		okayThreads.join_all();

	if (recycleThreadFunctor)
		recycleThreadFunctor->final();
	if (recycleThread)
		recycleThread->join();
}

