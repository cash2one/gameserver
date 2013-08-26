/**
* \brief ʵ���̳߳���,���ڴ�������ӷ�����
*
* 
*/
#include <zebra/srvEngine.h>

#include <assert.h>
//#include <ext/pool_allocator.h>

#include <iostream>

/**
* \brief ���TCP����״��,���δ����,��������
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
* \brief ������������
*
*/
//typedef std::list<x_tcp_clientTask *,__gnu_cxx::__pool_alloc<x_tcp_clientTask *> > x_tcp_clientTaskContainer;
typedef std::list<x_tcp_clientTask *> x_tcp_clientTaskContainer;

/**
* \brief �����������������
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
* \brief ����TCP���ӵ���֤,�����֤��ͨ��,��Ҫ�����������
*
*/
class zCheckwaitThread : public zThread,public x_tcp_clientTaskQueue
{

private:

	x_tcp_clientTaskPool *pool;
	x_tcp_clientTaskContainer tasks;  /**< �����б� */
	x_tcp_clientTaskContainer::size_type task_count;          /**< tasks����(��֤�̰߳�ȫ*/
	pollfdContainer pfds;

	/**
	* \brief ���һ����������
	* \param task ��������
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
	* \brief ���캯��
	* \param pool ���������ӳ�
	* \param name �߳�����
	*/
	zCheckwaitThread(
		x_tcp_clientTaskPool *pool,
		const std::string &name = std::string("zCheckwaitThread"))
		: zThread(name),pool(pool)
	{
		task_count = 0;
	}

	/**
	* \brief ��������
	*
	*/
	~zCheckwaitThread()
	{
	}

	virtual void run();

};

/**
* \brief �ȴ�������ָ֤��,��������֤
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
					//�׽ӿڳ��ִ���
					printf("�׽ӿڳ��ִ���remove\n");
					remove(it,i--);
					task->resetState();
				}
				else if( pfds[i].revents & POLLIN )
				{
					switch(task->checkRebound())
					{
					case 1:
						//��֤�ɹ�,��ȡ��һ��״̬
						remove(it,i);
						if (!pool->addMain(task))
							task->resetState();
						break;
					case -1:
						//��֤ʧ��,��������
						printf("��֤ʧ��remove\n");
						remove(it,i);
						task->resetState();
						break;
					default:
						it ++;
						i  ++;
						//��ʱ,����ᴦ��
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
	//�����еȴ���֤�����е����Ӽ��뵽���ն�����,������Щ����
	for(i = 0,it = tasks.begin(); it != tasks.end();)
	{
		x_tcp_clientTask *task = *it;
		remove(it,i);
		task->resetState();
	}
}

/**
* \brief TCP���ӵ��������߳�,һ��һ���̴߳�����TCP����,���������������Ч��
*
*/
class x_tcp_clientTaskThread : public zThread,public x_tcp_clientTaskQueue
{

private:

	x_tcp_clientTaskPool *pool;
	x_tcp_clientTaskContainer tasks;  /**< �����б� */
	x_tcp_clientTaskContainer::size_type task_count;          /**< tasks����(��֤�̰߳�ȫ*/

	pollfdContainer pfds;

	zMutex m_Lock;
	/**
	* \brief ���һ����������
	* \param task ��������
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

	static const x_tcp_clientTaskContainer::size_type connPerThread = 256;  /**< ÿ���̴߳����������� */

	/**
	* \brief ���캯��
	* \param pool ���������ӳ�
	* \param name �߳�����
	*/
	x_tcp_clientTaskThread(
		x_tcp_clientTaskPool *pool,
		const std::string &name = std::string("x_tcp_clientTaskThread"))
		: zThread(name),pool(pool)
	{
		task_count = 0;

	}

	/**
	* \brief ��������
	*
	*/
	~x_tcp_clientTaskThread()
	{
	}

	virtual void run();

	/**
	* \brief ������������ĸ���
	* \return ����̴߳��������������
	*/
	const x_tcp_clientTaskContainer::size_type size() const
	{
		return task_count + _size;
	}

};

/**
* \brief �������߳�,�ص��������ӵ��������ָ��
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
						//����ǵ�һ�μ��봦��,��ҪԤ�ȴ������е�����
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
							//�׽ӿڳ��ִ���
							Xlogger->debug("%x_tcp_clientTaskThread::run: �׽ӿ��쳣����");
							task->Terminate(x_tcp_clientTask::TM_sock_error);
						}
						else if( retcode > 0 )
						{
							//�׽ӿ�׼�����˶�ȡ����
							if (!task->ListeningRecv(true))
							{
								Xlogger->debug("x_tcp_clientTaskThread::run: �׽ӿڶ���������");
								task->Terminate(x_tcp_clientTask::TM_sock_error);
							}
						}
						retcode = task->WaitSend( false );
						if( retcode == - 1 )
						{
							//�׽ӿڳ��ִ���
							Xlogger->debug("%x_tcp_clientTaskThread::run: �׽ӿ��쳣����");
							task->Terminate(x_tcp_clientTask::TM_sock_error);
						}
						else if( retcode == 1 )
						{
							//�׽ӿ�׼������д�����
							if (!task->ListeningSend())
							{
								Xlogger->debug("x_tcp_clientTaskThread::run: �׽ӿ�д��������");
								task->Terminate(x_tcp_clientTask::TM_sock_error);
							}
						}
					}
					else
					{
						if( ::poll(&pfds[i],1,0) <= 0 ) continue;
						if ( pfds[i].revents & POLLPRI )
						{
							//�׽ӿڳ��ִ���
							Xlogger->debug("%x_tcp_clientTaskThread::run: �׽ӿ��쳣����");
							task->Terminate(x_tcp_clientTask::TM_sock_error);
						}
						else
						{
							if( pfds[i].revents & POLLIN)
							{
								//�׽ӿ�׼�����˶�ȡ����
								if (!task->ListeningRecv(true))
								{
									Xlogger->debug("x_tcp_clientTaskThread::run: �׽ӿڶ���������");
									task->Terminate(x_tcp_clientTask::TM_sock_error);
								}
							}
							if ( pfds[i].revents & POLLOUT)
							{
								//�׽ӿ�׼������д�����
								if (!task->ListeningSend())
								{
									Xlogger->debug("x_tcp_clientTaskThread::run: �׽ӿ�д��������");
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

	//��������������е����Ӽ��뵽���ն�����,������Щ����


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
* \brief ��������
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
* \brief ��ʼ���̳߳�,Ԥ�ȴ��������߳�
*
* \return ��ʼ���Ƿ�ɹ�
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
* \brief ��һ��ָ��������ӵ�����
* \param task ����ӵ�����
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
* \brief ��ʱִ�е�����
* ��Ҫ������ͻ��˶��߳�������
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
			//�Ѿ�������״̬,������������ź�
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
* \brief ��������ӵ��ȴ�������֤���صĶ�����
* \param task ����ӵ�����
*/
void x_tcp_clientTaskPool::addCheckwait(x_tcp_clientTask *task)
{
	checkwaitThread->add(task);
	task->getNextState();
}

/**
* \brief ��������ӵ�������ѭ����
* \param task ����ӵ�����
* \return ����Ƿ�ɹ�
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
		Xlogger->fatal("x_tcp_clientTaskPool::addMain: ���ܵõ�һ�������߳�");
		return false;
	}
}

