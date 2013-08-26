#pragma once
#ifndef _INC_SRVENGINE_H_
#define _INC_SRVENGINE_H_

#include <zebra/csCommon.h>
//#include <sys/types.h>
#include "baseLib/regex.h"
#include <zlib.h>
#include <libxml/parser.h>
#include "baseLib/timeLib.h"
//#include "baseLib/gcchash.h"
//#include "baseLib/gccmt_allocator.h"
//#include <string.h>
#include <assert.h>
//#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <list>
#include <queue>
//#include <xhash>
#include <hash_map>
//#include <hash_multimap>
#include <functional>

extern long g_RecvSize;
extern long g_SendSize;
extern long g_WantSendSize;
extern uint32_t g_SocketSize; 



// [ranqd] 包头格式定义
struct PACK_HEAD
{
	unsigned char Header[2];
	unsigned short Len;
	PACK_HEAD()
	{
		Header[0] = 0xAA;
		Header[1] = 0xDD;
	}
};
// [ranqd] 包尾格式定义
struct PACK_LAST
{
	unsigned char Last;
	PACK_LAST()
	{
		Last = 0xAA;
	}
};

#define PACKHEADLASTSIZE (sizeof(PACK_HEAD))

#define PACKHEADSIZE    sizeof(PACK_HEAD)

#define PACKLASTSIZE    0

template <class T>
class __mt_alloc
{
	T memPool[2046];
public:
	char * allocate(size_t  len){return (char*)malloc(len);}

	void deallocate(unsigned char* ptr,size_t len)
	{
		free(ptr);
	}


};

template <typename T>
class SingletonBase
{
public:
	SingletonBase() {}
	virtual ~SingletonBase() {}
	static T& getInstance()
	{
		assert(instance);
		return *instance;
	}
	static void newInstance()
	{
		SAFE_DELETE(instance);
		instance = new T();
	}
	static void delInstance()
	{
		SAFE_DELETE(instance);
	}
protected:
	static T* instance;
private:
	SingletonBase(const SingletonBase&);
	SingletonBase & operator= (const SingletonBase &);
};
template <typename T> T* SingletonBase<T>::instance = NULL;

using namespace std;
using namespace stdext;

//#include <ext/hash_map>
//#include <ext/pool_allocator.h>
////#include <ext/mt_allocator.h>

/**
* \brief 把字符串根据token转化为多个字符串
*
* 下面是使用例子程序：
*    <pre>
*    std::list<string> ls;
*    stringtok (ls," this  \t is\t\n  a test  ");
*    for(std::list<string>const_iterator i = ls.begin(); i != ls.end(); ++i)
*        std::cerr << ':' << (*i) << ":\n";
*     </pre>
*
* \param container 容器，用于存放字符串
* \param in 输入字符串
* \param delimiters 分隔符号
* \param deep 深度，分割的深度，缺省没有限制
*/
template <typename Container>
inline void
stringtok(Container &container,std::string const &in,
		  const char * const delimiters = " \t\n",
		  const int deep = 0)
{
	const std::string::size_type len = in.length();
	std::string::size_type i = 0;
	int count = 0;

	while(i < len)
	{
		i = in.find_first_not_of (delimiters,i);
		if (i == std::string::npos)
			return;   // nothing left

		// find the end of the token
		std::string::size_type j = in.find_first_of (delimiters,i);

		count++;
		// push token
		if (j == std::string::npos
			|| (deep > 0 && count > deep)) {
				container.push_back (in.substr(i));
				return;
		}
		else
			container.push_back (in.substr(i,j-i));

		// set up for next loop
		i = j + 1;
	}
}

/**
* \brief 把字符转化为小写的函数对象
*
* 例如：
* <pre>
* std::string  s ("Some Kind Of Initial Input Goes Here");
* std::transform (s.begin(),s.end(),s.begin(),ToLower());
* </pre>
*/
struct ToLower
{
	char operator() (char c) const
	{
		//return std::tolower(c);
		return tolower(c);
	}
};

/**
* \brief 把字符串转化为小写
* 
* 把输入的字符串转化为小写
*
* \param s 需要转化的字符串
*/
inline void to_lower(std::string &s)
{
	std::transform(s.begin(),s.end(),s.begin(),ToLower());
}

/**
* \brief 把字符转化为大写的函数对象
*
* 例如：
* <pre>
* std::string  s ("Some Kind Of Initial Input Goes Here");
* std::transform (s.begin(),s.end(),s.begin(),ToUpper());
* </pre>
*/
struct ToUpper
{
	char operator() (char c) const
	{
		return toupper(c);
	}
};

/**
* \brief 把字符串转化为大写
* 
* 把输入的字符串转化为大写
*
* \param s 需要转化的字符串
*/
inline void to_upper(std::string &s)
{
	std::transform(s.begin(),s.end(),s.begin(),ToUpper());
}

/**
* \brief png格式的验证码生成器
*/
void *jpeg_Passport(char *buffer,const int buffer_len,int *size);

/**
* \brief base64编码解码函数
*/
void base64_encrypt(const std::string &input,std::string &output);
void base64_decrypt(const std::string &input,std::string &output);

template <typename V>
class Parse
{
public:
	V* operator () (const std::string& down,const std::string& separator_down)
	{
		std::string::size_type pos = 0;
		if  ( (pos = down.find(separator_down)) != std::string::npos ) {

			std::string first_element = down.substr(0,pos);
			std::string second_element = down.substr(pos+separator_down.length());
			return new V(first_element,second_element);
		}

		return NULL;
	}
};

template <typename V>
class Parse3
{
public:
	V* operator () (const std::string& down,const std::string& separator_down)
	{
		std::string::size_type pos = 0;
		if  ( (pos = down.find(separator_down)) != std::string::npos ) {

			std::string first_element = down.substr(0,pos);
			std::string::size_type npos = 0;
			if ((npos = down.find(separator_down,pos+separator_down.length())) != std::string::npos) {
				std::string second_element = down.substr(pos+separator_down.length(),npos-pos);
				std::string third_element = down.substr(npos+separator_down.length());
				return new V(first_element,second_element,third_element);
			}
		}

		return NULL;
	}
};

/**
* \brief  分隔由二级分隔符分隔的字符串
* \param list 待分隔的字符串
* \param dest 存储分隔结果，必须满足特定的语义要求
* \param separator_up 一级分隔符
* \param separator_down 二级分隔符     
*/
template <template <typename> class P = Parse>
class Split
{
public:

	template <typename T>
	void operator() (const std::string& list,T& dest,const std::string& separator_up = ";",const std::string& separator_down = ",")
	{  
		typedef typename T::value_type value_type;
		typedef typename T::pointer pointer;

		std::string::size_type lpos = 0;
		std::string::size_type pos = 0;
		P<value_type> p;


		while ( ( lpos = list.find(separator_up,pos)) != std::string::npos) {
			/*
			std::string down = list.substr(pos,lpos - pos);
			std::string::size_type dpos = 0;
			if  ( (dpos = down.find(separator_down)) != std::string::npos ) {

			std::string first_element = down.substr(0,dpos);
			std::string second_element = down.substr(dpos+separator_down.length());
			dest.push_back(typename T::value_type(first_element,second_element));
			}
			pos = lpos+1;
			*/
			std::string down = list.substr(pos,lpos - pos);
			pointer v = p(down,separator_down);
			if (v) {
				dest.push_back(*v);
				SAFE_DELETE(v);
			}
			pos = lpos+1;
		}

		std::string down = list.substr(pos,lpos - pos);
		pointer v = p(down,separator_down);
		if (v) {
			dest.push_back(*v);
			SAFE_DELETE(v);
		}
	}
};


struct UrlInfo
{
	const uint32_t hashcode;
	const std::string url;
	const bool supportTransactions;

	char host[MAX_HOSTSIZE];
	char user[MAX_USERSIZE];
	char passwd[MAX_PASSuint16_t];
	uint32_t port;
	char dbName[MAX_DBSIZE];

	UrlInfo()
		: hashcode(0),url(),supportTransactions(false) {};
	UrlInfo(const uint32_t hashcode,const std::string &url,const bool supportTransactions)
		: hashcode(hashcode),url(url),supportTransactions(supportTransactions)
	{
		parseMySQLURLString();
	}
	UrlInfo(const UrlInfo &ui)
		: hashcode(ui.hashcode),url(ui.url),supportTransactions(ui.supportTransactions)
	{
		parseMySQLURLString();
	}

private:
	void parseMySQLURLString()
	{
		bzero(host,sizeof(host));
		bzero(user,sizeof(user));
		bzero(passwd,sizeof(passwd));
		port=3306;
		bzero(dbName,sizeof(dbName));

		char strPort[16] = "";
		int  j,k;
		size_t i;
		const char *connString = url.c_str();
		if (0 == strncmp(connString,"mysql://",strlen("mysql://")))
		{
			i = 0; j = 0; k = 0;
			for(i = strlen("mysql://"); i < strlen(connString) + 1; i++)
			{
				switch(j)
				{
				case 0:
					if (connString[i] == ':')
					{
						user[k] = '\0'; j++; k = 0;
					}
					else
						user[k++] = connString[i];
					break;
				case 1:
					if (connString[i] == '@')
					{
						passwd[k] = '\0'; j++; k = 0;
					}
					else
						passwd[k++] = connString[i];
					break;
				case 2:
					if (connString[i] == ':')
					{
						host[k] = '\0'; j++; k = 0;
					}
					else
						host[k++] = connString[i];
					break;
				case 3:
					if (connString[i] == '/')
					{
						strPort[k] = '\0'; j++; k = 0;
					}
					else
						strPort[k++] = connString[i];
					break;
				case 4:
					if (connString[i] == '\0')
					{
						dbName[k] = '\0'; j++; k = 0;
					}
					else
						dbName[k++] = connString[i];
					break;
				default:
					break;
				}
			}
		}
		port=atoi(strPort);
	}
};




/**
* \brief 定义x_socket类，用于对套接口底层进行封装
*/
#define SHUT_RDWR       SD_BOTH
#define SHUT_RD         SD_RECEIVE
#define SHUT_WR         SD_SEND

#define MSG_NOSIGNAL    0
#define EWOULDBLOCK     WSAEWOULDBLOCK

#ifdef __cplusplus
extern "C"{
#endif //__cplusplus

#define POLLIN  1       /* Set if data to read. */
#define POLLPRI 2       /* Set if urgent data to read. */
#define POLLOUT 4       /* Set if writing data wouldn't block. */

	class x_socket;

	struct pollfd {
		int fd;
		short events;
		short revents;
		x_socket* pSock;
	};

	extern int poll(struct pollfd *fds,unsigned int nfds,int timeout);
	extern int WaitRecvAll( struct pollfd *fds,unsigned int nfds,int timeout );

#ifdef __cplusplus
}
#endif //__cplusplus

// [ranqd] IO操作状态标志
typedef   enum   enum_IOOperationType   
{     
	IO_Write,     // 写
	IO_Read		  // 读

}IOOperationType,   *LPIOOperationType;

/**
* \brief 对数据进行组织,需要时压缩,不加密
* \param pData 待组织的数据，输入
* \param nLen 待拆包的数据长度，输入
* \param cmd_queue 输出，存放数据
* \return 封包后的大小
*/
template<typename buffer_type>
inline uint32_t x_socket::packetAppendNoEnc(const void *pData,const uint32_t nLen,buffer_type &cmd_queue)
{
	//	Xlogger->debug("输入长度1： %d", nLen);
	int nSize = packetPackZip(pData,nLen,cmd_queue,PACKET_ZIP == (bitmask & PACKET_ZIP));
	//	Xlogger->debug("封包长度1： %d", nSize);	

	return nSize;

}

/**
* \brief 对数据进行组织,需要时压缩和加密
* \param pData 待组织的数据，输入
* \param nLen 待拆包的数据长度，输入
* \param cmd_queue 输出，存放数据
* \return 封包后的大小
*/
template<typename buffer_type>
inline uint32_t x_socket::packetAppend(const void *pData,const uint32_t nLen,buffer_type &cmd_queue)
{
	//	Xlogger->debug("输入长度2： %d", nLen);
	t_StackCmdQueue t_cmd_queue;
	uint32_t nSize = packetPackZip( pData,nLen,t_cmd_queue,PACKET_ZIP == (bitmask & PACKET_ZIP));
	if (need_enc())
		nSize = packetPackEnc(t_cmd_queue,t_cmd_queue.rd_size());
	//	Xlogger->debug("封包长度2： %d", nSize);
	PACK_HEAD head;
	head.Len = t_cmd_queue.rd_size();
	cmd_queue.put((BYTE*)&head, sizeof(head));
	cmd_queue.put(t_cmd_queue.rd_buf(), t_cmd_queue.rd_size());
	return nSize;
}

/**
* \brief         对数据进行加密
* \param cmd_queue    待加密的数据，输入输出
* \param current_cmd  最后一个指令长度
* \param offset    待加密数据的偏移
* \return         返回加密以后真实数据的大小
*/
template<typename buffer_type>
inline uint32_t x_socket::packetPackEnc(buffer_type &cmd_queue,const uint32_t current_cmd,uint32_t offset)
{
	uint32_t mod = (cmd_queue.rd_size() - offset) % 8;
	if (0!=mod)
	{
		mod = 8 - mod;
		// [ranqd] 这样似乎更合理
		//(*(uint32_t *)(&(cmd_queue.rd_buf()[cmd_queue.rd_size() - current_cmd - PACKLASTSIZE]))) += mod;
		(*(uint32_t *)(&(cmd_queue.rd_buf()[cmd_queue.rd_size() - current_cmd]))) += mod;
		cmd_queue.wr_flip(mod);
	}

	//加密动作
	enc.encdec(&cmd_queue.rd_buf()[offset],cmd_queue.rd_size() - offset,true);

	return cmd_queue.rd_size();
}

/**
* \brief       对数据进行压缩,由上层判断是否需要加密,这里只负责加密不作判断
* \param pData   待压缩的数据，输入
* \param nLen     待压缩的数据长度，输入
* \param pBuffer   输出，存放压缩以后的数据
* \param _compress  当数据包过大时候是否压缩
* \return       返回加密以后真实数据的大小
*/
template<typename buffer_type>
inline uint32_t x_socket::packetPackZip(const void *pData,const uint32_t nLen,buffer_type &cmd_queue,const bool _compress)
{
	/*if (nLen > MAX_DATASIZE)
	{
	Cmd::t_NullCmd *cmd = (Cmd::t_NullCmd *)pData;
	Xlogger->warn("x_socket::packetPackZip: 发送的数据包过大(cmd = %u,para = %u",cmd->cmd,cmd->para);
	}*/
	uint32_t nSize = nLen > MAX_DATASIZE ? MAX_DATASIZE : nLen;//nLen & PACKET_MASK;
	uint32_t nMask = 0;//nLen & (~PACKET_MASK);
	if (nSize > PACKET_ZIP_MIN /*数据包过大*/ 
		&& _compress /*带压缩标记，数据包需要压缩*/
		/*&& !(nMask & PACKET_ZIP)*/ /*数据包过大可能已经是压缩过的*/ )
	{
		uLong nZipLen = unzip_size(nSize);
		cmd_queue.wr_reserve(nZipLen + PH_LEN);
		int retcode = compress(&(cmd_queue.wr_buf()[PH_LEN]),&nZipLen,(const Bytef *)pData,nSize);
		switch(retcode)
		{
		case Z_OK:
			break;
		case Z_MEM_ERROR:
			Xlogger->fatal("x_socket::packetPackZip Z_MEM_ERROR.");
			break;
		case Z_BUF_ERROR:
			Xlogger->fatal("x_socket::packetPackZip Z_BUF_ERROR.");
			break;
		}
		nSize = nZipLen;
		nMask |= PACKET_ZIP;
	}
	else
	{
		cmd_queue.wr_reserve(nSize + PH_LEN);
		bcopy(pData,&(cmd_queue.wr_buf()[PH_LEN]),nSize,cmd_queue.wr_size());
	}

	(*(uint32_t *)(cmd_queue.wr_buf())) = (nSize | nMask);

	cmd_queue.wr_flip(nSize + PH_LEN);

	return nSize + PH_LEN;
}

class zAcceptThread;

// [ranqd] 接收连接线程类
class zAcceptThread : public zThread
{
public:
	zAcceptThread( x_netservice* p, const std::string &name ): zThread(name)
	{
		pService = p;
	}
	~zAcceptThread()
	{
		final();
		join();
	}
	x_netservice* pService;

	void run()         // [ranqd] 接收连接线程函数
	{
		while(!isFinal())
		{
			//Xlogger->debug("接收连接线程建立！");
			struct sockaddr_in addr;
			if( pService->tcpServer != NULL )
			{
				int retcode = pService->tcpServer->accept(&addr);
				if (retcode >= 0) 
				{
					//接收连接成功，处理连接
					pService->newTCPTask(retcode,&addr);
				}
			}
		}
	}
};


/**
* \brief zMTCPServer类，封装了服务器监听模块，可以方便的创建一个服务器对象，等待客户端的连接
* 可以同时监听多个端口
*/
class zMTCPServer : private boost::noncopyable
{
public:
	typedef std::map<int,uint16_t> Sock2Port;
	typedef Sock2Port::value_type Sock2Port_value_type;
	typedef Sock2Port::iterator Sock2Port_iterator;
	typedef Sock2Port::const_iterator Sock2Port_const_iterator;

	zMTCPServer(const std::string &name);
	~zMTCPServer() ;

	bool bind(const std::string &name,const uint16_t port);
	int accept(Sock2Port &res);

private:

	static const int T_MSEC =2100;      /**< 轮询超时，毫秒 */
	static const int MAX_WAITQUEUE = 2000;  /**< 最大等待队列 */

	std::string name;            /**< 服务器名称 */
	Sock2Port mapper;
	zMutex mlock;
	std::vector<struct pollfd> pfds;

}; 

/**
* \brief 网络服务器类
* 实现了网络服务器框架代码，这个类比较通用一点
*/
class zMNetService : public x_service
{

public:

	/**
	* \brief 虚析构函数
	*/
	virtual ~zMNetService() { instance = NULL; };

	/**
	* \brief 根据得到的TCP/IP连接获取一个连接任务
	* \param sock TCP/IP套接口
	* \param srcPort 由于服务器绑定了多个端口，这个参数指定连接来自那个绑定端口
	* \return 新建立的连接任务
	*/
	virtual void newTCPTask(const int sock,const uint16_t srcPort) = 0;

	/**
	* \brief 绑定服务到某个端口
	* \param name 待绑定端口名称
	* \param port 待绑定的端口
	* \return 绑定是否成功
	*/
	bool bind(const std::string &name,const uint16_t port)
	{
		if (tcpServer)
			return tcpServer->bind(name,port);
		else
			return false;
	}

protected:

	/**
	* \brief 构造函数
	* 受保护的构造函数，实现了Singleton设计模式，保证了一个进程中只有一个类实例
	* \param name 名称
	*/
	zMNetService(const std::string &name) : x_service(name)
	{
		instance = this;

		serviceName = name;
		tcpServer = NULL;
	}

	bool init();
	bool serviceCallback();
	void final();

private:
	static zMNetService *instance;    /**< 类的唯一实例指针，包括派生类，初始化为空指针 */
	std::string serviceName;      /**< 网络服务器名称 */
	zMTCPServer *tcpServer;        /**< TCP服务器实例指针 */
};


/**
* \brief TCP客户端
*
* 封装了一些TCP客户端的逻辑，比如建立连接等等
*
*/
class x_tcp_clientTask : public zProcessor,private boost::noncopyable
{

public:

	/**
	* \brief 连接断开类型
	*
	*/
	enum TerminateMethod
	{
		TM_no,          /**< 没有结束任务 */
		TM_sock_error,      /**< 检测到套接口关闭或者套接口异常 */
		TM_service_close      /**< 服务器即将关闭 */
	};

	/**
	* \brief 连接任务状态
	*
	*/
	enum ConnState
	{
		close    =  0,            /**< 连接关闭状态 */
		sync    =  1,            /**< 等待同步状态 */
		okay    =  2,            /**< 连接处理阶段 */
		recycle    =  3              /**< 连接退出状态 */
	};

	/**
	* \brief 构造函数，创建实例对象，初始化对象成员
	* \param ip 地址
	* \param port 端口
	* \param compress 底层数据传输是否支持压缩
	*/
	x_tcp_clientTask(
		const std::string &ip,
		const uint16_t port,
		const bool compress = false) : pSocket(NULL),compress(compress),ip(ip),port(port),_ten_min(600)
	{
		state = close;
		terminate = TM_no;
		mainloop = false;
		fdsradd = false; 
	}

	/**
	* \brief 析构函数，销毁对象
	*/
	virtual ~x_tcp_clientTask() 
	{
		final();
	}

	/**
	* \brief 清楚数据
	*
	*/
	void final()
	{
		//		SAFE_DELETE(pSocket);
		if( pSocket != NULL )
		{
			if(pSocket->SafeDelete( false ))
				delete pSocket;
			pSocket = NULL;
		}		
		terminate = TM_no;
		mainloop = false;
	}

	/**
	* \brief 判断是否需要关闭连接
	* \return true or false
	*/
	bool isTerminate() const
	{
		return TM_no != terminate;
	}

	/**
	* \brief 需要主动断开客户端的连接
	* \param method 连接断开方式
	*/
	void Terminate(const TerminateMethod method)
	{
		terminate = method;
	}

	/**
	* \brief 如果是第一次进入主循环处理，需要先处理缓冲中的指令
	* \return 是否是第一次进入主处理循环
	*/
	bool checkFirstMainLoop()
	{
		if (mainloop)
			return false;
		else
		{
			mainloop = true;
			return true;
		}
	}

	/**
	* \brief 获取连接任务当前状态
	* \return 状态
	*/
	const ConnState getState() const
	{
		return state;
	}

	/**
	* \brief 设置连接任务下一个状态
	* \param state 需要设置的状态
	*/
	void setState(const ConnState state)
	{
		this->state = state;
	}

	/**
	* \brief 获得状态的字符串描述
	* \param state 状态
	* \return 返回状态的字符串描述
	*/
	const char *getStateString(const ConnState state)
	{
		const char *retval = NULL;

		switch(state)
		{
		case close:
			retval = "close";
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
		}

		return retval;
	}


	/**
	* \brief 填充pollfd结构
	* \param pfd 待填充的结构
	* \param events 等待的事件参数
	*/
	void fillPollFD(struct pollfd &pfd,short events)
	{
		if (pSocket)
			pSocket->fillPollFD(pfd,events);
	}

	/**
	* \brief 检测某种状态是否验证超时
	* \param state 待检测的状态
	* \param ct 当前系统时间
	* \param timeout 超时时间
	* \return 检测是否成功
	*/
	bool checkStateTimeout(const ConnState state,const zTime &ct,const time_t timeout) const
	{
		if (state == this->state)
			return (lifeTime.elapse(ct) >= timeout);
		else
			return false;
	}

	/**
	* \brief 连接验证函数
	*
	* 子类需要重载这个函数用于验证一个TCP连接，每个TCP连接必须通过验证才能进入下一步处理阶段，缺省使用一条空的指令作为验证指令
	* <pre>
	* int retcode = pSocket->recvToBuf_NoPoll();
	* if (retcode > 0)
	* {
	*     BYTE pstrCmd[x_socket::MAX_DATASIZE];
	*     int nCmdLen = pSocket->recvToCmd_NoPoll(pstrCmd,sizeof(pstrCmd));
	*     if (nCmdLen <= 0)
	*       //这里只是从缓冲取数据包，所以不会出错，没有数据直接返回
	*       return 0;
	*     else
	*     {
	*       x_socket::t_NullCmd *pNullCmd = (x_socket::t_NullCmd *)pstrCmd;
	*       if (x_socket::null_opcode == pNullCmd->opcode)
	*       {
	*         std::cout << "客户端连接通过验证" << std::endl;
	*         return 1;
	*       }
	*       else
	*       {
	*         return -1;
	*       }
	*     }
	* }
	* else
	*     return retcode;
	* </pre>
	*
	* \return 验证是否成功，1表示成功，可以进入下一步操作，0，表示还要继续等待验证，-1表示等待验证失败，需要断开连接
	*/
	virtual int checkRebound()
	{
		return 1;
	}

	/**
	* \brief 需要删除这个TCP连接相关资源
	*/
	virtual void recycleConn() {};

	/**
	* \brief 一个连接任务验证等步骤完成以后，需要添加到全局容器中
	*
	* 这个全局容器是外部容器
	*
	*/
	virtual void addToContainer() {};

	/**
	* \brief 连接任务退出的时候，需要从全局容器中删除
	*
	* 这个全局容器是外部容器
	*
	*/
	virtual void removeFromContainer() {};

	virtual bool connect();

	void checkConn();
	bool sendCmd(const void *pstrCmd,const int nCmdLen);
	bool ListeningRecv(bool);
	bool ListeningSend();

	void getNextState();
	void resetState();
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
	bool fdsrAdd(bool set=true)
	{
		fdsradd=set;
		return fdsradd;
	}

	bool UseIocp()
	{
		return pSocket->m_bUseIocp;
	}

	int WaitRecv( bool bWait = false, int timeout = 0 )
	{
		return pSocket->WaitRecv( bWait, timeout );
	}

	int WaitSend( bool bWait = false, int timeout = 0 )
	{
		return pSocket->WaitSend( bWait, timeout );
	}

protected:

	x_socket *pSocket;                /**< 底层套接口 */
	volatile ConnState state;            /**< 连接状态 */

private:

	bool fdsradd;                  /**< 读事件添加标志 */
	const bool compress;              /**< 是否支持压缩 */
	const std::string ip;              /**< 服务器地址 */
	const uint16_t port;            /**< 服务器端口 */

	zTime lifeTime;                  /**< 生命期，记录每次状态改变的时间 */
	TerminateMethod terminate;            /**< 是否结束任务 */
	volatile bool mainloop;              /**< 是否已经进入主处理循环 */
	Timer _ten_min;

}; 

/**
* \brief 连接线程池类，封装了一个线程处理多个连接的线程池框架
*
*/
class x_tcp_clientTaskPool : private boost::noncopyable
{

public:

	explicit x_tcp_clientTaskPool(const uint32_t connPerThread,const int us=50000) : connPerThread(connPerThread)
	{       
		usleep_time=us;
		checkwaitThread = NULL; 
	} 
	~x_tcp_clientTaskPool();

	bool init();
	bool put(x_tcp_clientTask *task);
	void timeAction(const zTime &ct);

	void addCheckwait(x_tcp_clientTask *task);
	bool addMain(x_tcp_clientTask *task);
	void setUsleepTime(int time)
	{
		usleep_time = time;
	}

private:

	const uint32_t connPerThread;
	x_tcp_clientTaskThread *newThread();

	/**
	* \brief 连接检测线程
	*
	*/
	zCheckconnectThread *checkconnectThread;;
	/**
	* \brief 连接等待返回信息的线程
	*
	*/
	zCheckwaitThread *checkwaitThread;;
	/**
	* \brief 所有成功连接处理的主线程
	*
	*/
	zThreadGroup taskThreads;

	/**
	* \brief 连接任务链表
	*
	*/
	//typedef std::list<x_tcp_clientTask *,__pool_alloc<x_tcp_clientTask *> > x_tcp_clientTaskContainer;
	typedef std::list<x_tcp_clientTask *> x_tcp_clientTaskContainer;


	/**
	* \brief 连接任务链表叠代器
	*
	*/
	typedef x_tcp_clientTaskContainer::iterator x_tcp_clientTask_IT;

	zMutex mlock;          /**< 互斥变量 */
	x_tcp_clientTaskContainer tasks;  /**< 任务列表 */

public:
	int usleep_time;                                        /**< 循环等待时间 */
};

template <typename T>
struct singleton_default
{
private:
	singleton_default();

public:
	typedef T object_type;

	static object_type & instance()
	{
		return obj;
	}

	static object_type obj;
};
template <typename T>
typename singleton_default<T>::object_type singleton_default<T>::obj;

//手动调用构造函数，不分配内存
template<class _T1> 
inline  void constructInPlace(_T1  *_Ptr)
{
	new (static_cast<void*>(_Ptr)) _T1();
}
/// 声明变长指令
#define BUFFER_CMD(cmd,name,len) char buffer##name[len];\
	cmd *name=(cmd *)buffer##name;constructInPlace(name);

typedef std::pair<uint32_t,BYTE *> CmdPair;
template <int QueueSize=102400>
class MsgQueue
{
public:
	MsgQueue()
	{
		queueRead=0;
		queueWrite=0;
	}
	~MsgQueue()
	{
		clear();
	}
	typedef std::pair<volatile bool,CmdPair > CmdQueue;
	CmdPair *get()
	{
		CmdPair *ret=NULL;
		if (cmdQueue[queueRead].first)
		{
			ret=&cmdQueue[queueRead].second;
		}
		return ret;
	}
	void erase()
	{
		//SAFE_DELETE_VEC(cmdQueue[queueRead].second.second);
		__mt_alloc.deallocate(cmdQueue[queueRead].second.second,cmdQueue[queueRead].second.first);
		cmdQueue[queueRead].first=false;
		queueRead = (++queueRead)%QueueSize;
	}
	bool put(const void *pNullCmd,const uint32_t cmdLen)
	{
		//BYTE *buf = new BYTE[cmdLen];
		BYTE *buf = (BYTE*)__mt_alloc.allocate(cmdLen);
		if (buf)
		{
			bcopy(pNullCmd,buf,cmdLen,cmdLen);
			if (!putQueueToArray() && !cmdQueue[queueWrite].first)
			{
				cmdQueue[queueWrite].second.first = cmdLen;
				cmdQueue[queueWrite].second.second = buf;
				cmdQueue[queueWrite].first=true;
				queueWrite = (++queueWrite)%QueueSize;
				return true;
			}
			else
			{
				queueCmd.push(std::make_pair(cmdLen,buf));
			}
			return true;
		}
		return false;

	}
private:
	void clear()
	{
		while(putQueueToArray())
		{
			while(get())
			{
				erase();
			}
		}
		while(get())
		{
			erase();
		}
	}
	bool putQueueToArray()
	{
		bool isLeft=false;
		while(!queueCmd.empty())
		{
			if (!cmdQueue[queueWrite].first)
			{
				cmdQueue[queueWrite].second = queueCmd.front();;
				cmdQueue[queueWrite].first=true;
				queueWrite = (++queueWrite)%QueueSize;
				queueCmd.pop();
			}
			else
			{
				isLeft = true; 
				break;
			}
		}
		return isLeft;
	}
	__mt_alloc<BYTE> __mt_alloc;
	CmdQueue cmdQueue[QueueSize];
	std::queue<CmdPair> queueCmd;
	uint32_t queueWrite;
	uint32_t queueRead;
};

class MessageQueue
{
protected:
	virtual ~MessageQueue(){};
public:
	bool msgParse(const Cmd::t_NullCmd *pNullCmd,const uint32_t cmdLen) {
		Xlogger->debug("%s, %u", __PRETTY_FUNCTION__, __LINE__);
		return cmdQueue.put((void*)pNullCmd,cmdLen);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd *,const uint32_t)=0;
	bool doCmd()
	{
		CmdPair *cmd = cmdQueue.get();
		while(cmd)
		{
			cmdMsgParse((const Cmd::t_NullCmd *)cmd->second,cmd->first);
			cmdQueue.erase();
			cmd = cmdQueue.get();
		}
		if (cmd)
		{
			cmdQueue.erase();
		}
		return true;
	}

private:
	MsgQueue<> cmdQueue;
};

/**
* \brief zUniqueID模板
* 本模板实现了唯一ID生成器，并保证线程安全。
* 可以用各种长度的无符号整数作为ID。
*/
template <class T>
class zUniqueID:private boost::noncopyable
{
private:
	zMutex mutex;
	//std::list<T,__pool_alloc<T> > ids;
	std::list<T> ids;
	T maxID;
	T minID;
	T curMaxID;
	void init(T min,T max)
	{
		minID=min;
		maxID=max;
		curMaxID=minID;
	}

public:
	/**
	* \brief 默认构造函数 
	* 开始ID为1，最大有效ID为(T)-2,无效ID为(T)-1
	*/
	zUniqueID()
	{
		init(1,(T)-1);
	}

	/**
	* \brief 构造函数 
	* 用户自定义起始ID，最大有效ID为(T)-2,无效ID为(T)-1
	* \param startID 用户自定义的起始ID
	*/
	zUniqueID(T startID)
	{
		init(startID,(T)-1);
	}

	/**
	* \brief 构造函数 
	* 用户自定义起始ID，及最大无效ID,最大有效ID为最大无效ID-1
	* \param startID 用户自定义的起始ID
	* \param endID 用户自定义的最大无效ID
	*/
	zUniqueID(T startID,T endID)
	{
		init(startID,endID);
	}

	/**
	* \brief 析构函数 
	* 回收已分配的ID内存。
	*/
	~zUniqueID()
	{
		mutex.lock();
		ids.clear();
		mutex.unlock();
	}

	/**
	* \brief 得到最大无效ID 
	* \return 返回最大无效ID
	*/
	T invalid()
	{
		return maxID;
	}

	/**
	* \brief 测试这个ID是否被分配出去
	* \return 被分配出去返回true,无效ID和未分配ID返回false
	*/
	bool hasAssigned(T testid)
	{
		mutex.lock();
		if (testid<maxID && testid>=minID)
		{
			typename std::list<T,__pool_alloc<T> >::iterator iter = ids.begin();
			for(;iter != ids.end() ; iter ++)
			{
				if (*iter == testid)
				{
					mutex.unlock();
					return false;
				}
			}
			/*
			for(int i=0,n=ids.size() ;i<n;i++)
			{
			if (ids[i]==testid)
			{
			mutex.unlock();
			return false;
			}
			}
			// */
			mutex.unlock();
			return true;
		}
		mutex.unlock();
		return false;
	}

	/**
	* \brief 得到一个唯一ID 
	* \return 返回一个唯一ID，如果返回最大无效ID，比表示所有ID都已被用，无可用ID。
	*/
	T get()
	{
		T ret;
		mutex.lock();
		if (maxID>curMaxID)
		{
			ret=curMaxID;
			curMaxID++;
		}
		else
			ret=maxID;
		if (ret == maxID && !ids.empty())
		{
			ret=ids.back();
			ids.pop_back();
		}
		mutex.unlock();
		return ret;
	}

	/**
	* \brief 一次得到多个ID，这些ID都是相邻的,并且不回被放回去 
	* \param size 要分配的ID个数
	* \param count 实际分配ID的个数
	* \return 返回第一个ID，如果返回最大无效ID，比表示所有ID都已被用，无可用ID。
	*/
	T get(int size,int & count)
	{
		T ret;
		mutex.lock();
		if (maxID>curMaxID)
		{
			count=(maxID-curMaxID)>size?size:(maxID-curMaxID);
			ret=curMaxID;
			curMaxID+=count;
		}
		else
		{
			count=0;
			ret=maxID;
		}
		mutex.unlock();
		return ret;
	}

	/**
	* \brief 将ID放回ID池，以便下次使用。 
	* 
	* 放回的ID必须是由get函数得到的。并且不能保证放回的ID,没有被其他线程使用。
	* 所以用户要自己保证还在使用的ID不会被放回去。以免出现ID重复现象。
	* \param id 由get得到的ID.
	*/
	void put(T id)
	{
		mutex.lock();
		if (id<maxID && id>=minID)
		{
			bool hasID=false;
			typename std::list<T/*,__pool_alloc<T> */>::iterator iter = ids.begin();
			for(;iter != ids.end() ; iter ++)
			{
				if (*iter == id)
				{
					hasID=true;
					break;
				}
			}
			/*
			for(int i=0,n=ids.size() ;i<n;i++)
			{
			if (ids[i]==id)
			{
			hasID=true;
			break;
			}
			}
			// */
			if (!hasID) ids.push_front(id);
			//if (!hasID) ids.insert(ids.begin(),id);
			//if (!hasID) ids.push_back(id);
		}
		mutex.unlock();
	}
};

typedef zUniqueID<uint32_t> zUniqueuint32_tID;

/**
* \brief 配置文件解析器声明
*/
/**
* \brief zXMLParser定义
* 
* 主要提供了节点的浏览,和其属性的得到.
*/
class zXMLParser
{
public:
	zXMLParser();
	~zXMLParser();

	bool initFile(const std::string &xmlFile);
	bool initFile(const char *xmlFile);
	bool initStr(const std::string &xmlStr);
	bool initStr(const char *xmlStr);
	bool init();
	void final();
	std::string & dump(std::string & s,bool format=false);
	std::string & dump(xmlNodePtr dumpNode,std::string & s,bool head=true);
	xmlNodePtr getRootNode(const char *rootName);
	xmlNodePtr getChildNode(const xmlNodePtr parent,const char *childName);
	xmlNodePtr getNextNode(const xmlNodePtr node,const char *nextName);
	uint32_t getChildNodeNum(const xmlNodePtr parent,const char *childName);

	xmlNodePtr newRootNode(const char *rootName);
	xmlNodePtr newChildNode(const xmlNodePtr parent,const char *childName,const char *content);
	bool newNodeProp(const xmlNodePtr node,const char *propName,const char *prop);

	bool getNodePropNum(const xmlNodePtr node,const char *propName,void *prop,int propSize);
	bool getNodePropStr(const xmlNodePtr node,const char *propName,void *prop,int propSize);
	bool getNodePropStr(const xmlNodePtr node,const char *propName,std::string &prop);
	bool getNodeContentNum(const xmlNodePtr node,void *content,int contentSize);
	bool getNodeContentStr(const xmlNodePtr node,void *content,int contentSize);
	bool getNodeContentStr(const xmlNodePtr node,std::string &content);
	bool getNodeContentStr(const xmlNodePtr node,std::string &content,bool head );
private:
	BYTE *charConv(BYTE *in,const char *fromEncoding,const char *toEncoding);
	xmlDocPtr doc;
};

/**
* \brief 配置文件解析器
*
* 此类必须继承使用。本类实现了全局参数的解析标记为\<global\>\</global\>
* 并把解析的参数保存在一个全局的参数容器global中。
*
* 如果用户有自己的配置,用户应该实现自己的参数解析。
*
*/
class zConfile
{
protected:
	/**
	* \brief xml解析器
	*/
	zXMLParser parser;
	/**
	* \brief 配置文件名称
	*
	*/
	std::string confile;

	bool globalParse(const xmlNodePtr node);
	bool parseNormal(const xmlNodePtr node);
	bool parseSuperServer(const xmlNodePtr node);
	virtual bool parseYour(const xmlNodePtr node)=0;

public:
	zConfile(const char *confile="config.xml");
	virtual ~zConfile();
	bool parse(const char *name);
};

/**
* \brief entry管理器定义文件
*/
/**
* \brief Entry基类
*/

#pragma pack(1)
struct zEntryC
{
	/**
	* \brief entry的数据ID，不同类型的Entry可能会重复,此时不能实现从ID查找entry
	*/
	uint32_t id;
	/**
	* \brief entry的临时id,建议在实现EntryManager时，保证分配唯一
	*/
	uint32_t tempid;
	/**
	* \brief entry的名字，不同类型的Entry可能会重复,此时不能实现从名字查找entry
	*/
	char name[MAX_NAMESIZE+1];
	zEntryC()
	{
		id=0;
		tempid=0;
		bzero(name,sizeof(name));
	};
};

/**
* \brief 回调函数类模板
*/
template <typename T,typename RTValue = bool>
struct zEntryCallback
{
	virtual RTValue exec(T *e)=0;
	virtual ~zEntryCallback(){};
};

struct zEntry:public zEntryC,private boost::noncopyable
{
	virtual ~zEntry(){};
	zEntry():zEntryC()
	{
	};
};
#pragma pack()

/**
* \brief key值等值比较,目前支持 (uint32_t,char *)，两种类型
*/
template <class keyT>
struct my_key_equal : public std::binary_function<keyT,keyT,bool>
{
	inline bool operator()(const keyT s1,const keyT s2) const;
};

/**
* \brief 模板偏特化
* 对字符串进行比较
*/
template<>
inline bool my_key_equal<const char *>::operator()(const char * s1,const char * s2) const
{
	return strcmp(s1,s2) == 0;
}

/**
* \brief 模板偏特化
* 对整数进行比较
*/
template<>
inline bool my_key_equal<uint32_t>::operator()(const uint32_t s1,const uint32_t s2) const
{
	return s1  == s2;
}

/**
* \brief 有限桶Hash管理模板,非线程安全
*
* 目前支持两种key类型(uint32_t,char *),value类型不作限制,但此类型要可copy的。
* \param keyT key类型(uint32_t,char *)
* \param valueT value类型
*/
template <class keyT,class valueT>
class LimitHash:private boost::noncopyable
{
protected:

	/**
	* \brief hash_map容器
	*/
	//typedef hash_map<keyT,valueT,hash<keyT>,my_key_equal<keyT> > hashmap;
	typedef hash_map<keyT,valueT> hashmap;
	typedef typename hashmap::iterator iter;
	typedef typename hashmap::const_iterator const_iter;
	hashmap ets;

	/**
	* \brief 插入数据，如果原来存在相同key值的数据，原来数据将会被替换
	* \param key key值
	* \param value 要插入的数据
	* \return 成功返回true，否则返回false
	*/
	inline bool insert(const keyT &key,valueT &value)
	{
		ets[key]=value;
		return true;
	}

	/**
	* \brief 根据key值查找并得到数据
	* \param key 要寻找的key值
	* \param value 返回结果将放入此处,未找到将不会改变此值
	* \return 查找到返回true，未找到返回false
	*/
	inline bool find(const keyT &key,valueT &value) const
	{
		const_iter it = ets.find(key);
		if (it != ets.end())
		{
			value = it->second;
			return true;
		}
		else
			return false;
	}

	/**
	* \brief 查找并得到一个数据
	* \param value 返回结果将放入此处,未找到将不会改变此值
	* \return 查找到返回true，未找到返回false
	*/
	inline bool findOne(valueT &value) const
	{
		if (!ets.empty())
		{
			value=ets.begin()->second;
			return true;
		}
		return false;
	}

	/**
	* \brief 构造函数
	*
	*/
	LimitHash()
	{
	}

	/**
	* \brief 析构函数,清除所有数据
	*/
	~LimitHash()
	{
		clear();
	}

	/**
	* \brief 移除数据
	* \param key 要移除的key值
	*/
	inline void remove(const keyT &key)
	{
		ets.erase(key);
	}

	/**
	* \brief 清除所有数据
	*/
	inline void clear()
	{
		ets.clear();
	}

	/**
	* \brief 统计数据个数
	*/
	inline uint32_t size() const
	{
		return ets.size();
	}

	/**
	* \brief 判断容器是否为空
	*/
	inline bool empty() const
	{
		return ets.empty();
	}
};

/**
* \brief 有限桶MultiHash管理模板,非线程安全
*
* 目前支持两种key类型(uint32_t,char *),value类型不作限制,但此类型要可copy的。
* \param keyT key类型(uint32_t,char *)
* \param valueT value类型
*/
template <class keyT,class valueT>
class MultiHash:private boost::noncopyable
{
protected:

	/**
	* \brief hash_multimap容器
	*/
	//typedef hash_multimap<keyT,valueT,hash<keyT>,my_key_equal<keyT> > hashmap;
	typedef hash_multimap<keyT,valueT> hashmap;
	typedef typename hashmap::iterator iter;
	typedef typename hashmap::const_iterator const_iter;
	hashmap ets;

	/**
	* \brief 插入数据，如果原来存在相同key值的数据，原来数据将会被替换
	* \param key key值
	* \param value 要插入的数据
	* \return 成功返回true，否则返回false
	*/
	inline bool insert(const keyT &key,valueT &value)
	{
		//if(ets.find(key) == ets.end())
		ets.insert(std::pair<keyT,valueT>(key,value));
		return true;
	}

	/**
	* \brief 构造函数
	*
	*/
	MultiHash()
	{
	}

	/**
	* \brief 析构函数,清除所有数据
	*/
	~MultiHash()
	{
		clear();
	}

	/**
	* \brief 清除所有数据
	*/
	inline void clear()
	{
		ets.clear();
	}

	/**
	* \brief 统计数据个数
	*/
	inline uint32_t size() const
	{
		return ets.size();
	}

	/**
	* \brief 判断容器是否为空
	*/
	inline bool empty() const
	{
		return ets.empty();
	}
};

/**
* \brief Entry以临时ID为key值的指针容器，需要继承使用
*/
class zEntryTempID:public LimitHash<uint32_t,zEntry *>
{
protected:

	zEntryTempID() {}
	virtual ~zEntryTempID() {}

	/**
	* \brief 将Entry加入容器中,tempid重复添加失败
	* \param e 要加入的Entry
	* \return 成功返回true,否则返回false
	*/
	inline bool push(zEntry * e)
	{
		if (e!=NULL && getUniqeID(e->tempid))
		{
			zEntry *temp;
			if (!find(e->tempid,temp))
			{
				if (insert(e->tempid,e))
					return true;
			}
			putUniqeID(e->tempid);
		}
		return false;
	}

	/**
	* \brief 移除Entry
	* \param e 要移除的Entry
	*/
	inline void remove(zEntry * e)
	{
		if (e!=NULL)
		{
			putUniqeID(e->tempid);
			LimitHash<uint32_t,zEntry *>::remove(e->tempid);
		}
	}

	/**
	* \brief 通过临时ID得到Entry
	* \param tempid 要得到Entry的临时ID
	* \return 返回Entry指针,未找到返回NULL
	*/
	inline zEntry * getEntryByTempID(const uint32_t tempid) const
	{
		zEntry *ret=NULL;
		LimitHash<uint32_t,zEntry *>::find(tempid,ret);
		return ret;
	}

	/**
	* \brief 得到一个临时ID
	* \param tempid 存放要得到的临时ID
	* \return 得到返回true,否则返回false
	*/
	virtual bool getUniqeID(uint32_t &tempid) =0;
	/**
	* \brief 放回一个临时ID
	* \param tempid 要放回的临时ID
	*/
	virtual void putUniqeID(const uint32_t &tempid) =0;
};

/**
* \brief Entry以ID为key值的指针容器，需要继承使用
*/
class zEntryID:public LimitHash<uint32_t,zEntry *>
{
protected:
	/**
	* \brief 将Entry加入容器中
	* \param e 要加入的Entry
	* \return 成功返回true,否则返回false
	*/
	inline bool push(zEntry * &e)
	{
		zEntry *temp;
		if (!find(e->id,temp))
			return insert(e->id,e);
		else
			return false;
	}

	/**
	* \brief 移除Entry
	* \param e 要移除的Entry
	*/
	inline void remove(zEntry * e)
	{
		if (e!=NULL)
		{
			LimitHash<uint32_t,zEntry *>::remove(e->id);
		}
	}

	/**
	* \brief 通过ID得到Entry
	* \param id 要得到Entry的ID
	* \return 返回Entry指针,未找到返回NULL
	*/
	inline zEntry * getEntryByID(const uint32_t id) const
	{
		zEntry *ret=NULL;
		LimitHash<uint32_t,zEntry *>::find(id,ret);
		return ret;
	}
};

/**
* \brief Entry以名字为key值的指针容器，需要继承使用
*/
class zEntryName:public LimitHash<std::string,zEntry *>
{
protected:
	/**
	* \brief 将Entry加入容器中,如果容器中有相同key值的添加失败
	* \param e 要加入的Entry
	* \return 成功返回true,否则返回false
	*/
	inline bool push(zEntry * &e)
	{
		zEntry *temp;
		if (!find(std::string(e->name),temp))
			return insert(std::string(e->name),e);
		else
			return false;
	}

	/**
	* \brief 移除Entry
	* \param e 要移除的Entry
	*/
	inline void remove(zEntry * e)
	{
		if (e!=NULL)
		{
			LimitHash<std::string,zEntry *>::remove(std::string(e->name));
		}
	}

	/**
	* \brief 通过名字得到Entry
	* \param name 要得到Entry的名字
	* \return 返回Entry指针,未找到返回NULL
	*/
	inline zEntry * getEntryByName( const char * name) const
	{
		zEntry *ret=NULL;
		LimitHash<std::string,zEntry *>::find(std::string(name),ret);
		return ret;
	}

	/**
	* \brief 通过名字得到Entry
	* \param name 要得到Entry的名字
	* \return 返回Entry指针,未找到返回NULL
	*/
	inline zEntry * getEntryByName(const std::string  &name) const
	{
		return getEntryByName(name.c_str());
	}
};

/**
* \brief Entry以名字为key值的指针容器，需要继承使用
*/
class zMultiEntryName:public MultiHash</*const char **/std::string,zEntry *>
{
protected:
	/**
	* \brief 将Entry加入容器中,如果容器中有相同key值的添加失败
	* \param e 要加入的Entry
	* \return 成功返回true,否则返回false
	*/
	inline bool push(zEntry * &e)
	{
		return insert(std::string(e->name),e);
	}

	/**
	* \brief 将Entry从容器中移除
	* \param e 需要移除的Entry
	*/
	inline void remove(zEntry * &e)
	{
		pair<iter,iter> its = ets.equal_range(std::string(e->name));
		for(iter it = its.first; it != its.second; it++)
		{
			if (it->second == e)
			{
				ets.erase(it);
				return;
			}
		}
	}

	/**
	* \brief 根据key值查找并得到数据
	* \param name 要寻找的name值
	* \param e 返回结果将放入此处,未找到将不会改变此值
	* \param r 如果有多项匹配，是否随机选择
	* \return 查找到返回true，未找到返回false
	*/
	inline bool find(const char * &name,zEntry * &e,const bool r=false) const
	{
		int rd = ets.count(std::string(name));
		if (rd > 0)
		{
			int mrd = 0,j = 0;
			if (r)
				randBetween(0,rd - 1);
			pair<const_iter,const_iter> its = ets.equal_range(std::string(name));
			for(const_iter it = its.first; it != its.second && j < rd; it++,j++)
			{
				if (mrd == j)
				{
					e = it->second;
					return true;
				}
			}
		}
		return false;
	}

};

template<int i>
class zEntryNone
{
protected:
	inline bool push(zEntry * &e) { return true; }
	inline void remove(zEntry * &e) { }
	inline void clear(){}
};

/**
* \brief Entry处理接口,由<code>zEntryManager::execEveryEntry</code>使用
*/
template <class YourEntry>
struct execEntry
{
	virtual bool exec(YourEntry *entry) =0;
	virtual ~execEntry(){}
};

/**
* \brief Entry删除条件接口,由<code>zEntryManager::removeEntry_if</code>使用
*/
template <class YourEntry>
struct removeEntry_Pred
{
	/**
	* \brief 被删除的entry存储在这里
	*/
	std::vector<YourEntry *> removed;
	/**
	* \brief 测试是否要删除的entry,需要实现
	* \param 要被测试的entry
	*/
	virtual bool isIt(YourEntry *entry) =0;
	/**
	* \brief 析构函数
	*/
	virtual ~removeEntry_Pred(){}
};

/**
* \brief Entry管理器接口,用户应该根据不同使用情况继承它
*/

template<typename e1,typename e2=zEntryNone<1>,typename e3=zEntryNone<2> >
class zEntryManager:protected e1,protected e2,protected e3
{
protected:

	//unsigned long count;

	/**
	* \brief 添加Entry,对于重复索引的Entry添加失败
	* \param e 被添加的 Entry指针
	* \return 成功返回true，否则返回false 
	*/
	inline bool addEntry(zEntry * e)
	{

		if(NULL == e)
			return false;
		//++count;
		// unsigned long t = count;

		//if( 765 == count)
		//{
		//Xlogger->error("%u\n",count);
		//fprintf(stderr,"%u\n",count);
		//  }
		if (e1::push(e))
		{ 
			//zEntry *ee = e1::getEntryByName(e->name); 
			if (e2::push(e))
			{ 

				if (e3::push(e))
					return true;
				else
				{
					e2::remove(e);
					e1::remove(e);
				}
			}
			else
				e1::remove(e);
		}
		return false;
	}

	/**
	* \brief 删除Entry
	* \param e 被删除的Entry指针
	*/
	inline void removeEntry(zEntry * e)
	{
		e1::remove(e);
		e2::remove(e);
		e3::remove(e);
	}


	zEntryManager() { }
	/**
	* \brief 虚析构函数
	*/
	~zEntryManager() { };

	/**
	* \brief 统计管理器中Entry的个数
	* \return 返回Entry个数
	*/
	inline int size() const
	{
		return e1::size();
	}

	/**
	* \brief 判断容器是否为空
	*/
	inline bool empty() const
	{
		return e1::empty();
	}

	/**
	* \brief 清除所有Entry
	*/
	inline void clear()
	{
		e1::clear();
		e2::clear();
		e3::clear();
	}

	/**
	* \brief 对每个Entry进行处理
	* 当处理某个Entry返回false时立即打断处理返回
	* \param eee 处理接口
	* \return 如果全部执行完毕返回true,否则返回false
	*/
	template <class YourEntry>
	inline bool execEveryEntry(execEntry<YourEntry> &eee)
	{
		typedef typename e1::iter my_iter;
		for(my_iter it=e1::ets.begin();it!=e1::ets.end();it++)
		{
			if (!eee.exec((YourEntry *)it->second))
				return false;
		}
		return true;
	}

	/**
	* \brief 删除满足条件的Entry
	* \param pred 测试条件接口
	*/
	template <class YourEntry>
	inline void removeEntry_if (removeEntry_Pred<YourEntry> &pred)
	{
		typedef typename e1::iter my_iter;
		my_iter it=e1::ets.begin();
		while(it!=e1::ets.end())
		{
			if (pred.isIt((YourEntry *)it->second))
			{
				pred.removed.push_back((YourEntry *)it->second);
			}
			it++;
		}

		for(uint32_t i=0;i<pred.removed.size();i++)
		{
			removeEntry(pred.removed[i]);
		}
	}
};

/**
* \brief 场景上物件定义
*/
#pragma pack(1)
/**
* \brief 用于偏移计算的坐标值
*/
struct zAdjust
{
	int x;    /**< 横坐标*/
	int y;    /**< 纵坐标*/
};
/**
* \brief 场景坐标
*/
struct zPos
{
	uint32_t x;    /**< 横坐标*/
	uint32_t y;    /**< 纵坐标*/
	/**
	* \brief 构造函数
	*
	*/
	zPos()
	{
		x = 0;
		y = 0;
	}
	/**
	* \brief 构造函数
	*
	*/
	zPos(const uint32_t x,const uint32_t y)
	{
		this->x = x;
		this->y = y;
	}
	/**
	* \brief 拷贝构造函数
	*
	*/
	zPos(const zPos &pos)
	{
		x = pos.x;
		y = pos.y;
	}
	/**
	* \brief 赋值操作符号
	*
	*/
	zPos & operator= (const zPos &pos)
	{
		x = pos.x;
		y = pos.y;
		return *this;
	}
	/**
	* \brief 重载+运算符号
	*
	*/
	const zPos & operator+ (const zPos &pos)
	{
		x += pos.x;
		y += pos.y;
		return *this;
	}
	/**
	* \brief 重载+运算符号
	* 对坐标进行修正
	*/
	const zPos & operator+ (const zAdjust &adjust)
	{
		x += adjust.x;
		y += adjust.y;
		return *this;
	}
	/**
	* \brief 重载+=运算符号
	*
	*/
	const zPos & operator+= (const zPos &pos)
	{
		x += pos.x;
		y += pos.y;
		return *this;
	}
	/**
	* \brief 重载+=运算符号
	* 对坐标进行修正
	*/
	const zPos & operator+= (const zAdjust &adjust)
	{
		x += adjust.x;
		y += adjust.y;
		return *this;
	}
	/**
	* \brief 重载-运算符号
	*
	*/
	const zPos & operator- (const zPos &pos)
	{
		x -= pos.x;
		y -= pos.y;
		return *this;
	}
	/**
	* \brief 重载-运算符号
	* 对坐标进行修正
	*/
	const zPos & operator- (const zAdjust &adjust)
	{
		x -= adjust.x;
		y -= adjust.y;
		return *this;
	}
	/**
	* \brief 重载-=运算符号
	*
	*/
	const zPos & operator-= (const zPos &pos)
	{
		x -= pos.x;
		y -= pos.y;
		return *this;
	}
	/**
	* \brief 重载-=运算符号
	* 对坐标进行修正
	*/
	const zPos & operator-= (const zAdjust &adjust)
	{
		x -= adjust.x;
		y -= adjust.y;
		return *this;
	}
	/**
	* \brief 重载==逻辑运算符号
	*
	*/
	const bool operator== (const zPos &pos) const
	{
		return (x == pos.x && y == pos.y);
	}
	/**
	* \brief 重载>逻辑运算符号
	*
	*/
	const bool operator> (const zPos &pos) const
	{
		return (x > pos.x && y > pos.y);
	}
	/**
	* \brief 重载>=逻辑运算符号
	*
	*/
	const bool operator>= (const zPos &pos) const
	{
		return (x >= pos.x && y >= pos.y);
	}
	/**
	* \brief 重载<逻辑运算符号
	*
	*/
	const bool operator< (const zPos &pos) const
	{
		return (x < pos.x && y < pos.y);
	}
	/**
	* \brief 重载<=逻辑运算符号
	*
	*/
	const bool operator<= (const zPos &pos) const
	{
		return (x <= pos.x && y <= pos.y);
	}
	/**
	* \brief 以自身为中心点，获取到另外一个坐标的方向
	* \param pos 另外一个坐标点
	* \return 方向
	*/
	const int getDirect(const zPos &pos) const
	{
		using namespace Cmd;
		if (x == pos.x && y > pos.y)
		{
			return _DIR_UP;
		}
		else if (x < pos.x && y > pos.y)
		{
			return _DIR_UPRIGHT;
		}
		else if (x < pos.x && y == pos.y)
		{
			return _DIR_RIGHT;
		}
		else if (x < pos.x && y < pos.y)
		{
			return _DIR_RIGHTDOWN;
		}
		else if (x == pos.x && y < pos.y)
		{
			return _DIR_DOWN;
		}
		else if (x > pos.x && y < pos.y)
		{
			return _DIR_DOWNLEFT;
		}
		else if (x > pos.x && y == pos.y)
		{
			return _DIR_LEFT;
		}
		else if (x > pos.x && y > pos.y)
		{
			return _DIR_LEFTUP;
		}

		return _DIR_WRONG;
	}
};
/**
* \brief 半屏坐标
*
*/
const zPos zPosHalfScreen(SCREEN_WIDTH / 2,SCREEN_HEIGHT / 2);
#pragma pack()

/**
* \brief 场景屏坐标
*/
typedef uint32_t zPosI;

/**
* \brief 存放屏编号的向量
*
*/
typedef std::vector<zPosI> zPosIVector;
typedef std::vector<zPos> zPosVector;

typedef std::list<uint16_t> SceneEntryStateList;

class zSceneEntryIndex;
/**
* \brief 场景上物件，比如人物,NPC,建筑，地上物品等
*
* 作用有两个
*
* 1.建立屏索引
* 2.定义阻挡
*/
struct zSceneEntry:public zEntry
{
	friend class zSceneEntryIndex;
public:

	unsigned short dupIndex;
	/**
	* \brief 物件类型
	*/
	enum SceneEntryType
	{
		SceneEntry_Player,/**< 玩家角色*/
		SceneEntry_NPC,  /**< NPC*/
		SceneEntry_Build,/**< 建筑*/
		SceneEntry_Object,/**< 地上物品*/
		SceneEntry_Pet,  /**< 宠物*/
		SceneEntry_MAX
	};
	/**
	* \brief 物件状态
	*
	*/
	enum SceneEntryState
	{
		SceneEntry_Normal,  /**< 普通状态 */
		SceneEntry_Death,  /**< 死亡状态 */
		SceneEntry_Hide      /**< 隐藏状态 */
	};
	/**
	* \brief 坐标转化
	* \param screenWH 地图宽和高
	* \param pos 源坐标
	* \param posi 目的坐标
	*/
	static void zPos2zPosI(const zPos &screenWH,const zPos &pos,zPosI &posi)
	{
		posi=((screenWH.x+SCREEN_WIDTH-1)/SCREEN_WIDTH) * (pos.y/SCREEN_HEIGHT) + (pos.x/SCREEN_WIDTH);
	}
protected:
	/**
	* \brief 构造函数
	*/
	zSceneEntry(SceneEntryType type,const SceneEntryState state = SceneEntry_Normal):sceneentrytype(type),sceneentrystate(state)
	{
		bzero(byState,sizeof(byState));
		dir = Cmd::_DIR_DOWN;
		inserted=false;
		dupIndex = 0;
	}

	/**
	* \brief 坐标
	*/
	zPos pos;
	/**
	* \brief 屏坐标
	*/
	zPosI posi;
	/**
	* \brief 方向
	*
	*/
	BYTE dir;

	zPos lastPos1;
	zPos lastPos2;

private:
	/**
	* \brief 物件类型
	*/
	const SceneEntryType sceneentrytype;
	/**
	* \brief 物件状态
	*
	*/
	SceneEntryState sceneentrystate;
	/**
	* \brief 物件是否在场景上
	*/
	bool inserted;

	/**
	* \brief 设置物件坐标
	* \param screenWH 场景的宽高
	* \param newPos 物件的新坐标
	* \return 坐标超出场景宽高返回false,否则返回true
	*/
	bool setPos(const zPos &screenWH,const zPos &newPos)
	{
		if (screenWH.x>newPos.x && screenWH.y>newPos.y)
		{
			pos=newPos;
			zPos2zPosI(screenWH,newPos,posi);
			return true;
		}
		else
			return false;
	}

private:
	/**
	* \brief 物件状态，与魔法等相关的
	* 这种状态是外观可以表现的，带上某种状态客户端就可以以一种方式来表现
	* 详细的状态参见Command.h中
	*/
	BYTE byState[(Cmd::MAX_STATE + 7) / 8];
protected:
	SceneEntryStateList stateList;
public:
	/**
	* \brief 填充物件状态
	* \param state 填充位置
	* \return 状态个数
	*/
	inline BYTE full_UState(uint16_t *state)
	{
		BYTE ret = stateList.size();
		SceneEntryStateList::iterator iter = stateList.begin();
		for(int i=0 ; i < ret ; i ++)
		{
			state[i] = *iter;
			iter ++;
		}
		return ret;
	}
	/**
	* \brief 填充物件所有状态
	* \param state 填充位置
	*/
	inline void full_all_UState(void *state,uint32_t maxSize )
	{
		bcopy(byState,state,sizeof(byState),maxSize);
	}

	/**
	* \brief 得到物件坐标
	* \return 物件坐标
	*/
	inline const zPos &getPos() const
	{
		return pos;
	}

	/**
	* \brief 得到物件刚才的坐标
	* \return 物件坐标
	*/
	inline const zPos &getOldPos1() const
	{
		return lastPos1;
	}

	/**
	* \brief 得到物件刚才的坐标
	* \return 物件坐标
	*/
	inline const zPos &getOldPos2() const
	{
		return lastPos2;
	}

	/**
	* \brief 得到物件屏坐标
	* \return 物件屏坐标
	*/
	inline const zPosI &getPosI() const
	{ 
		return posi;
	}
	/**
	* \brief 测试物件是否在场景中
	* \return 物件在场景中返回true,否则返回false
	*/
	inline bool hasInScene() const
	{ 
		return inserted;
	}

	/**
	* \brief 得到物件类型
	* \return 物件类型
	*/
	inline const SceneEntryType & getType() const
	{
		return sceneentrytype;
	}

	/**
	* \brief 获取物件状态
	* \return 状态
	*/
	inline const SceneEntryState & getState() const
	{
		return sceneentrystate;
	}

	/**
	* \brief 设置物件状态
	* \param state 需要设置的状态
	*/
	void setState(const SceneEntryState & state)
	{
		sceneentrystate = state;
	}

	/**
	* \brief 获取方向
	* \return 方向
	*/
	inline const BYTE getDir() const
	{
		return dir % 8;
	}

	/**
	* \brief 设置方向
	* \param dir 方向
	*/
	void setDir(const BYTE dir)
	{
		this->dir = dir % 8;
	}

	/**
	* \brief 检查某种状态是否设置
	* \param state 待检查的状态
	* \return 这种状态是否已经设置
	*/
	inline bool issetUState(const int state) const
	{
		return Cmd::isset_state(byState,state);
	}

	/**
	* \brief 设置某种状态
	* \param state 待设置的状态
	* \return 如果已经设置该状态返回false,否则返回true
	*/
	inline bool setUState(const int state)
	{
		if (!issetUState(state))
		{
			stateList.push_back(state);
			Cmd::set_state(byState,state);
			return true;
		}
		return false;
	}

	/**
	* \brief 清除某种状态
	* \param state 待清除的状态
	* \return 如果已经设置该状态返回true,否则返回false
	*/
	inline bool clearUState(const int state)
	{
		Cmd::clear_state(byState,state);
		SceneEntryStateList::iterator iter = stateList.begin();
		for( ; iter != stateList.end() ; ++iter)
		{
			if (*iter == state)
			{
				stateList.erase(iter);
				return true;
			}
		}
		return false;
	}
};

/**
* \brief 场景管理器定义
*/
enum enumSceneRunningState{
	SCENE_RUNNINGSTATE_NORMAL,//正常运行
	SCENE_RUNNINGSTATE_UNLOAD,//正在卸载
	SCENE_RUNNINGSTATE_REMOVE,//正在卸载
};
/**
* \brief 场景基本信息定义
*/
struct zScene:public zEntry
{
private:
	uint32_t running_state;
public:
	zScene():running_state(SCENE_RUNNINGSTATE_NORMAL){}
	uint32_t getRunningState() const
	{
		return running_state;
	}
	uint32_t setRunningState(uint32_t set)
	{
		running_state = set;
		return running_state;
	}
};

/**
* \brief 场景管理器
*
* 以名字和临时ID索引,没有ID索引，因为场景可能重复
*/
class zSceneManager:public zEntryManager<zEntryID,zEntryTempID,zEntryName>
{


protected:
	/**
	* \brief 访问管理器的互斥锁
	*/
	zRWLock rwlock;

	zScene * getSceneByName( const char * name)
	{
		rwlock.rdlock();
		zScene *ret =(zScene *)getEntryByName(name);
		rwlock.unlock();
		return ret;
	}



	zScene * getSceneByID(uint32_t id)
	{
		rwlock.rdlock();
		zScene *ret =(zScene *)getEntryByID(id);
		rwlock.unlock();
		return ret;
	}

	zScene * getSceneByTempID( uint32_t tempid)
	{
		rwlock.rdlock();
		zScene *ret =(zScene *)getEntryByTempID(tempid);
		rwlock.unlock();
		return ret;
	}

	template <class YourSceneEntry>
	bool execEveryScene(execEntry<YourSceneEntry> &exec)
	{
		rwlock.rdlock();
		bool ret=execEveryEntry<>(exec);
		rwlock.unlock();
		return ret;
	}

	/**
	* \brief 移出符合条件的角色
	* \param pred 条件断言
	*/
	template <class YourSceneEntry>
	void removeScene_if(removeEntry_Pred<YourSceneEntry> &pred)
	{
		rwlock.wrlock();
		removeEntry_if<>(pred);
		rwlock.unlock();
	}

public:
	/**
	* \brief 构造函数
	*/
	zSceneManager()
	{
	}

	/**
	* \brief 析构函数
	*/
	virtual ~zSceneManager()
	{
		clear();
	}

};

/**
* \brief 游戏基本数据管理器 声明
*/
#pragma pack(1)
//------------------------------------
// ObjectBase
//------------------------------------
struct ObjectBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}

	uint32_t  dwField0;    // 编号
	char  strField1[64];    // 名称
	uint32_t  dwField2;    // 最大数量
	uint32_t  dwField3;    // 类型
	uint32_t  dwField4;    // 职业限定
	uint32_t  dwField5;    // 需要等级
	uint32_t  dwField6;    // 道具等级
	char  strField7[256];    // 孔
	uint32_t  dwField8;    // 配合物品
	char  strField9[256];    // 药品作用
	uint32_t  dwField10;    // 最大生命值
	uint32_t  dwField11;    // 最大法术值
	uint32_t  dwField12;    // 最大体力值
	uint32_t  dwField13;    // 最小物攻
	uint32_t  dwField14;    // 最大物攻
	uint32_t  dwField15;    // 最小魔攻
	uint32_t  dwField16;    // 最大魔攻
	uint32_t  dwField17;    // 物防
	uint32_t  dwField18;    // 魔防
	uint32_t  dwField19;    // 伤害加成

	uint32_t  dwField20;    // 攻击速度
	uint32_t  dwField21;    // 移动速度
	uint32_t  dwField22;    // 命中率
	uint32_t  dwField23;    // 躲避率
	uint32_t  dwField24;    // 改造
	uint32_t  dwField25;    // 合成等级
	uint32_t  dwField26;    // 打造
	char  strField27[32];    // 需要技能
	char  strField28[1024];    // 需要原料
	uint32_t  dwField29;    // 装备位置
	uint32_t  dwField30;    // 耐久度
	uint32_t  dwField31;    // 价格
	uint32_t  dwField32;    // 颜色
	uint32_t  dwField33;    // 格子宽
	uint32_t  dwField34;    // 格子高
	uint32_t  dwField35;    // 金子
	uint32_t  dwField36;    // 合成单价
	uint32_t  dwField37;    // 重击
	uint32_t  dwField38;    // 神圣概率
	char  strField39[256];    // 神圣标识 

	//sky 新增属性
	uint32_t  dwField40;    // 力量
	uint32_t  dwField41;    // 智力
	uint32_t  dwField42;    // 敏捷
	uint32_t  dwField43;    // 精神
	uint32_t  dwField44;    // 耐力
	uint32_t  dwField45;    // 物理免伤
	uint32_t  dwField46;    // 魔法免伤
};//导出 ObjectBase 成功，共 940 条记录

/**
* \brief 物品基本表
*/
struct zObjectB:public zEntry
{
	uint32_t maxnum;        // 最大数量
	BYTE kind;          // 类型
	BYTE job;          // sky 职业限制
	uint16_t level;          // 道具等级
	std::vector<uint32_t> hole;  //孔

	uint16_t needobject;      // 配合物品
	struct leechdom_t {
		uint16_t id; //功能标识
		uint16_t effect; //效果
		uint16_t time; //时间
		leechdom_t(const std::string& _id="",const std::string& _effect="",const std::string& _time="") 
			: id(atoi(_id.c_str())),effect(atoi(_effect.c_str())),time(atoi(_time.c_str()))
		{ }
	} leechdom ;         // 药品作用

	uint16_t needlevel;        // 需要等级

	uint32_t maxhp;          // 最大生命值
	uint32_t maxmp;          // 最大法术值
	uint32_t maxsp;          // 最大体力值

	uint32_t pdamage;        // 最小攻击力
	uint32_t maxpdamage;      // 最大攻击力
	uint32_t mdamage;        // 最小法术攻击力
	uint32_t maxmdamage;      // 最大法术攻击力

	uint32_t pdefence;        // 物防
	uint32_t mdefence;        // 魔防

	uint16_t damagebonus;      //伤害加成

	uint16_t akspeed;        // 攻击速度
	uint16_t mvspeed;        // 移动速度
	uint16_t atrating;        // 命中率
	uint16_t akdodge;        // 躲避率

	uint32_t color;        // 颜色  

	//struct socket
	//{
	//  uint16_t odds;
	//  BYTE min;
	//  BYTE max;
	//  socket(const std::string& odds_,const std::string& number_)
	//  {
	// odds=atoi(odds_.c_str());
	// min=0;
	// max=0;
	//    std::string::size_type pos = 0;
	//    if  ( (pos = number_.find("-")) != std::string::npos )
	//    {
	//      
	//      min = atoi(number_.substr(0,pos).c_str());
	//      max = atoi(number_.substr(pos+strlen("-")).c_str());
	//      //if (odds) Xlogger->debug("odds:%d\tmin:%d\tmax:%d",odds,min,max);
	//    }
	//  }
	//} hole;            //孔

	BYTE recast;        // 改造

	BYTE recastlevel;       // 合成等级
	uint16_t recastcost;      // 合成单价


	uint16_t make;          // 打造
	struct skills 
	{
		uint16_t id;
		BYTE level;
		skills(const std::string& id_="0",const std::string& level_="0") : id(atoi(id_.c_str())),level(atoi(level_.c_str()))
		{ }
	};
	skills need_skill;      // 需要技能

	struct material
	{
		uint16_t gold;
		struct  stuff
		{
			uint16_t id;
			uint16_t number;
			BYTE level;
			stuff(const std::string& id_,const std::string& level_,const std::string& number_) : id(atoi(id_.c_str())),number(atoi(number_.c_str())),level(atoi(level_.c_str()))
			{ }  
		};
		std::vector<stuff> stuffs;
		typedef std::vector<stuff>::iterator stuffs_iterator;
	};
	material need_material;    // 需要原料

	BYTE setpos;        // 装备位置
	uint16_t durability;      // 耐久度
	uint32_t price;        // 价格

	BYTE width;          // 格子宽
	BYTE height;        // 格子高
	union
	{
		uint32_t cardpoint;      // 金子 (已经无用)
		uint32_t cointype;        // 货币类型
	};
	uint16_t bang;          //重击
	uint32_t holyrating;      //神圣概率
	std::vector<uint32_t> holys;     //神圣标识

	// sky 新增基本属性
	uint16_t str;				 //力量
	uint16_t inte;			 //智力
	uint16_t dex;				 //敏捷
	uint16_t spi;				 //精神
	uint16_t con;				 //耐力

	uint16_t atkhpp;  //魔法免伤
	uint16_t mtkhpp;  //魔法免伤

	int  nSuitData;

	void fill(ObjectBase &data)
	{
		nSuitData = -1;

		id = data.dwField0;
		strncpy(name,data.strField1,MAX_NAMESIZE);

		maxnum = data.dwField2;  
		kind = data.dwField3;  
		job = data.dwField4;  
		needlevel =  data.dwField5;  
		level =  data.dwField6;  

		init_identifier(hole,data.strField7);

		needobject = data.dwField8;  
		init_leechdom(data.strField9);

		maxhp = data.dwField10;  
		maxmp = data.dwField11;
		maxsp =  data.dwField12;

		pdamage = data.dwField13;
		maxpdamage = data.dwField14;
		mdamage = data.dwField15;
		maxmdamage = data.dwField16;
		pdefence = data.dwField17;
		mdefence = data.dwField18;
		damagebonus = data.dwField19;

		akspeed = data.dwField20;
		mvspeed = data.dwField21;
		atrating = data.dwField22;
		akdodge = data.dwField23;

		recast = data.dwField24;
		recastlevel = data.dwField25;

		make = data.dwField26;

		init_need_skills(data.strField27);
		init_need_material(data.strField28);

		setpos = data.dwField29;
		durability = data.dwField30;
		price =  data.dwField31;

		//sky  新游戏里已经不需要这个属性拉
		/*bluerating = data.dwField34;
		goldrating = data.dwField35;*/

		color = data.dwField32;
		width =  data.dwField33;
		height = data.dwField34;
		cardpoint = data.dwField35;
		recastcost = data.dwField36;
		bang = data.dwField37;

		holyrating = data.dwField38;
		init_identifier(holys,data.strField39);

		//sky 新增加属性
		str		= data.dwField40;	//力量
		inte	= data.dwField41;	//智力
		dex		= data.dwField42;	//敏捷
		spi		= data.dwField43;	//精神
		con		= data.dwField44;	//耐力
		atkhpp	= data.dwField45;  //魔法免伤
		mtkhpp	= data.dwField46;  //魔法免伤


	}

	zObjectB():zEntry()/*,hole("0","0-0")*/
	{
		bzero(this,sizeof(zObjectB));
	};

	void init_identifier(std::vector<uint32_t>& list,const std::string& info)
	{
		list.clear();
		getAllNum(info.c_str(),list);
	}

	void init_leechdom(const std::string& info)
	{
		leechdom_t* p = Parse3<leechdom_t>()(info,":");
		if (p) {
			leechdom = *p;
			SAFE_DELETE(p);
		}  
	}  

	/*void init_socket(const std::string& socket_info)
	{
	std::string::size_type pos = socket_info.find(':');
	if (pos != std::string::npos) {
	hole = socket(socket_info.substr(0,pos),socket_info.substr(pos+1));
	}

	}*/

	void init_need_skills(const std::string& skills_list)
	{  
		std::string::size_type pos = skills_list.find(':');
		if (pos != std::string::npos) {
			need_skill = skills(skills_list.substr(0,pos),skills_list.substr(pos+1));
		}
	}

	void init_need_material(const std::string& materials)
	{
		need_material.stuffs.clear();
		Split<Parse3> p;
		std::string::size_type pos = materials.find(':');
		if (pos != std::string::npos) {
			need_material.gold = atoi(materials.substr(0,pos).c_str());
			p(materials.substr(pos+1),need_material.stuffs,";","-");
		}
	}

};

//------------------------------------
// ColorObjectBase
//------------------------------------
struct ColorObjectBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}

	uint32_t  dwField0;    // 编号
	char  strField1[64];    // 名称
	char  strField2[32];    // 连接符
	char  strField3[128];    // 金色品质
	char  strField4[32];    // 力量
	char  strField5[32];    // 智力
	char  strField6[32];    // 敏捷
	char  strField7[32];    // 精神
	char  strField8[32];    // 体质
	char  strField9[32];    // 五行属性
	char  strField10[32];    // 最小物攻
	char  strField11[32];    // 最大物攻
	char  strField12[32];    // 最小魔攻
	char  strField13[32];    // 最大魔攻
	char  strField14[32];    // 物防
	char  strField15[32];    // 魔防
	char  strField16[32];    // 最大生命值
	char  strField17[32];    // 最大法术值
	char  strField18[32];    // 最大体力值
	char  strField19[32];    // 移动速度
	char  strField20[32];    // 生命值恢复
	char  strField21[32];    // 法术值恢复
	char  strField22[32];    // 体力值恢复
	char  strField23[32];    // 攻击速度
	char  strField24[32];    // 增加物理攻击力
	char  strField25[32];    // 增加物理防御力
	char  strField26[32];    // 增加魔法攻击力
	char  strField27[32];    // 增加魔法防御力
	char  strField28[32];    // 命中率
	char  strField29[32];    // 闪避率
	char  strField30[32];    // 抗毒增加
	char  strField31[32];    // 抗麻痹增加
	char  strField32[32];    // 抗眩晕增加
	char  strField33[32];    // 抗噬魔增加
	char  strField34[32];    // 抗噬力增加
	char  strField35[32];    // 抗混乱增加
	char  strField36[32];    // 抗冰冻增加
	char  strField37[32];    // 抗石化增加
	char  strField38[32];    // 抗失明增加
	char  strField39[32];    // 抗定身增加
	char  strField40[32];    // 抗减速增加
	char  strField41[32];    // 抗诱惑增加
	char  strField42[32];    // 恢复耐久度
	char  strField43[32];    // 重击
	uint32_t  dwField44;    // 神圣装备几率
	char  strField45[1024];    // 技能加成
	char  strField46[32];    // 全系技能加成
};

//一个范围值得描述
struct rangeValue
{
	uint16_t min;
	uint16_t max;
};

struct luckRangeValue
{
	uint16_t per;  //是否产生本属性的几率
	rangeValue data;  //产生属性值的随机范围
	uint16_t sleightValue;  //根据熟练度产生的加权值

	operator int()
	{
		return per;
	}
};

static void fillRangeValue(const char *str,rangeValue &data)
{
	std::vector<uint32_t> num;
	int i =getAllNum(str,num);
	if (i!=2)
	{
		data.min=0;
		data.max=0;
	}
	else
	{
		data.min=num[0];
		data.max=num[1];
	}
}

static void fillLuckRangeValue(char *str,luckRangeValue &data)
{
	std::vector<uint32_t> num;
	int i =getAllNum(str,num);
	if (i<3)
	{
		if (i!=1)
		{
			Xlogger->debug("fillLuckRangeValue %s",str);
		}
		data.per=0;
		data.data.min=0;
		data.data.max=0;
		data.sleightValue=0;
	}
	else
	{
		data.per=num[0];
		data.data.min=num[1];
		data.data.max=num[2];
		if (i==4)
			data.sleightValue=num[3];
		else
			data.sleightValue=0;
	}
}

struct skillbonus {
	uint16_t odds; //几率
	uint16_t id; //技能 id
	uint16_t level; // 技能等级
	skillbonus(std::string _odds="0",std::string _id="0",std::string _level="0") : odds(atoi(_odds.c_str())),id(atoi(_id.c_str())),level(atoi(_level.c_str()))
	{ }
}; 

template <class Base,uint16_t tt>
struct zColorObjectB:public zEntry
{
	//std::string prefix;      // 名称
	char prefix[MAX_NAMESIZE];      // 名称
	//std::string joint;      // 连接符
	char joint[MAX_NAMESIZE];      // 连接符
	std::vector<uint16_t> golds;  // 金色品质

	union {
		luckRangeValue _p1[5];
		struct {
			luckRangeValue str;      // 力量
			luckRangeValue inte;    // 智力
			luckRangeValue dex;      // 敏捷
			luckRangeValue spi;      // 精神
			luckRangeValue con;      // 体质
		};  
	};
	luckRangeValue five;    // 五行属性

	rangeValue pdamage;      // 最小物攻
	rangeValue maxpdamage;    // 最大物攻
	rangeValue mdamage;      // 最小魔攻
	rangeValue maxmdamage;    // 最大魔攻
	rangeValue pdefence;      // 物防
	rangeValue mdefence;      // 魔防

	luckRangeValue maxhp;    // 最大生命值
	luckRangeValue maxmp;    // 最大法术值
	luckRangeValue maxsp;    // 最大体力值

	luckRangeValue mvspeed;    // 移动速度
	luckRangeValue hpr;      // 生命值恢复
	luckRangeValue mpr;      // 法术值恢复
	luckRangeValue spr;      // 体力值恢复
	luckRangeValue akspeed;    // 攻击速度

	union {
		luckRangeValue _p2[18];
		struct {
			luckRangeValue pdam;    // 增加物理攻击力
			luckRangeValue pdef;    // 增加物理防御力
			luckRangeValue mdam;    // 增加魔法攻击力
			luckRangeValue mdef;    // 增加魔法防御力

			luckRangeValue poisondef;  // 抗毒增加
			luckRangeValue lulldef;    // 抗麻痹增加
			luckRangeValue reeldef;    // 抗眩晕增加
			luckRangeValue evildef;    // 抗噬魔增加
			luckRangeValue bitedef;    // 抗噬力增加
			luckRangeValue chaosdef;  // 抗混乱增加
			luckRangeValue colddef;    // 抗冰冻增加
			luckRangeValue petrifydef;    // 抗石化增加
			luckRangeValue blinddef;    // 抗失明增加
			luckRangeValue stabledef;    // 抗定身增加
			luckRangeValue slowdef;    // 抗减速增加
			luckRangeValue luredef;    // 抗诱惑增加

			luckRangeValue atrating;    // 命中率
			luckRangeValue akdodge;    // 闪避率

		};
	};  

	luckRangeValue resumedur;    // 恢复耐久度
	luckRangeValue bang;    // 重击
	uint16_t holyrating;  //神圣装备几率

	std::vector<skillbonus> skill;  // 技能加成
	skillbonus skills;        // 全系技能加成

	uint16_t type;

public:
	void fill(Base &data)
	{
		id = data.dwField0;
		strncpy(name,data.strField1,MAX_NAMESIZE);

		//prefix =  data.strField1;
		//joint = data.strField2;
		strncpy(prefix,data.strField1,MAX_NAMESIZE);
		strncpy(joint,data.strField2,MAX_NAMESIZE);
		getAllNum(data.strField3,golds);
		fillLuckRangeValue(data.strField4,str);
		fillLuckRangeValue(data.strField5,inte);
		fillLuckRangeValue(data.strField6,dex);
		fillLuckRangeValue(data.strField7,spi);
		fillLuckRangeValue(data.strField8,con);

		fillLuckRangeValue(data.strField9,five);

		fillRangeValue(data.strField10,pdamage);
		fillRangeValue(data.strField11,maxpdamage);
		fillRangeValue(data.strField12,mdamage);
		fillRangeValue(data.strField13,maxmdamage);
		fillRangeValue(data.strField14,pdefence);
		fillRangeValue(data.strField15,mdefence);

		fillLuckRangeValue(data.strField16,maxhp);
		fillLuckRangeValue(data.strField17,maxmp);
		fillLuckRangeValue(data.strField18,maxsp);
		fillLuckRangeValue(data.strField19,mvspeed);
		fillLuckRangeValue(data.strField20,hpr);
		fillLuckRangeValue(data.strField21,mpr);
		fillLuckRangeValue(data.strField22,spr);
		fillLuckRangeValue(data.strField23,akspeed);
		fillLuckRangeValue(data.strField24,pdam);
		fillLuckRangeValue(data.strField25,pdef);
		fillLuckRangeValue(data.strField26,mdam);
		fillLuckRangeValue(data.strField27,mdef);
		fillLuckRangeValue(data.strField28,atrating);
		fillLuckRangeValue(data.strField29,akdodge);

		fillLuckRangeValue(data.strField30,poisondef);
		fillLuckRangeValue(data.strField31,lulldef);
		fillLuckRangeValue(data.strField32,reeldef);
		fillLuckRangeValue(data.strField33,evildef);
		fillLuckRangeValue(data.strField34,bitedef);
		fillLuckRangeValue(data.strField35,chaosdef);
		fillLuckRangeValue(data.strField36,colddef);
		fillLuckRangeValue(data.strField37,petrifydef);
		fillLuckRangeValue(data.strField38,blinddef);
		fillLuckRangeValue(data.strField39,stabledef);
		fillLuckRangeValue(data.strField40,slowdef);
		fillLuckRangeValue(data.strField41,luredef);
		fillLuckRangeValue(data.strField42,resumedur);
		//bang = data.dwField43;
		fillLuckRangeValue(data.strField43,bang);
		holyrating = data.dwField44;

		init_skill(data.strField45);
		init_skills(data.strField46);

		//Xlogger->debug("id:%d,name:%s",id,name);
#if 0
		//恢复耐久度格式单独处理
		{
			std::vector<uint32_t> num;
			int i =getAllNum(data.strField47,num);
			if (i!=7)
			{
				bzero(&durpoint,sizeof(durpoint));
				bzero(&dursecond,sizeof(dursecond));
			}
			else
			{
				durpoint.per=num[0];
				durpoint.data.min=num[1];
				durpoint.data.max=num[2];
				durpoint.sleightValue=num[3];
				dursecond.per=0;
				dursecond.data.min=num[4];
				dursecond.data.max=num[5];
				dursecond.sleightValue=num[6];
			}
		}
#endif

	}

	zColorObjectB():zEntry()
	{
		bzero(this,sizeof(zColorObjectB));
		type=tt;
	};

	void init_skill(const std::string& info)
	{
		skill.clear();
		Split<Parse3> p;
		p(info,skill,";",":");
	}

	void init_skills(const std::string& info)
	{
		skillbonus* p = Parse3<skillbonus>()(info,":");
		if (p) {
			skills = *p;
			SAFE_DELETE(p);
		}  
		else if (strcmp(info.c_str(),"0")!=0)
		{       
			Xlogger->debug("init_skills(%d),%s",id,info.c_str());
		}     
	}  

};

typedef ColorObjectBase GoldObjectBase;
typedef ColorObjectBase DropGoldObjectBase;
typedef ColorObjectBase BlueObjectBase;
typedef zColorObjectB<BlueObjectBase,1> zBlueObjectB;
typedef zColorObjectB<GoldObjectBase,2> zGoldObjectB;
typedef zColorObjectB<DropGoldObjectBase,3> zDropGoldObjectB;

//------------------------------------
// SetObjectBase
//------------------------------------
struct SetObjectBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 编号
	char  strField1[32];    // 名称
	char  strField2[64];    // 套装5
	char  strField3[32];    // 套装4
	char  strField4[32];    // 套装3
	char  strField5[32];    // 套装2
	char  strField6[32];    // 套装1
	uint32_t  dwField7;    // 属性标识
};//导出 SetObjectBase 成功，共 532 条记录

struct zSetObjectB:public zEntry
{
	struct SET
	{
		uint16_t odds;
		std::vector<uint16_t> ids;
	};

	typedef std::vector<SET> SETS;
	typedef SETS::iterator iterator;
	SETS sets;
	uint32_t mark;

	void fill(SetObjectBase& data)
	{
		id = data.dwField0;
		strncpy(name,data.strField1,MAX_NAMESIZE);
		init_set(data.strField2);
		init_set(data.strField3);
		init_set(data.strField4);
		init_set(data.strField5);
		init_set(data.strField6);
		mark = data.dwField7;
	}

	zSetObjectB():zEntry()
	{
		bzero(this,sizeof(zSetObjectB));
	};

	void init_set(const std::string& info)
	{
		sets.clear();
		std::string::size_type pos = info.find(':');
		SET set;
		if (pos != std::string::npos) {
			set.odds = atoi(info.substr(0,pos).c_str());
			getAllNum(info.substr(pos+1).c_str(),set.ids);
		}
		sets.push_back(set);
	}

};

//------------------------------------
// FiveSetBase
//------------------------------------
struct FiveSetBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 属性标识
	char  strField1[16];    // 物理伤害减少x%
	char  strField2[16];    // 法术伤害减少x%
	char  strField3[16];    // 增加伤害值x%
	char  strField4[16];    // 伤害反射x%
	char  strField5[16];    // x%忽视目标防御
};//导出 FiveSetBase 成功，共 4 条记录


struct zFiveSetB:public zEntry
{
	rangeValue dpdam; //物理伤害减少%x
	rangeValue dmdam; //法术伤害减少%x
	rangeValue bdam; //增加伤害x%
	rangeValue rdam; //伤害反射%x
	rangeValue ignoredef; //%x忽视目标防御

	void fill(FiveSetBase& data)
	{
		id = data.dwField0;
		fillRangeValue(data.strField1,dpdam);
		fillRangeValue(data.strField2,dmdam);
		fillRangeValue(data.strField3,bdam);    
		fillRangeValue(data.strField4,rdam);    
		fillRangeValue(data.strField5,ignoredef);    
	}

	zFiveSetB():zEntry()
	{
		bzero(this,sizeof(zFiveSetB));
	};  
};

//------------------------------------
// HolyObjectBase
//------------------------------------
struct HolyObjectBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 编号
	char  strField1[64];    // 名称
	char  strField2[16];    // 神圣一击
	char  strField3[16];    // 增加伤害值x％
	char  strField4[16];    // 五行属性增加
	char  strField5[16];    // 生命值恢复
	char  strField6[16];    // 法术值恢复
	char  strField7[16];    // 体力值恢复
	char  strField8[16];    // 攻击速度
	char  strField9[16];    // 移动速度
	char  strField10[16];    // 命中率
	char  strField11[16];    // 闪避率
	char  strField12[16];    // 技能加成
	char  strField13[16];    // 全系技能加成
	char  strField14[16];    // 双倍经验
	char  strField15[16];    // 增加掉宝率
};//导出 HolyObjectBase 成功，共 705 条记录

struct zHolyObjectB:public zEntry
{
	uint16_t  holy;        // 神圣一击
	luckRangeValue  damage;    // 增加伤害值x％
	luckRangeValue  fivepoint;    // 五行属性增加

	luckRangeValue hpr;      // 生命值恢复
	luckRangeValue mpr;      // 法术值恢复
	luckRangeValue spr;      // 体力值恢复

	luckRangeValue akspeed;    // 攻击速度
	luckRangeValue mvspeed;    // 移动速度

	luckRangeValue atrating;    // 命中率
	luckRangeValue akdodge;      // 闪避率

	std::vector<skillbonus> skill;  // 技能加成
	skillbonus skills;        // 全系技能加成

	luckRangeValue doublexp;    //%x双倍经验
	luckRangeValue mf;       //掉宝率

	void fill(HolyObjectBase &data)
	{
		id = data.dwField0;
		strncpy(name,data.strField1,MAX_NAMESIZE);
		holy = atoi(data.strField2);

		fillLuckRangeValue(data.strField3,damage);    
		fillLuckRangeValue(data.strField4,fivepoint);
		fillLuckRangeValue(data.strField5,hpr);
		fillLuckRangeValue(data.strField6,mpr);
		fillLuckRangeValue(data.strField7,spr);
		fillLuckRangeValue(data.strField8,akspeed);
		fillLuckRangeValue(data.strField9,mvspeed);
		fillLuckRangeValue(data.strField10,atrating);
		fillLuckRangeValue(data.strField11,akdodge);

		init_skill(data.strField12);
		init_skills(data.strField13);

		fillLuckRangeValue(data.strField14,doublexp);
		fillLuckRangeValue(data.strField15,mf);

	}

	zHolyObjectB():zEntry()
	{
		bzero(this,sizeof(zHolyObjectB));
	};

	void init_skill(const std::string& info)
	{
		skill.clear();
		Split<Parse3> p;
		p(info,skill,";",":");
	}

	void init_skills(const std::string& info)
	{
		skillbonus* p = Parse3<skillbonus>()(info,":");
		if (p) {
			skills = *p;
			SAFE_DELETE(p);
		}
	}  
};

//------------------------------------
// UpgradeObjectBase
//------------------------------------
struct UpgradeObjectBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 编号
	uint32_t  dwField1;    // 物品ID
	char  strField2[64];    // 名称
	uint32_t  dwField3;    // 类型
	uint32_t  dwField4;    // 升级原料
	uint32_t  dwField5;    // 需要银子
	uint32_t  dwField6;    // 对应成功率
	uint32_t  dwField7;    // 最小物攻增加
	uint32_t  dwField8;    // 最大物攻增加
	uint32_t  dwField9;    // 最小魔攻增加
	uint32_t  dwField10;    // 最大魔攻增加
	uint32_t  dwField11;    // 物防增加
	uint32_t  dwField12;    // 魔防增加
	uint32_t  dwField13;    // 生命值增加
};//导出 UpgradeObjectBase 成功，共 6345 条记录


struct zUpgradeObjectB:public zEntry
{
	uint32_t dwObjectID;    // 物品ID
	uint16_t level;    // 类型

	uint16_t stuff;    // 升级原料

	uint16_t gold;    // 需要银子

	uint16_t odds;    // 对应成功率

	uint32_t pdamage;        // 最小攻击力
	uint32_t maxpdamage;      // 最大攻击力
	uint32_t mdamage;        // 最小法术攻击力
	uint32_t maxmdamage;      // 最大法术攻击力

	uint32_t pdefence;        // 物防
	uint32_t mdefence;        // 魔防
	uint32_t maxhp;          // 最大生命值

	void fill(UpgradeObjectBase  &data)
	{
		id = data.dwField0;
		dwObjectID = data.dwField1;
		strncpy(name,data.strField2,MAX_NAMESIZE);
		level = data.dwField3;
		stuff = data.dwField4;
		gold = data.dwField5;
		odds = data.dwField6;

		pdamage = data.dwField7;
		maxpdamage = data.dwField8;
		mdamage = data.dwField9;
		maxmdamage = data.dwField10;

		pdefence = data.dwField11;
		mdefence = data.dwField12;

		maxhp = data.dwField13;
	}

	zUpgradeObjectB():zEntry()
	{
		bzero(this,sizeof(zUpgradeObjectB));
	}
};

//------------------------------------
// NpcBase
//------------------------------------
struct NpcBase
{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 编号
	char  strField1[32];    // 名称
	uint32_t  dwField2;    // 类型
	uint32_t  dwField3;    // 等级
	uint32_t  dwField4;    // 生命值
	uint32_t  dwField5;    // 经验值

	uint32_t  dwField6;    // 力
	uint32_t  dwField7;    // 智
	uint32_t  dwField8;    // 敏捷
	uint32_t  dwField9;    // 精神
	uint32_t  dwField10;    // 体质
	uint32_t  dwField11;    // 体质

	uint32_t  dwField12;    // 颜色
	uint32_t  dwField13;    // ai
	uint32_t  dwField14;    // 移动间隔
	uint32_t  dwField15;    // 攻击间隔
	uint32_t  dwField16;    // 最小物理防御力
	uint32_t  dwField17;    // 最大物理防御力
	uint32_t  dwField18;    // 最小法术防御力
	uint32_t  dwField19;    // 最大法术防御力
	uint32_t  dwField20;    // 五行属性
	uint32_t  dwField21;    // 五行点数
	char  strField22[1024];    // 攻击类型
	uint32_t  dwField23;    // 最小法术攻击
	uint32_t  dwField24;    // 最大法术攻击
	uint32_t  dwField25;    // 最小攻击力
	uint32_t  dwField26;    // 最大攻击力
	uint32_t  dwField27;    // 技能
	char  strField28[4096];    // 携带物品
	uint32_t  dwField29;    // 魂魄之石几率
	char  strField30[1024];    // 使用技能
	char  strField31[1024];    // 状态
	uint32_t  dwField32;    // 躲避率
	uint32_t  dwField33;    // 命中率
	uint32_t  dwField34;    // 图片
	uint32_t  dwField35;    // 品质
	uint32_t  dwField36;    // 怪物类别
	uint32_t  dwField37;    // 纸娃娃图片
	char  strField38[64];    // 回血
	uint32_t  dwField39;    // 二进制标志
	uint32_t  dwField40;    // 二进制标志
	uint32_t  dwField41;    // sky 极品倍率
};

struct CarryObject
{
	uint32_t id;
	int   rate;
	int   minnum;
	int   maxnum;
	CarryObject()
	{
		id = 0;
		rate = 0;
		minnum = 0;
		maxnum = 0;
	}
};

typedef std::vector<CarryObject> NpcLostObject;

struct NpcCarryObject : private boost::noncopyable
{
	NpcCarryObject() {};
	bool set(const char *objects)
	{
		bool retval = true;
		//mlock.lock();
		cov.clear();
		if (strcmp(objects,"0"))
		{
			std::vector<std::string> obs;
			stringtok(obs,objects,";");
			for(std::vector<std::string>::const_iterator it = obs.begin(); it != obs.end(); it++)
			{
				std::vector<std::string> rt;
				stringtok(rt,*it,":");
				if (3 == rt.size())
				{
					CarryObject co;
					co.id = atoi(rt[0].c_str());
					co.rate = atoi(rt[1].c_str());
					std::vector<std::string> nu;
					stringtok(nu,rt[2],"-");
					if (2 == nu.size())
					{
						co.minnum = atoi(nu[0].c_str());
						co.maxnum = atoi(nu[1].c_str());
						cov.push_back(co);
					}
					else
						retval = false;
				}
				else
					retval = false;
			}
		}
		//mlock.unlock();
		return retval;
	}

	/**
	* \brief 物品掉落处理
	* \param nlo npc携带物品集合
	* \param value 掉落率打折比
	* \param value1 掉落率增加
	* \param value2 银子掉落率增加
	*/
	void lost(NpcLostObject &nlo,int value,int value1,int value2,int vcharm,int vlucky,int player_level,int DropRate,int DropRateLevel)
	{
		//mlock.lock();
		if (vcharm>1000) vcharm=1000;
		if (vlucky>1000) vlucky=1000;
		for(std::vector<CarryObject>::const_iterator it = cov.begin(); it != cov.end(); it++)
		{
			//Xlogger->debug("%u,%u,%u,%u",(*it).id,(*it).rate,(*it).minnum,(*it).maxnum);
			switch((*it).id)
			{
			case 665:
				{
					int vrate = (int)(((*it).rate/value)*(1+value1/100.0f)*(1+value2/100.0f)*(1+vcharm/1000.0f)*(1+vlucky/1000.0f));
					if (selectByTenTh(vrate))
					{
						nlo.push_back(*it);
					}
				}
				break;
			default:
				{
					int vrate = (int)(((*it).rate/value)*(1+value1/100.0f)*(1+vcharm/1000.0f)*(1+vlucky/1000.0f));
					if (player_level<= DropRateLevel)
					{
						if (selectByTenTh(vrate * DropRate))
						{
							nlo.push_back(*it);
						}
					}
					else
					{
						if (selectByTenTh(vrate))
						{
							nlo.push_back(*it);
						}
					}
				}
				break;
			}
		}
		//mlock.unlock();
	}
	/**
	* \brief 全部物品掉落处理
	* \param nlo npc携带物品集合
	* \param value 掉落率打折比
	* \param value1 掉落率增加
	* \param value2 银子掉落率增加
	*/
	void lostAll(NpcLostObject &nlo)
	{
		for(std::vector<CarryObject>::const_iterator it = cov.begin(); it != cov.end(); it++)
		{
			nlo.push_back(*it);
		}
	}

	/**
	* \brief 装备物品全部掉落处理(绿怪专用)
	* \param nlo npc携带物品集合
	* \param value 掉落率打折比
	* \param value1 掉落率增加
	* \param value2 银子掉落率增加
	*/
	void lostGreen(NpcLostObject &nlo,int value=1,int value1=0,int value2=0,int vcharm = 0,int vlucky = 0);
private:
	std::vector<CarryObject> cov;
	//zMutex mlock;
};


struct aTypeS{
	aTypeS()
	{
		byValue[0] = 0;
		byValue[1] = 0;
	}
	union {
		struct {
			BYTE byAType;
			BYTE byAction;
		};
		BYTE byValue[2];
	};
};

enum
{
	NPC_TYPE_HUMAN    = 0,///人型
	NPC_TYPE_NORMAL    = 1,/// 普通类型
	NPC_TYPE_BBOSS    = 2,/// 大Boss类型
	NPC_TYPE_LBOSS    = 3,/// 小Boss类型
	NPC_TYPE_BACKBONE  = 4,/// 精英类型
	NPC_TYPE_GOLD    = 5,/// 黄金类型
	NPC_TYPE_TRADE    = 6,/// 买卖类型
	NPC_TYPE_TASK    = 7,/// 任务类型
	NPC_TYPE_GUARD    = 8,/// 士兵类型
	NPC_TYPE_PET    = 9,/// 宠物类型
	NPC_TYPE_BACKBONEBUG= 10,/// 精怪类型
	NPC_TYPE_SUMMONS  = 11,/// 召唤类型
	NPC_TYPE_TOTEM    = 12,/// 图腾类型
	NPC_TYPE_AGGRANDIZEMENT = 13,/// 强化类型
	NPC_TYPE_ABERRANCE  = 14,/// 变异类型
	NPC_TYPE_STORAGE  = 15,/// 仓库类型
	NPC_TYPE_ROADSIGN  = 16,/// 路标类型
	NPC_TYPE_TREASURE  = 17,/// 宝箱类型
	NPC_TYPE_WILDHORSE  = 18,/// 野马类型
	NPC_TYPE_MOBILETRADE  = 19,/// 流浪小贩
	NPC_TYPE_LIVENPC  = 20,/// 生活npc（不战斗，攻城时消失）
	NPC_TYPE_DUCKHIT  = 21,/// 蹲下才能打的npc
	NPC_TYPE_BANNER    = 22,/// 旗帜类型
	NPC_TYPE_TRAP    = 23,/// 陷阱类型
	NPC_TYPE_MAILBOX  =24,///邮箱
	NPC_TYPE_AUCTION  =25,///拍卖管理员
	NPC_TYPE_UNIONGUARD  =26,///帮会守卫
	NPC_TYPE_SOLDIER  =27,///士兵，只攻击外国人
	NPC_TYPE_UNIONATTACKER  =28,///攻方士兵
	NPC_TYPE_SURFACE = 29,/// 地表类型
	NPC_TYPE_CARTOONPET = 30,/// 替身宝宝
	NPC_TYPE_PBOSS = 31,/// 紫色BOSS
	NPC_TYPE_RESOURCE = 32, /// 资源类NPC

	//sky添加
	NPC_TYPE_GHOST	= 999,  /// 元神类NPC
	NPC_TYPE_ANIMON   = 33,   /// 动物类怪物
	NPC_TYPE_GOTO	= 34,	///传送点
	NPC_TYPE_RESUR  = 35,	///复活点
	NPC_TYPE_UNFIGHTPET	= 36, ///非战斗宠物
	NPC_TYPE_FIGHTPET	= 37, ///战斗宠物
	NPC_TYPE_RIDE		= 38, ///坐骑
	NPC_TYPE_TURRET	= 39, /// 炮塔
	NPC_TYPE_BARRACKS = 40, /// 兵营
	NPC_TYPE_CAMP = 41,		/// 基地
};

enum
{
	NPC_ATYPE_NEAR    = 1,/// 近距离攻击
	NPC_ATYPE_FAR    = 2,/// 远距离攻击
	NPC_ATYPE_MFAR    = 3,/// 法术远程攻击
	NPC_ATYPE_MNEAR    = 4,/// 法术近身攻击
	NPC_ATYPE_NOACTION  = 5,    /// 无攻击动作
	NPC_ATYPE_ANIMAL    = 6  /// 动物类
};

///npc使用一个技能的描述
struct npcSkill
{
	uint32_t id;///技能id
	int needLevel;///技能id
	int rate;///使用几率
	int coefficient;///升级系数

	npcSkill():id(0),needLevel(0),rate(0),coefficient(0){}
	npcSkill(const npcSkill &skill)
	{
		id = skill.id;
		needLevel = skill.needLevel;
		rate = skill.rate;
		coefficient = skill.coefficient;
	}
	npcSkill& operator = (const npcSkill &skill)
	{
		id = skill.id;
		needLevel = skill.needLevel;
		rate = skill.rate;
		coefficient = skill.coefficient;
		return *this;
	}
};

struct npcRecover
{
	uint32_t start;
	BYTE type;
	uint32_t num;

	npcRecover()
	{
		start = 0;
		type = 0;
		num = 0;
	}

	void parse(const char * str)
	{
		if (!str) return;

		std::vector<std::string> vec;

		vec.clear();
		stringtok(vec,str,":");
		if (3==vec.size())
		{
			start = atoi(vec[0].c_str());
			type = atoi(vec[1].c_str());
			num = atoi(vec[2].c_str());
		}
	}
};

/**
* \brief Npc基本表格数据
*
*/
struct zNpcB : public zEntry
{
	uint32_t  kind;        // 类型
	uint32_t  level;        // 等级
	uint32_t  hp;          // 生命值
	uint32_t  exp;        // 经验值
	uint32_t  str;        // 力量
	uint32_t   inte;        // 智力
	uint32_t   dex;        // 敏捷
	uint32_t   men;        // 精神
	uint32_t   con;        // 体质
	uint32_t   cri;        // 暴击
	uint32_t  color;        // 颜色
	uint32_t  ai;          // ai
	uint32_t  distance;      // 移动间隔
	uint32_t  adistance;      // 攻击间隔
	uint32_t  pdefence;      // 最小物理防御力
	uint32_t  maxpdefence;    // 最大物理防御力
	uint32_t  mdefence;      // 最小法术防御力
	uint32_t  maxmdefence;    // 最大法术防御力
	uint32_t  five;        // 五行属性
	uint32_t   fivepoint;      // 五行点数
	std::vector<aTypeS> atypelist;  // 攻击类型
	uint32_t  mdamage;      // 最小法术攻击
	uint32_t  maxmdamage;      // 最大法术攻击
	uint32_t  damage;        // 最小攻击力
	uint32_t  maxdamage;      // 最大攻击力
	uint32_t  skill;        // 技能
	//char  object[1024 + 1];  // 携带物品
	NpcCarryObject nco;
	uint32_t  ChangeNpcID;     //soulrate;      //sky NPC变身ID
	char  skills[1024];    // 使用技能
	char  state[1024];    // 状态
	uint32_t  dodge;        // 躲避率
	uint32_t  rating;        // 命中率
	uint32_t  pic;        // 图片
	uint32_t  trait;        //品质
	uint32_t  bear_type;      //怪物类别
	uint32_t  pet_pic;      //宠物图片
	npcRecover recover;
	uint32_t  flags;      //二进制标志，目前有一个，可不可被外国人杀
	uint32_t  allyVisit;      //可被盟国访问的等级 0：不可访问 1：1级可访问 2：2级可访问

	std::map<int,std::vector<npcSkill> > skillMap;

	uint32_t  Need_Probability; //sky 极品概率

	bool parseSkills(const char * str)
	{
		skillMap.clear();
		strncpy(skills,str,sizeof(skills));

		bool ret = false;
		std::vector<std::string> type_v;
		stringtok(type_v,str,";");
		if (type_v.size()>0)
		{
			std::vector<std::string> type_sub_v,skill_v,prop_v;
			std::vector<std::string>::iterator type_it,skill_it;

			for (type_it=type_v.begin();type_it!=type_v.end();type_it++)
			{
				type_sub_v.clear();
				stringtok(type_sub_v,type_it->c_str(),":");
				if (2==type_sub_v.size())
				{
					int type = atoi(type_sub_v[0].c_str());

					std::vector<npcSkill> oneTypeSkills;
					skill_v.clear();
					stringtok(skill_v,type_sub_v[1].c_str(),",");
					for (skill_it=skill_v.begin();skill_it!=skill_v.end();skill_it++)
					{
						prop_v.clear();
						stringtok(prop_v,skill_it->c_str(),"-");
						if (4==prop_v.size())
						{
							npcSkill oneSkill;
							oneSkill.id = atoi(prop_v[0].c_str());
							oneSkill.needLevel = atoi(prop_v[1].c_str());
							oneSkill.rate = atoi(prop_v[2].c_str());
							oneSkill.coefficient = atoi(prop_v[3].c_str());

							oneTypeSkills.push_back(oneSkill);
						}
					}
					if (oneTypeSkills.size()>0)
					{
						skillMap[type] = oneTypeSkills;
						ret = true;
					}
				}
			}
		}
		return ret;
	}

	/**
	* \brief 根据类型随机取出一个npc技能的描述
	*
	* \param type 技能类型
	* \param skill 返回值，取得的技能描述
	* \return 是否取得成功
	*/
	bool getRandomSkillByType(int type,npcSkill &skill)
	{
		if (skillMap.find(type)==skillMap.end()) return false;

		skill = skillMap[type][randBetween(0,skillMap[type].size()-1)];
		return true;
	}

	/**
	* \brief 取得所有可用的技能ID
	*
	*
	* \param list 技能ID列表
	* \return bool 是否有技能
	*/
	bool getAllSkills(std::vector<uint32_t> & list,uint16_t level)
	{
		std::map<int,std::vector<npcSkill> >::iterator type_it;
		std::vector<npcSkill>::iterator skill_it;
		for (type_it=skillMap.begin();type_it!=skillMap.end();type_it++)
		{
			for (skill_it=type_it->second.begin();skill_it!=type_it->second.end();skill_it++)
				if (level>=skill_it->needLevel)
					list.push_back(skill_it->id);
		}
		return list.size()>0;
	}

	/**
	* \brief 增加一个npc技能
	* \param type 技能分类
	* \param id 要增加的技能id
	* \param rate 施放几率
	* \param coefficient 系数
	*/
	void addSkill(int type,uint32_t id,int needLevel,int rate,int coefficient = 0)
	{
		npcSkill s;
		s.id = id;
		s.needLevel = needLevel;
		s.rate = rate;
		s.coefficient = coefficient;
		skillMap[type].push_back(s);
	}

	/**
	* \brief 删除一个npc技能
	*
	*
	* \param id 要删除的技能id
	* \return npc没有该技能则返回false
	*/
	bool delSkill(uint32_t id)
	{
		std::map<int,std::vector<npcSkill> >::iterator v_it;
		for (v_it=skillMap.begin();v_it!=skillMap.end();v_it++)
		{
			std::vector<npcSkill> v = v_it->second;
			std::vector<npcSkill>::iterator s_it;
			for (s_it=v.begin();s_it!=v.end();s_it++)
			{
				if (s_it->id==id)
				{
					v.erase(s_it);
					return true;
				}
			}
		}
		return false;
	}

	/**
	* \brief 设置npc的攻击类型
	*
	*
	* \param data 传入的字符串
	* \param size 字符串大小
	*/
	void setAType(const char *data,int size)
	{

		//Xlogger->error("address = %x",data);
		if(NULL == data)
		{
			fprintf(stderr,"data == NULL");
			return;
		}
		atypelist.clear();
		size = 1024;

		char Buf[1024];
		bzero(Buf,size);
		strncpy(Buf,data,size);
		std::vector<std::string> v_fir;
		stringtok(v_fir,Buf,":");
		for(std::vector<std::string>::iterator iter = v_fir.begin() ; iter != v_fir.end() ; iter++)
		{
			std::vector<std::string> v_sec;
			stringtok(v_sec,iter->c_str(),"-");

			if (v_sec.size() != 2)
			{
				return;
			}

			aTypeS aValue;
			std::vector<std::string>::iterator iter_1 = v_sec.begin();

			for(int i=0; i<2; i++)
			{
				aValue.byValue[i] = (BYTE)atoi(iter_1->c_str());
				iter_1 ++;
			}
			atypelist.push_back(aValue);
		}
		return;
	}

	/**
	* \brief 取得npc的攻击类型和动画类型
	*
	*
	* \param type 输出 攻击类型
	* \param action
	*/
	void getATypeAndAction(BYTE &type,BYTE &action)
	{    
		int size = atypelist.size();
		if (size == 0)
		{
			type = NPC_ATYPE_NEAR;
			action = 4 ;//Cmd::AniTypeEnum::Ani_Attack;//Cmd::Ani_Attack
			return;
		}
		int num = randBetween(0,size-1);
		type = atypelist[num].byAType;
		action = atypelist[num].byAction;
	}

	/**
	* \brief 根据表格中读出的数据填充zNpcB结构
	*
	*
	* \param npc 从表中读出的数据
	*/
	void fill(const NpcBase &npc)
	{
		setAType(npc.strField22,1024);
		id=          npc.dwField0;
		strncpy(name,npc.strField1,MAX_NAMESIZE);
		kind=        npc.dwField2;
		level=        npc.dwField3;
		hp=          npc.dwField4;
		exp=        npc.dwField5;
		str=        npc.dwField6;
		inte=        npc.dwField7;
		dex=        npc.dwField8;
		men=        npc.dwField9;
		con=        npc.dwField10;
		cri=        npc.dwField11;
		color=        npc.dwField12;
		ai=          npc.dwField13;
		distance=      (0==npc.dwField14)?640:npc.dwField14;
		adistance=       (0==npc.dwField15)?1000:npc.dwField15;
		pdefence=      npc.dwField16;
		maxpdefence=    npc.dwField17;
		mdefence=      npc.dwField18;
		maxmdefence=    npc.dwField19;
		five=        npc.dwField20;
		fivepoint=      npc.dwField21;

		mdamage=      npc.dwField23;
		maxmdamage=      npc.dwField24;
		damage=        npc.dwField25;
		maxdamage=      npc.dwField26;
		skill=        npc.dwField27;
		if (!nco.set(npc.strField28))
			Xlogger->error("Npc表格携带物品格式解析错误：%u,%s,\'%s\'",id,name,npc.strField28);
		ChangeNpcID=      npc.dwField29;
		parseSkills(npc.strField30);
		strncpy(state,npc.strField31,1024);
		dodge=        npc.dwField32;
		rating=        npc.dwField33;
		pic=        npc.dwField34;
		trait=        npc.dwField35;
		bear_type=      npc.dwField36;
		pet_pic=      npc.dwField37;
		recover.parse(npc.strField38);
		flags=        npc.dwField39;
		allyVisit=        npc.dwField40;
		Need_Probability = npc.dwField41; //sky 极品倍率
	}

	zNpcB() : zEntry()
	{
		id=          0;
		bzero(name,sizeof(name));
		kind=        0;
		level=        0;
		hp=        0;
		exp=        0;
		str=        0;
		inte=        0;
		dex=        0;
		men=        0;
		con=        0;
		cri=        0;
		color=        0;
		ai=        0;
		distance=      0;
		adistance=       0;
		pdefence=      0;
		maxpdefence=    0;
		mdefence=      0;
		maxmdefence=    0;
		five=        0;
		fivepoint=      0;
		atypelist.clear();
		mdamage=      0;
		maxmdamage=      0;
		damage=        0;
		maxdamage=      0;
		skill=        0;
		//bzero(object,sizeof(object));
		ChangeNpcID=      0;
		bzero(skills,sizeof(skills));
		bzero(state,sizeof(state));
		dodge=        0;
		rating=        0;
		pic=        0;
		trait=        0;
		bear_type=      0;
		pet_pic=      0;
		flags=        0;
		allyVisit=      0;
		Need_Probability = 0;
	}

};

//------------------------------------
// 人物经验Base
//------------------------------------
struct ExperienceBase
{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 等级
	uint32_t  dwField1;    // 需要经验
};//导出 人物经验Base 成功，共 300 条记录

struct zExperienceB : public zEntry
{
	uint32_t  level;        // 等级
	Quint16_t  nextexp;      //需要经验

	void fill(const ExperienceBase &data)
	{
		id = data.dwField0;
		//snprintf(name,MAX_NAMESIZE,"%u",id);
		_snprintf_s(name,MAX_NAMESIZE,"%u",id);
		nextexp = data.dwField1;
	}

	zExperienceB () : zEntry()
	{
		id = 0;
		nextexp = 0;
	}
};
//------------------------------------
// 荣誉增加表
//------------------------------------
struct HonorBase
{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 等级
	uint32_t  dwField1;    // 需要经验
};//导出 人物经验Base 成功，共 300 条记录

struct zHonorB : public zEntry
{
	uint32_t  level;        // 等级
	Quint16_t  value;      //需要经验

	void fill(const HonorBase &data)
	{
		id = data.dwField0;
		//snprintf(name,MAX_NAMESIZE,"%u",id);
		_snprintf_s(name,MAX_NAMESIZE,"%u",id);
		value = data.dwField1;
	}

	zHonorB () : zEntry()
	{
		id = 0;
		value = 0;
	}
};

//------------------------------------
// SkillBase
//------------------------------------
/**
* \brief 根据技能类型和等级计算一个临时唯一编号
*
*/
#define skill_hash(type,level) ((type - 1) * 100 + level)

struct SkillBase
{
	const uint32_t getUniqueID() const
	{
		return skill_hash(dwField0,dwField2);
	}

	uint32_t  dwField0;      // 技能ID
	char  strField1[32];    // 技能名称
	uint32_t  dwField2;      // 技能等级
	uint32_t  dwField3;      // 技能系别
	uint32_t  dwField4;      // 技能树别
	uint32_t  dwField5;      // 需要本线技能点数
	uint32_t  dwField6;      // 前提技能一
	uint32_t  dwField7;      // 前提技能一等级
	uint32_t  dwField8;      // 前提技能二
	uint32_t  dwField9;      // 前提技能二等级
	uint32_t  dwField10;      // 前提技能三
	uint32_t  dwField11;      // 前提技能三等级
	uint32_t  dwField12;      // 间隔时间
	uint32_t  dwField13;      // 攻击方式
	uint32_t  dwField14;      // 能否骑马使用
	uint32_t  dwField15;      // 需要物品
	char  strField16[128];  // 需要武器
	uint32_t  dwField17;      // 消耗体力值
	uint32_t  dwField18;      // 消耗法术值
	uint32_t  dwField19;      // 消耗生命值
	uint32_t  dwField20;      // 伤害加成
	char  strField21[1024];  // 效果
	uint32_t  dwField22;      // 消耗物品类型
	uint32_t  dwField23;      // 物品消耗数量
};//导出 SkillBase 成功，共 1 条记录

#define BENIGNED_SKILL_STATE 2
#define BAD_SKILL_STATE 4
#define NONE_SKILL_STATE 1 

struct SkillElement
{
	SkillElement()
	{
		id = 0;
		value = 0;
		percent = 0;
		time = 0;
		state = 0;
	}
	union {
		struct {
			uint32_t id;
			uint32_t percent;
			uint32_t value;
			uint32_t time;
			uint32_t state;
		};
		uint32_t element[5];
	};
	static SkillElement *create(SkillElement elem);
};
struct SkillStatus
{
	SkillStatus()
	{
		for(int i = 0 ; i < (int)(sizeof(status) / sizeof(uint16_t)) ; i ++)
		{
			status[i] = 0;
		}
	}
	union {
		struct {
			uint16_t id;//技能id
			uint16_t target;//目标
			uint16_t center;//中心点
			uint16_t range;//范围
			uint16_t mode;//飞行模式
			uint16_t clear;//能否清除
			uint16_t isInjure;//是否需要伤害计算
		};
		uint16_t status[7];
	};
	std::vector<SkillElement> _StatusElementList;
};
struct zSkillB : public zEntry
{
	bool has_needweapon(const uint16_t weapontype) const
	{
		std::vector<uint16_t>::const_iterator iter;
		if (weaponlist.empty()) return true;
		for(iter = weaponlist.begin(); iter != weaponlist.end(); iter++)
		{
			if (*iter == weapontype) return true;
		}
		return false;
	}

	bool set_weaponlist(const char *data)
	{
		weaponlist.clear(); 
		std::vector<std::string> v_fir;
		stringtok(v_fir,data,":");
		for(std::vector<std::string>::iterator iter = v_fir.begin() ; iter != v_fir.end() ; iter++)
		{
			uint16_t weaponkind = (uint16_t)atoi(iter->c_str());
			weaponlist.push_back(weaponkind);
		}
		return true;
	}

	bool set_skillState(const char *data)
	{
		skillStatus.clear(); 
		std::vector<std::string> v_fir;
		stringtok(v_fir,data,".");
		for(std::vector<std::string>::iterator iter = v_fir.begin() ; iter != v_fir.end() ; iter++)
		{
			//Xlogger->debug("%s",iter->c_str());
			std::vector<std::string> v_sec;
			stringtok(v_sec,iter->c_str(),":");
			/*
			if (v_sec.size() != 2)
			{
			return false;
			}
			// */
			SkillStatus status;
			std::vector<std::string>::iterator iter_1 = v_sec.begin() ;
			std::vector<std::string> v_thi;
			stringtok(v_thi,iter_1->c_str(),"-");
			if (v_thi.size() != 7)
			{
				//Xlogger->debug("操作!=7");
				continue;
				//return false;
			}
			std::vector<std::string>::iterator iter_2 = v_thi.begin() ;
			for(int i = 0 ; i < 7 ; i ++)
			{
				status.status[i] = (uint16_t)atoi(iter_2->c_str());
				//Xlogger->debug("status.status[%ld]=%ld",i,status.status[i]);
				iter_2 ++;
			}
			iter_1 ++;
			if (iter_1 == v_sec.end())
			{
				//Xlogger->debug("空操作");
				skillStatus.push_back(status);
				continue;
			}
			std::vector<std::string> v_fou;
			stringtok(v_fou,iter_1->c_str(),";");
			std::vector<std::string>::iterator iter_3 = v_fou.begin() ;
			for( ; iter_3 != v_fou.end() ; iter_3 ++)
			{
				std::vector<std::string> v_fiv;
				stringtok(v_fiv,iter_3->c_str(),"-");
				if (v_fiv.size() != 5)
				{
					//Xlogger->debug("元素个数不对");
					continue;
					//return false;
				}
				std::vector<std::string>::iterator iter_4 = v_fiv.begin() ;
				SkillElement element;
				for(int i = 0 ; i < 5 ; i ++)
				{
					element.element[i] = (uint32_t)atoi(iter_4->c_str());
					//Xlogger->debug("element.element[%u]=%u",i,element.element[i]);
					iter_4 ++;
				}
				status._StatusElementList.push_back(element);
			}
			skillStatus.push_back(status);
		}
		return true;
	}
	uint32_t  skillid;            //技能ID
	uint32_t  level;              //技能等级
	uint32_t  kind;              //技能系别
	uint32_t  subkind;            //技能树别
	uint32_t  needpoint;            //需要本线技能点数
	uint32_t  preskill1;            //前提技能1
	uint32_t  preskilllevel1;          //前提技能级别1
	uint32_t  preskill2;            //前提技能2
	uint32_t  preskilllevel2;          //前提技能级别2
	uint32_t  preskill3;            //前提技能3
	uint32_t  preskilllevel3;          //前提技能级别3
	uint32_t  dtime;              //间隔时间
	uint32_t  usetype;            //攻击方式
	uint32_t  ride;              //可否骑马使用
	uint32_t  useBook;            //需要物品
	uint32_t  spcost;              //消耗体力值
	uint32_t  mpcost;              //消耗法术值
	uint32_t  hpcost;              //消耗生命值
	uint32_t  damnum;              //伤害加成
	uint32_t  objcost;            //消耗物品类型
	uint32_t  objnum;              //消耗物品数量
	std::vector<SkillStatus> skillStatus;  //效果
	std::vector<uint16_t> weaponlist;      //武器列表



	void fill(const SkillBase &data)
	{
		id=skill_hash(data.dwField0,data.dwField2);
		skillid=data.dwField0;                //技能ID
		strncpy(name,data.strField1,MAX_NAMESIZE);
		level      = data.dwField2;          //技能等级
		kind      = data.dwField3;          //技能系别
		subkind      = data.dwField4;          //技能树别
		needpoint    = data.dwField5;          //需要本线技能点数
		preskill1    = data.dwField6;          //前提技能1
		preskilllevel1  = data.dwField7;;          //前提技能级别1
		preskill2    = data.dwField8;          //前提技能2
		preskilllevel2  = data.dwField9;          //前提技能级别2
		preskill3    = data.dwField10;          //前提技能3
		preskilllevel3  = data.dwField11;          //前提技能级别3
		dtime      = data.dwField12;          //间隔时间
		usetype      = data.dwField13;          //攻击方式
		ride      = data.dwField14;          //可否骑马使用
		useBook      = data.dwField15;          //学习需要物品
		set_weaponlist(data.strField16);          //需要武器
		spcost      = data.dwField17;          //消耗体力值
		mpcost      = data.dwField18;          //消耗法术值
		hpcost      = data.dwField19;          //消耗生命值
		damnum      = data.dwField20;          //伤害加成
		set_skillState(data.strField21);
		objcost      = data.dwField22;          //消耗物品类型
		objnum      = data.dwField23;          //消耗物品数量
	}


	zSkillB() : zEntry()
	{
		id = 0;
		skillid = 0;
		bzero(name,sizeof(name));        //说明
		level      = 0;          //技能等级
		kind      = 0;          //技能系别
		subkind      = 0;          //技能树别
		needpoint    = 0;          //需要本线技能点数
		preskill1    = 0;          //前提技能1
		preskilllevel1  = 0;          //前提技能级别1
		preskill2    = 0;          //前提技能2
		preskilllevel2  = 0;          //前提技能级别2
		preskill3    = 0;          //前提技能3
		preskilllevel3  = 0;          //前提技能级别3
		dtime      = 0;          //间隔时间
		usetype      = 0;          //攻击方式
		ride      = 0;          //可否骑马使用
		useBook      = 0;          //需要物品
		spcost      = 0;          //消耗体力值
		mpcost      = 0;          //消耗法术值
		hpcost      = 0;          //消耗生命值
		damnum      = 0;          //伤害加成
		objcost      = 0;          //消耗物品类型
		objnum      = 0;          //消耗物品数量
	}

};

struct LiveSkillBase{

	const uint32_t getUniqueID() const
	{
		return ((0xffff & dwField11) << 16) | (0xffff & dwField0);
	}

	uint32_t  dwField0;    // 技能ID
	char  strField1[64];    // 技能名称
	uint32_t  dwField2;    // 需要工具
	uint32_t  dwField3;    // 初始技能
	uint32_t  dwField4;    // 对应图素
	uint32_t  dwField5;    // 类别
	uint32_t  dwField6;    // 技能升级经验
	uint32_t  dwField7;    // 可否升级
	uint32_t  dwField8;    // 进阶技能
	uint32_t  dwField9;    // 前提技能ID
	uint32_t  dwField10;    // 所需前提技能等级
	uint32_t  dwField11;    // 技能等级
	char  strField12[32];    // 技能称号
	char  strField13[256];    // 获得物品
};

struct zLiveSkillB : public zEntry
{
	enum {
		MAX_EXP_BONUS = 30,
		MIN_POINT_BONUS = 1,
		MAX_POINT_BONUS = 3,
		WORKING_TIME = 6,
		MAX_LEVEL = 30,
	};

	//uint32_t skill_id; //技能标识
	//uint32_t level; //技能等级
	//uint16_t should be enough
	uint16_t skill_id; //技能标识
	uint16_t level; //技能等级
	uint32_t point; //升级所需技能点
	uint32_t weapon_kind; //武器种类
	//std::string name; //技能名称
	std::string title; //称号
	bool orig; //初始技能
	bool upgrade; //能否升级
	uint32_t kind; //技能类别
	uint32_t basic_skill_id; //前提技能id
	uint32_t basic_skill_level; //前提技能等级]
	uint32_t up_skill_id; //进阶技能id
	uint32_t map_kind;

	class ITEM 
	{
	public:
		uint32_t item; //获得物品
		uint32_t odds;  //几率
		uint32_t min_number; //最小数量
		uint32_t max_number; //最大数量

		ITEM( const std::string& odds_,const std::string& item_,const std::string& number_) : item(atoi(item_.c_str())),odds(atoi(odds_.c_str())),min_number(0),max_number(0)
		{
			std::string::size_type pos = 0;
			if  ( (pos = number_.find("-")) != std::string::npos ) {

				min_number = atoi(number_.substr(0,pos).c_str());
				max_number = atoi(number_.substr(pos+strlen("-")).c_str());
			}
			//if (item) Xlogger->debug("劳动获得物品数据:ID(%d),几率(%d),个数(%d-%d)",item,odds,min_number,max_number);
		}
	}; 

	typedef std::vector<ITEM> ITEMS;
	ITEMS items;

	BYTE min_point_bonus; //最小增加技能点
	BYTE max_point_bonus; //最大增加技能点
	BYTE exp_bonus; //奖励经验
	BYTE max_level; //最大等级

	zLiveSkillB() : zEntry(),skill_id(0),level(0),point(0),weapon_kind(0),/*name("未知"),*/ title(""),orig(false),upgrade(false),
		kind(1),basic_skill_id(0),basic_skill_level(0),up_skill_id(0),map_kind(0),
		min_point_bonus(MIN_POINT_BONUS),max_point_bonus(MAX_POINT_BONUS),exp_bonus(MAX_EXP_BONUS),
		max_level(MAX_LEVEL)
	{

	}

	void fill(const LiveSkillBase& base)
	{
		skill_id = 0xffff & base.dwField0;
		//name = base.strField1;
		weapon_kind = base.dwField2;
		orig = (base.dwField3==1)?true:false;
		map_kind = base.dwField4;
		kind = base.dwField5;
		point = base.dwField6;
		upgrade = (base.dwField7==1)?true:false;
		up_skill_id = base.dwField8;
		basic_skill_id = base.dwField9;
		basic_skill_level = base.dwField10;
		level = 0xffff & base.dwField11;
		strncpy(name,base.strField1,MAX_NAMESIZE);
		title = base.strField12;
		init_items(base.strField13);

		id = (level << 16) | skill_id;
	}

	void init_items(const std::string& item_list)
	{
		items.clear();
		Split<Parse3> p;
		p(item_list,items,";",":");

	}

};

//------------------------------------
// SoulStoneBase
//------------------------------------
struct SoulStoneBase{
	const uint32_t getUniqueID() const
	{
		return dwField2;
	}

	uint32_t  dwField0;    // 编号
	char  strField1[32];    // 名称
	uint32_t  dwField2;    // 品质
	char  strField3[16];    // x%吸收生命值y
	char  strField4[16];    // x%吸收法术值y
	char  strField5[16];    // 转换x%生命值为法术值减少
	char  strField6[16];    // 增加银子掉落x%
	char  strField7[16];    // x%双倍经验
	char  strField8[16];    // 增加掉宝率x%
	char  strField9[16];    // 抗毒增加
	char  strField10[16];    // 抗麻痹增加
	char  strField11[16];    // 抗眩晕增加
	char  strField12[16];    // 抗噬魔增加
	char  strField13[16];    // 抗噬力增加
	char  strField14[16];    // 抗混乱增加
	char  strField15[16];    // 抗冰冻增加
	char  strField16[16];    // 抗石化增加
	char  strField17[16];    // 抗失明增加
	char  strField18[16];    // 抗定身增加
	char  strField19[16];    // 抗减速增加
	char  strField20[16];    // 抗诱惑增加
	char  strField21[16];    // 中毒增加
	char  strField22[16];    // 麻痹增加
	char  strField23[16];    // 眩晕增加
	char  strField24[16];    // 噬魔增加
	char  strField25[16];    // 噬力增加
	char  strField26[16];    // 混乱增加
	char  strField27[16];    // 冰冻增加
	char  strField28[16];    // 石化增加
	char  strField29[16];    // 失明增加
	char  strField30[16];    // 定身增加
	char  strField31[16];    // 减速增加
	char  strField32[16];    // 诱惑增加
	uint32_t  dwField33;    // 需求等级
	char  strField34[16];    // 力量
	char  strField35[16];    // 智力
	char  strField36[16];    // 敏捷
	char  strField37[16];    // 精神
	char  strField38[16];    // 体质   
};//导出 SoulStoneBase 成功，共 40 条记录



struct zSoulStoneB : public zEntry
{
	//uint32_t id;
	//std::string name;

	struct Value
	{ 
		rangeValue odds; 
		rangeValue effect; 
	} hpleech,mpleech; ////x%吸收生命值y,x%吸收法术值y

	rangeValue hptomp; //转换生命值为法术值x％

	rangeValue incgold; //增加银子掉落x%
	rangeValue doublexp; //x%双倍经验    
	rangeValue mf; //增加掉宝率x%

	rangeValue poisondef; //抗毒增加
	rangeValue lulldef; //抗麻痹增加
	rangeValue reeldef; //抗眩晕增加
	rangeValue evildef; //抗噬魔增加
	rangeValue bitedef; //抗噬力增加
	rangeValue chaosdef; //抗混乱增加
	rangeValue colddef; //抗冰冻增加
	rangeValue petrifydef; //抗石化增加
	rangeValue blinddef; //抗失明增加
	rangeValue stabledef; //抗定身增加
	rangeValue slowdef; //抗减速增加
	rangeValue luredef; //抗诱惑增加

	rangeValue poison; //中毒增加
	rangeValue lull; //麻痹增加
	rangeValue reel; //眩晕增加
	rangeValue evil; //噬魔增加
	rangeValue bite; //噬力增加
	rangeValue chaos; //混乱增加
	rangeValue cold; //冰冻增加
	rangeValue petrify; //石化增加
	rangeValue blind; //失明增加
	rangeValue stable; //定身增加
	rangeValue slow; //减速增加
	rangeValue lure; //诱惑增加

	uint16_t level;   

	rangeValue str;      // 力量
	rangeValue inte;    // 智力
	rangeValue dex;      // 敏捷
	rangeValue spi;      // 精神
	rangeValue con;      // 体质

	zSoulStoneB() : zEntry()
	{

	}

	void fill(const SoulStoneBase& base)
	{
		id = base.dwField2;
		strncpy(name,base.strField1,MAX_NAMESIZE);

		init_value(base.strField3,hpleech);
		init_value(base.strField4,mpleech);

		fillRangeValue(base.strField5,hptomp);
		fillRangeValue(base.strField6,incgold);
		fillRangeValue(base.strField7,doublexp);
		fillRangeValue(base.strField8,mf);

		fillRangeValue(base.strField9,poisondef);
		fillRangeValue(base.strField10,lulldef);
		fillRangeValue(base.strField11,reeldef);  
		fillRangeValue(base.strField12,evildef);
		fillRangeValue(base.strField13,bitedef);
		fillRangeValue(base.strField14,chaosdef);
		fillRangeValue(base.strField15,colddef);
		fillRangeValue(base.strField16,petrifydef);
		fillRangeValue(base.strField17,blinddef);
		fillRangeValue(base.strField18,stabledef);
		fillRangeValue(base.strField19,slowdef);
		fillRangeValue(base.strField20,luredef);

		fillRangeValue(base.strField21,poison);
		fillRangeValue(base.strField22,lull);
		fillRangeValue(base.strField23,reel);  
		fillRangeValue(base.strField24,evil);
		fillRangeValue(base.strField25,bite);
		fillRangeValue(base.strField26,chaos);
		fillRangeValue(base.strField27,cold);
		fillRangeValue(base.strField28,petrify);
		fillRangeValue(base.strField29,blind);
		fillRangeValue(base.strField30,stable);
		fillRangeValue(base.strField31,slow);
		fillRangeValue(base.strField32,lure);

		level = base.dwField33;

		fillRangeValue(base.strField34,str);
		fillRangeValue(base.strField35,inte);
		fillRangeValue(base.strField36,dex);
		fillRangeValue(base.strField37,spi);
		fillRangeValue(base.strField38,con);    
	}

	void init_value(const std::string& src,Value& value)
	{
		std::string::size_type pos = 0;
		if  ( (pos = src.find(';')) != std::string::npos ) {
			fillRangeValue(src.substr(0,pos).c_str(),value.odds);
			fillRangeValue(src.substr(pos+1).c_str(),value.effect);
		}
	}

};



//------------------------------------
// HairStyle
//------------------------------------
struct HairStyle{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 编号
	char  strField1[32];    // 名称
	uint32_t  dwField2;    // 性别
	uint32_t  dwField3;    // 动作发型图片
	uint32_t  dwField4;    // 纸娃娃发型图片
	uint32_t  dwField5;    // 费用
};//导出 HairStyle 成功，共 10 条记录
struct zHairStyleB : public zEntry
{
	uint32_t cost;
	zHairStyleB():zEntry()
	{
		cost=0;
	}
	void fill(const HairStyle& base)
	{
		id = base.dwField0;
		strncpy(name,base.strField1,MAX_NAMESIZE);
		cost=base.dwField5;
	}
};

//------------------------------------
// HairColour
//------------------------------------
struct HairColour{
	const uint32_t getUniqueID() const
	{
		return dwField2 & 0x00FFFFFF;//发色做
	}
	uint32_t  dwField0;    // 编号
	char  strField1[32];    // 名称
	uint32_t  dwField2;    // 颜色
	uint32_t  dwField3;    // 费用
};//导出 HairColour 成功，共 4 条记录
struct zHairColourB : public zEntry
{
	uint32_t color;
	uint32_t cost;
	zHairColourB() : zEntry()
	{
		color=0;
		cost=0;
	}
	void fill(const HairColour& base)
	{
		id = base.dwField2 & 0x00FFFFFF;//发色做
		strncpy(name,base.strField1,MAX_NAMESIZE);
		color=base.dwField2;
		cost=base.dwField3;
	}
};
//------------------------------------
// HeadList
//------------------------------------
struct HeadList{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // 编号
	char  strField1[16];    // 头像名
	uint32_t  dwField2;    // 性别
	uint32_t  dwField3;    // 头像编号
	uint32_t  dwField4;    // 费用
};//导出 HeadList 成功，共 10 条记录
struct zHeadListB : public zEntry
{
	uint32_t sex;
	uint32_t icon;
	uint32_t cost;
	zHeadListB() : zEntry()
	{
		sex=0;
		icon=0;
		cost=0;
	}
	void fill(const HeadList& base)
	{
		id = base.dwField0;
		strncpy(name,base.strField1,MAX_NAMESIZE);
		sex=base.dwField2;
		icon=base.dwField3;
		cost=base.dwField4;
	}
};


//------------------------------------
//// PetBase
////------------------------------------
struct PetBase{
	const uint32_t getUniqueID() const
	{
		return dwField0;
	}
	uint32_t  dwField0;    // id
	uint32_t  dwField1;    // 等级
	uint32_t  dwField2;    // 类型
	uint32_t  dwField3;    // 经验值
	uint32_t  dwField4;    // 生命值
	uint32_t  dwField5;    // 物攻下限
	uint32_t  dwField6;    // 物攻上限
	uint32_t  dwField7;    // 魔攻下限
	uint32_t  dwField8;    // 魔攻上限
	uint32_t  dwField9;    // 物防
	uint32_t  dwField10;    // 魔防
	uint32_t  dwField11;    // 重击
	uint32_t  dwField12;    // 力量
	uint32_t  dwField13;    // 智力
	uint32_t  dwField14;    // 敏捷
	uint32_t  dwField15;    // 精神
	uint32_t  dwField16;    // 体质    
};

struct zPetB : public zEntry
{
	uint32_t base_id;    // id
	uint32_t lv;         // 等级
	uint32_t type;       // 类型
	uint32_t exp;        // 经验值
	uint32_t hp;         // 生命值
	uint32_t atk;        // 物攻下限
	uint32_t maxatk;     // 物攻上限
	uint32_t matk;       // 魔攻下限
	uint32_t maxmatk;    // 魔攻上限
	uint32_t def;        // 物防
	uint32_t mdef;       // 魔防
	uint32_t cri;        // 重击
	uint32_t str;        // 力量
	uint32_t intel;      // 智力
	uint32_t agi;        // 敏捷
	uint32_t men;        // 精神
	uint32_t vit;    // 体质    

	zPetB() : zEntry()
	{
		base_id  = 0;  
		lv  = 0;       
		type  = 0;     
		exp  = 0;      
		hp  = 0;       
		atk  = 0;      
		maxatk  = 0;   
		matk  = 0;     
		maxmatk  = 0;  
		def  = 0;      
		mdef  = 0;     
		cri  = 0;      
		str  = 0;      
		intel  = 0;    
		agi  = 0;      
		men  = 0;      
		vit  = 0;  
	}
	void fill(PetBase &base)
	{
		base_id  = base.dwField0;  
		id  = base.dwField0;  
		char buf[32];
		sprintf_s(buf,"%d",base.dwField0);
		strncpy(name,buf,MAX_NAMESIZE);
		lv  = base.dwField1;  
		type  = base.dwField2;  
		exp  = base.dwField3;  
		hp  = base.dwField4;  
		atk  = base.dwField5;  
		maxatk  = base.dwField6;    
		matk  = base.dwField7;  
		maxmatk  = base.dwField8;    
		def  = base.dwField9;  
		mdef  = base.dwField10;  
		cri  = base.dwField11;  
		str  = base.dwField12;  
		intel  = base.dwField13;  
		agi  = base.dwField14;  
		men  = base.dwField15;  
		vit  = base.dwField16;      
	}
};
//------------------------------------
// CountryMaterial
//------------------------------------
struct CountryMaterial{
	const uint32_t getUniqueID() const
	{
		return dwField1+dwField3;
	}

	uint32_t  dwField0;    // 编号
	uint32_t  dwField1;    // 物品ID
	uint32_t  dwField2;    // 材料类型
	uint32_t  dwField3;    // 物品类别
};
struct zCountryMaterialB : public zEntry
{
	uint32_t dwObjectID;
	uint32_t dwMaterialKind;
	uint32_t dwKind;

	zCountryMaterialB() : zEntry()
	{
		dwObjectID = 0;
		dwMaterialKind = 0;
		dwKind = 0;
	}
	void fill(const CountryMaterial& base)
	{
		id = base.dwField1+base.dwField3;

		dwObjectID = base.dwField1;
		dwMaterialKind = base.dwField2;
		dwKind = base.dwField3;
	}
};

#pragma pack()

template <class data>
class zDatabaseCallBack
{
public:
	virtual bool exec(data *entry)=0;
	virtual ~zDatabaseCallBack(){};
};
typedef zEntryManager<zEntryID,zMultiEntryName> zDataManager;
template <class data,class datafile>
class  zDataBM:public zDataManager
{

private:
	static zDataBM<data,datafile> *me;
	zRWLock rwlock;

	zDataBM()
	{
	}

	class deleteEvery:public zDatabaseCallBack<data>
	{
		bool exec(data *entry)
		{
			delete entry;
			return true;
		}
	};

	~zDataBM()
	{
		deleteEvery temp;
		execAll(temp);
		rwlock.wrlock();
		clear();
		rwlock.unlock();
	}

	zEntry * getEntryByID( uint32_t id)
	{
		zEntry * ret=NULL;
		zEntryID::find(id,ret);
		return ret;
	}

	void removeEntryByID(uint32_t id)
	{
		zEntry * ret=NULL;
		if (zEntryID::find(id,ret))
			removeEntry(ret);
	}

	zEntry * getEntryByName( const char * name)
	{
		zEntry * ret=NULL;
		zMultiEntryName::find(name,ret,true);
		return ret;
	}

	void removeEntryByName(const char * name)
	{
		zEntry * ret=NULL;
		if (zMultiEntryName::find(name,ret))
			removeEntry(ret);
	}

	bool refresh(datafile &base)
	{
		static uint32_t id = base.getUniqueID();
		data *o=(data *)getEntryByID(base.getUniqueID());
		if (o==NULL)
		{
			o=new data();
			//fprintf(stderr,"%u",o->level);
			if (o==NULL)
			{
				Xlogger->fatal("无法分配内存");
				return false;
			}
			o->fill(base);
			if (!zDataManager::addEntry(o))
			{
				Xlogger->fatal("添加Entry错误(%ld)(id=%ld,name=%s)",base.dwField0,o->id,o->name);
				SAFE_DELETE(o);
				return false;
			}
		}
		else
		{
			o->fill(base);
			//重新调整名字hash中的位置，这样即使名称改变也可以查询到
			zMultiEntryName::remove((zEntry * &)o);
			zMultiEntryName::push((zEntry * &)o);
		}
		return true;
	}

public:
	static zDataBM & getMe()
	{
		if (me==NULL)
			me=new zDataBM();
		return *me;
	}

	static void delMe()
	{
		SAFE_DELETE(me);
	}

	bool refresh(const char *filename)
	{
		FILE* fp = fopen(filename,"rb");
		bool ret=false;
		if (fp)
		{
			uint32_t size;
			datafile ob;
			bzero(&ob,sizeof(ob));
			if (fread(&size,sizeof(size),1,fp)==1)
			{
				rwlock.wrlock();
				for(uint32_t i =0;i<size;i++)
				{
					if (fread(&ob,sizeof(ob),1,fp)==1)
					{
						refresh(ob);
						bzero(&ob,sizeof(ob));
					}
					else
					{
						Xlogger->error("读到未知大小结构，文件[%s]可能损坏",filename);
						break;
					}
					if (feof(fp)) break;
				}
				rwlock.unlock();
				ret=true;
			}
			else
			{
				Xlogger->error("读取记录个数失败");
			}
			fclose(fp);
		}
		else
		{
			Xlogger->error("打开文件[%s]失败",filename);
		}
		if (ret)
			Xlogger->info("刷新基本表[%s]成功",filename);
		else
			Xlogger->error("刷新基本表[%s]失败",filename);
		return ret;
	}

	data *get(uint32_t dataid)
	{
		rwlock.rdlock();
		data *ret=(data *)getEntryByID(dataid);
		rwlock.unlock();
		return ret;
	}

	data *get(const char *name)
	{
		rwlock.rdlock();
		data *ret=(data *)getEntryByName(name);
		rwlock.unlock();
		return ret;
	}

	void execAll(zDatabaseCallBack<data> &base)
	{
		rwlock.rdlock();
		for(zEntryID::hashmap::iterator it=zEntryID::ets.begin();it!=zEntryID::ets.end();it++)
		{
			if (!base.exec((data *)it->second))
			{
				rwlock.unlock();
				return;
			}
		}
		rwlock.unlock();
	}

	void listAll()
	{
		class listevery:public zDatabaseCallBack<data>
		{
		public:
			int i;
			listevery()
			{
				i=0;
			}
			bool exec(data *zEntry)
			{
				i++;
				Xlogger->debug("%ld\t%s",zEntry->id,zEntry->name);
				return true;
			}
		};
		listevery le;
		execAll(le);
		Xlogger->debug("Total %d",le.i);
	}
};

extern zDataBM<zObjectB,ObjectBase> &objectbm;
extern zDataBM<zBlueObjectB,BlueObjectBase> &blueobjectbm;
extern zDataBM<zGoldObjectB,GoldObjectBase> &goldobjectbm;
extern zDataBM<zDropGoldObjectB,DropGoldObjectBase> &dropgoldobjectbm;
extern zDataBM<zSetObjectB,SetObjectBase> &setobjectbm;
extern zDataBM<zFiveSetB,FiveSetBase> &fivesetbm;
extern zDataBM<zHolyObjectB,HolyObjectBase> &holyobjectbm;
extern zDataBM<zUpgradeObjectB,UpgradeObjectBase> &upgradeobjectbm;
extern zDataBM<zNpcB,NpcBase> &npcbm;
//extern zDataBM<zCharacterB,CharacterBase> &characterbm;
extern zDataBM<zExperienceB,ExperienceBase> &experiencebm;
extern zDataBM<zHonorB,HonorBase> &honorbm;
extern zDataBM<zSkillB,SkillBase> &skillbm;
extern zDataBM<zLiveSkillB,LiveSkillBase> &liveskillbm;
extern zDataBM<zSoulStoneB,SoulStoneBase> &soulstonebm;
extern zDataBM<zHairStyleB,HairStyle> &hairstylebm;
extern zDataBM<zHairColourB,HairColour> &haircolourbm;
extern zDataBM<zCountryMaterialB,CountryMaterial> &countrymaterialbm;
extern zDataBM<zHeadListB,HeadList> &headlistbm;
extern zDataBM<zPetB,PetBase> &petbm;

extern bool loadAllBM();
extern void unloadAllBM();

/**
* \brief 角色管理器定义
*/
/**
* \brief 角色定义类,有待扩充
*/
struct zUser:public zSceneEntry
{
	zUser():zSceneEntry(SceneEntry_Player)
	{
	}
	void lock()
	{
		//Xlogger->debug("lockuser");
		mlock.lock();
	}

	void unlock()
	{
		//Xlogger->debug("unlockuser");
		mlock.unlock();
	}

private:
	zMutex mlock;
};


/**
* \brief 角色管理器
*
* 实现了ID、临时ID和名字的索引,所以这些值不能重复
*/
class zUserManager:public zEntryManager< zEntryID,zEntryTempID,zEntryName>
{
protected:
	/**
	* \brief 管理器访问互斥锁
	*/
	zRWLock rwlock;

public:
	/**
	* \brief 构造函数
	*/
	zUserManager()
	{
	}

	/**
	* \brief 析构函数
	*/
	virtual ~zUserManager()
	{
		clear();
	}

	/**
	* \brief 根据角色名字得到角色
	* \param name 角色名字
	* \return 角色指针,如果返回NULL表示没找到角色
	*/
	zUser * getUserByName( const char * name)
	{
		rwlock.rdlock();
		zUser *ret =(zUser *)getEntryByName(name);
		rwlock.unlock();
		return ret;
	}

	/**
	* \brief 根据角色ID得到角色
	* \param id 角色ID
	* \return 角色指针,如果返回NULL表示没找到角色
	*/
	zUser * getUserByID( uint32_t id)
	{
		rwlock.rdlock();
		zUser *ret =(zUser *)getEntryByID(id);
		rwlock.unlock();
		return ret;
	}

	/**
	* \brief 根据角色临时ID得到角色
	* \param tempid 角色临时ID
	* \return 角色指针,如果返回NULL表示没找到角色
	*/
	zUser * getUserByTempID( uint32_t tempid)
	{
		rwlock.rdlock();
		zUser *ret =(zUser *)getEntryByTempID(tempid);
		rwlock.unlock();
		return ret;
	}

	/**
	* \brief 添加角色
	* \param user 角色
	* \return 添加是否成功
	*/
	bool addUser(zSceneEntry *user)
	{
		rwlock.wrlock();
		//      Xlogger->debug("%s(%x) really insert into user manager",user->name,user);      
		bool ret =addEntry((zEntry *)user);
		rwlock.unlock();
		return ret;
	}

	/**
	* \brief 移出角色
	* \param user 角色
	*/
	void removeUser(zSceneEntry *user)
	{
		rwlock.wrlock();
		//      Xlogger->debug("%s(%x) really removed from user manager",user->name,user);
		removeEntry((zEntry *)user);
		rwlock.unlock();
	}

	/**
	* \brief 移出符合条件的角色
	* \param pred 条件断言
	*/
	template <class YourUserEntry>
	void removeUser_if(removeEntry_Pred<YourUserEntry> &pred)
	{
		rwlock.wrlock();
		removeEntry_if<>(pred);
		rwlock.unlock();
	}

	/**
	* \brief 对每个用户执行
	* \param exec 执行接口
	*/
	template <class YourUserEntry>
	bool execEveryUser(execEntry<YourUserEntry> &exec)
	{
		rwlock.rdlock();
		bool ret=execEveryEntry<>(exec);
		rwlock.unlock();
		return ret;
	}
};

/**
* \brief A*寻路算法
*/
/**
* \brief A*寻路算法模板
* 其中step表示步长，radius表示搜索半径
*/
template <int step = 1,int radius = 12>
class zAStar
{

private:

	/**
	* \brief 路径坐标点
	*/
	struct zPathPoint
	{
		/**
		* \brief 坐标
		*/
		zPos pos;
		/**
		* \brief 当前距离
		*/
		int cc;
		/**
		* \brief 路径上一个结点指针
		*/
		zPathPoint *father;
	};

	/**
	* \brief 路径头
	*/
	struct zPathQueue
	{
		/**
		* \brief 路径节点头指针
		*/
		zPathPoint *node;
		/**
		* \brief 路径消耗距离
		*/
		int cost;
		/**
		* \brief 构造函数
		* \param node 初始化的路径节点头指针
		* \param cost 当前消耗距离
		*/
		zPathQueue(zPathPoint *node,int cost)
		{
			this->node = node;
			this->cost = cost;
		}
		/**
		* \brief 拷贝构造函数
		* \param queue 待拷贝的源数据
		*/
		zPathQueue(const zPathQueue &queue)
		{
			node = queue.node;
			cost = queue.cost;
		}
		/**
		* \brief 赋值操作符号
		* \param queue 待赋值的源数据
		* \return 返回结构的引用
		*/
		zPathQueue & operator= (const zPathQueue &queue)
		{
			node = queue.node;
			cost = queue.cost;
			return *this;
		}
	};

	/**
	* \brief 定义所有路径的链表
	*/
	typedef std::list<zPathQueue> zPathQueueHead;
	typedef typename zPathQueueHead::iterator iterator;
	typedef typename zPathQueueHead::reference reference;

	/**
	* \brief 估价函数
	* \param midPos 中间临时坐标点
	* \param endPos 最终坐标点
	* \return 估算出的两点之间的距离
	*/
	int judge(const zPos &midPos,const zPos &endPos)
	{
		int distance = abs((long)(midPos.x - endPos.x)) + abs((long)(midPos.y - endPos.y));
		return distance;
	}

	/**
	* \brief 进入路径队列
	* \param queueHead 路径队列头
	* \param pPoint 把路径节点添加到路径中
	* \param currentCost 路径的估算距离
	*/
	void enter_queue(zPathQueueHead &queueHead,zPathPoint *pPoint,int currentCost)
	{
		zPathQueue pNew(pPoint,currentCost);
		if (!queueHead.empty())
		{
			for(iterator it = queueHead.begin(); it != queueHead.end(); it++)
			{
				//队列按cost由小到大的顺序排列
				if ((*it).cost > currentCost)
				{
					queueHead.insert(it,pNew);
					return;
				}
			}
		}
		queueHead.push_back(pNew);
	}

	/**
	* \brief 从路径链表中弹出最近距离
	* \param queueHead 路径队列头
	* \return 弹出的最近路径
	*/
	zPathPoint *exit_queue(zPathQueueHead &queueHead)
	{
		zPathPoint *ret = NULL;
		if (!queueHead.empty())
		{
			reference ref = queueHead.front();
			ret = ref.node;
			queueHead.pop_front();
		}
		return ret;
	}

public:

	/**
	* \brief 寻路过程中判断中间点是否可达目的地
	*
	*  return (scene->zPosShortRange(tempPos,destPos,radius)
	*      && (!scene->checkBlock(tempPos) //目标点可达，或者是最终目标点
	*        || tempPos == destPos));
	*
	* \param tempPos 寻路过程的中间点
	* \param destPos 目的点坐标
	* \param radius 寻路范围，超出范围的视为目的地不可达
	* \return 返回是否可到达目的地
	*/
	virtual bool moveable(const zPos &tempPos,const zPos &destPos,const int radius = radius) = 0;
	/**
	* \brief 物件向某一个方向移动
	* \param direct 方向
	* \param step 表示步长
	* \return 移动是否成功
	*/
	virtual bool move(const int direct,const int step = step) = 0;
	/**
	* \brief 使物件向某一个点移动
	* 带寻路算法的移动
	* \param srcPos 起点坐标
	* \param destPos 目的地坐标
	* \return 移动是否成功
	*/
	bool gotoFindPath(const zPos &srcPos,const zPos &destPos);
	/**
	* \brief Npc向某一个点移动
	* \param srcPos 起点坐标
	* \param destPos 目的地坐标
	* \return 移动是否成功
	*/
	bool goTo(const zPos &srcPos,const zPos &destPos);
	/**
	* \brief Npc随机向某一个方向移动
	* \param direct 随机方向
	* \return 移动是否成功
	*/
	bool shiftMove(const int direct);

};

template<int step,int radius>
bool zAStar<step,radius>::gotoFindPath(const zPos &srcPos,const zPos &destPos)
{
	//DisMap是以destPos为中心的边长为2 * radius + 1 的正方形
	const int width = (2 * radius + 1);
	const int height = (2 * radius + 1);
	const int MaxNum = width * height;
	//把所有路径距离初始化为最大值
	std::vector<int> pDisMap(MaxNum,MaxNum);
	std::vector<zPathPoint> stack(MaxNum * 8 + 1);//在堆栈中分配内存
	zPathQueueHead queueHead;

	//从开始坐标进行计算
	zPathPoint *root = &stack[MaxNum * 8];
	root->pos = srcPos;
	root->cc = 0;
	root->father = NULL;
	enter_queue(queueHead,root,root->cc + judge(root->pos,destPos));

	int Count = 0;
	//无论如何,循环超过MaxNum次则放弃
	while(Count < MaxNum)
	{
		root = exit_queue(queueHead);
		if (NULL == root)
		{
			//目标点不可达
			return false;
		}

		if (root->pos == destPos)
		{
			//找到到达目的地的路径
			break;
		}

		const zAdjust adjust[8] =
		{
			{  1 * step,0 * step  },
			{  0 * step,-1 * step  },
			{  0 * step,1 * step  },
			{  -1 * step,0 * step  },
			{  1 * step,-1 * step  },
			{  -1 * step,-1 * step  },
			{  -1 * step,1 * step  },
			{  1 * step,1 * step  }
		};
		for(int i = 0; i < 8; i++)
		{
			//分别对周围8个格点进行计算路径
			bool bCanWalk = true;
			zPos tempPos = root->pos;
			tempPos += adjust[i];

			if (moveable(tempPos,destPos))
			{
				//对路径进行回溯
				zPathPoint *p = root;
				while(p)
				{
					if (p->pos == tempPos)
					{
						//发现坐标点已经在回溯路径中，不能向前走
						bCanWalk = false;
						break;
					}
					p = p->father;
				}

				//如果路径回溯成功，表示这个点是可行走的
				if (bCanWalk)
				{
					int cost = root->cc + 1;
					int index = (tempPos.y - destPos.y + radius) * width + (tempPos.x - destPos.x + radius);
					if (index >= 0
						&& index < MaxNum
						&& cost < pDisMap[index])
					{
						//这条路径比上次计算的路径还要短，需要加入到最短路径队列中
						pDisMap[index] = cost;
						zPathPoint *pNewEntry = &stack[Count * 8 + i];
						pNewEntry->pos = tempPos;
						pNewEntry->cc = cost;
						pNewEntry->father = root;
						enter_queue(queueHead,pNewEntry,pNewEntry->cc + judge(pNewEntry->pos,destPos));
					}
				}
			}
		}

		Count++;
	}

	if (Count < MaxNum)
	{
		//最终路径在PointHead中,但只走一步
		while(root)
		{
			//倒数第二个节点
			if (root->father != NULL
				&& root->father->father == NULL)
			{
				return move(srcPos.getDirect(root->pos));
			}

			root = root->father;
		}
	}

	return false;
}

template<int step,int radius>
inline bool zAStar<step,radius>::goTo(const zPos &srcPos,const zPos &destPos)
{
	int direct = srcPos.getDirect(destPos);

	if (!move(direct)) {
		int r = randBetween(0,1);
		int deep = 0;
		while(deep < 3) {
			switch(r) {
case 0://顺时针
	direct++;
	break;
case 1://逆时针
	direct += 7;
	break;
			}
			direct %= 8;
			if (move(direct))
				return true;
			deep++;
		}
	}

	return false;
}

template<int step,int radius>
inline bool zAStar<step,radius>::shiftMove(const int direct)
{
	return move(direct);
}

/**
* \brief 正则表达式类声明
*/
/**
* \brief 正则表达式类，对regex进行了封装，对于正则表达式请参考man 7 regex.
*
* 本类支持子字符串匹配，但最多支持31个字串
*
* 本类非线程安全
*/
class zRegex
{

public :

	zRegex(const char *exp):_exp(exp){}

	bool match(const char * target);
	/*{

	boost::regex reg(_exp);
	if(boost::regex_search(std::string(target),reg))
	{
	size_t len = strlen(target) + 1;
	const char *ptr1 = strstr(target,"(");
	const char *ptr2 = strstr(ptr1+1,",");
	size_t l1 = ptr2 - ptr1;
	char *f1 = new char[l1];
	strncpy(f1,ptr1+1,l1);
	f1[l1-1] = '\0';
	first = atoi(f1);
	delete[] f1;

	const char *ptr3 = strstr(ptr2+1,")");
	l1 = ptr3 - ptr2 - 1;
	f1 = new char[l1];
	strncpy(f1,ptr2+1,l1);
	f1[l1-1] = '\0';
	second = atoi(f1);
	delete[] f1;

	return true;
	}
	return false;
	}*/

private:
	/**
	* \brief 错误信息存放处
	*/
	std::string errstr;
	/**
	* \brief 错误代码
	*/
	int errcode;
	/**
	* \brief 正则表达式句柄
	*/
	//regex_t preg;
	/**
	* \brief 要匹配的字符串 
	*/
	//std::string smatch;
	/**
	* \brief 表达式是否已编译 
	*/
	//bool compiled;
	/**
	* \brief 是否匹配 
	*/
	//bool matched;
	/**
	* \brief 子串匹配位置 
	*/
	//regmatch_t rgm[32];

	/**
	* \brief 自定义错误代码:标记错误 
	*/
	static const int REG_FLAGS;
	/**
	* \brief 自定义错误代码:未编译错误
	*/
	static const int REG_COMP;
	/**
	* \brief 自定义错误代码:未知错误
	*/
	static const int REG_UNKNOW;
	/**
	* \brief 自定义错误代码:未进行匹配错误 
	*/
	static const int REG_MATCH;
public:
	/**
	* \brief 自定义标记:支持多行匹配，默认不支持
	*/
	static const int REG_MULTILINE;
	/**
	* \brief 自定义标记:默认标记
	*/
	static const int REG_DEFAULT;
	//zRegex();
	//~zRegex();
	//bool compile(const char * regex,int flags=REG_DEFAULT);
	//bool match(const char *s);
	//std::string &getSub(std::string &s,int sub=0);
	const std::string & getError();


	unsigned int first;
	unsigned int second;


private:
	const char *_exp;
};

#pragma pack(1)

/**
* \brief 定义才对战的基本结构
*
*/
namespace DareDef
{
	const uint32_t CREATE_DARE_NEED_PRICE_GOLD = 500; // 对战所扣金额
	const uint32_t DARE_WINNER_GOLD = 800; // 对战胜者一方，所获金额
	const uint32_t READYTIME  = 300; // 等待应战的时间，单位:秒
	const uint32_t ACTIVETIME = 3600; // 对战进行时间，单位:秒
	const uint32_t CREATE_UNION_CITY_DARE_NEED_PRICE_MONEY = 20000; //两锭
	const uint32_t CREATE_UNION_KING_CITY_DARE_NEED_PRICE_MONEY = 50000; //五锭
	const uint32_t CREATE_UNION_NEUTRAL_CITY_DARE_NEED_PRICE_MONEY = 50000; //五锭

	/// 状态描述
	extern char str_state[9][20];
	extern char str_type[7][30];
}

namespace QuizDef
{
	const uint32_t READYTIME  = 300; // 等待应战的时间，单位:秒
	const uint32_t ACTIVETIME = 3600; // 对战进行时间，单位:秒

	const uint32_t PERSONAL_QUIZ_NEED_GOLD = 100; // 个人问答，所需银两
	enum
	{
		WORLD_QUIZ = 0, // 全区竞赛
		PERSONAL_QUIZ = 1 // 个人问答
	};

	/// 状态描述
	extern char str_state[9][30];
	extern char str_type[2][20];
}

/**
* \brief 定义NPC争夺的公共信息
*
*/
namespace NpcDareDef
{
	const uint32_t CREATE_NPCDARE_NEED_ITEM = 738; // 发起对战需要的道具 地羽令

	struct NpcDareRecord {
		uint32_t dwCountry;      /// 国家
		uint32_t dwMapID;        /// 地图ID
		uint32_t dwNpcID;        /// NPC id
		uint32_t dwPosX;        /// npc的 x 坐标
		uint32_t dwPosY;        /// npc的 y 坐标
		uint32_t dwHoldSeptID;      /// 目前该npc的所有家族
		uint32_t dwDareSeptID;      /// 目前该npc的挑战家族
		uint32_t dwGold;        /// 结余税金
	};
}

#pragma pack()

void Seal_Startup(void);

//filter begin
#ifdef __cplusplus
extern "C"{
#endif //__cplusplus

	/*
	server启动时调用,其它的所有初始化已经完成.
	*/
	void filter_init(void);

	/*
	server每次接收到一个请求时调用,返回TRUE说明filter已经处理此请求.
	原则上filter可以改写server内部的处理流程,但是目前的设计是用来处理新增的功能的.
	*/
	BOOL filter_command(PBYTE pCmd,uint32_t dwCmd);

	/*
	server退出时调用,其它的所有清除尚未开始.
	*/
	void filter_term(void);

	typedef void (*PFN_filter_init)(void);

	typedef BOOL (*PFN_filter_command)(PBYTE pCmd,uint32_t dwCmd);

	typedef void (*PFN_filter_term)(void);

	typedef struct
	{
		HINSTANCE          hInstance;
		PFN_filter_init    filter_init;
		PFN_filter_command filter_command;
		PFN_filter_term    filter_term;
	}NFilterModule,*PFilterModule;

#ifdef __cplusplus
}

typedef std::vector<NFilterModule> NFilterModuleArray;

#endif //__cplusplus
//filter end

//service begin
void loadFilter(NFilterModuleArray & nFMA,PSTR szPattern);

int service_main( int argc,char *argv[] );
//service end

#endif //_INC_SRVENGINE_H_

