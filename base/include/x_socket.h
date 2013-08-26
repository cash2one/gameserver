#pragma once

#include "common.h"
#include <errno.h>
#include <unistd.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#include "x_buffer.h"
#include "x_nullcmd.h"


class x_socket : private boost::noncopyable
{

public:
	static const int T_RD_MSEC          =  2100;          /**< 读取超时的毫秒数 */
	static const int T_WR_MSEC          =  2100;          /**< 发送超时的毫秒数 */

	static const uint32_t PH_LEN       =  sizeof(uint32_t);  /**< 数据包包头大小 */
	static const uint32_t PACKET_ZIP_MIN  =  32;            /**< 数据包压缩最小大小 */

	static const uint32_t PACKET_ZIP    =  0x40000000;        /**< 数据包压缩标志 */
	static const uint32_t INCOMPLETE_READ  =  0x00000001;        /**< 上次对套接口进行读取操作没有读取完全的标志 */
	static const uint32_t INCOMPLETE_WRITE  =  0x00000002;        /**< 上次对套接口进行写入操作没有写入完毕的标志 */

	static const uint32_t PACKET_MASK      =  trunkSize - 1;  /**< 最大数据包长度掩码 */
	static const uint32_t MAX_DATABUFFERSIZE  =  PACKET_MASK;            /**< 数据包最大长度，包括包头4字节 */
	static const uint32_t MAX_DATASIZE      =  (MAX_DATABUFFERSIZE - PH_LEN);    /**< 数据包最大长度 */
	static const uint32_t MAX_USERDATASIZE    =  (MAX_DATASIZE - 128);        /**< 用户数据包最大长度 */

public:
	static const char *getIPByIfName(const char *ifName);

	x_socket(const int sock,const struct sockaddr_in *addr = NULL);
	~x_socket();

	int recvToCmd(void *pstrCmd,const int nCmdLen,const bool wait);
	bool sendCmd(const void *pstrCmd,const int nCmdLen,const bool buffer = false);
	bool sendCmdNoPack(const void *pstrCmd,const int nCmdLen,const bool buffer = false);
	int  Send(const int sock, const void* pBuffer, const int nLen,int flags);
	bool sync();
	void force_sync();

	int checkIOForRead();
	int checkIOForWrite();
	int recvToBuf_NoPoll();
	int recvToCmd_NoPoll(void *pstrCmd,const int nCmdLen);

	/**
	* \brief 获取套接口对方的地址
	* \return IP地址
	*/
	const char *getIP() const { return inet_ntoa(addr.sin_addr); }
	const uint32_t getAddr() const { return addr.sin_addr.s_addr; }

	/**
	* \brief 获取套接口对方端口
	* \return 端口
	*/
	const uint16_t getPort() const { return ntohs(addr.sin_port); }

	/**
	* \brief 获取套接口本地的地址
	* \return IP地址
	*/
	const char *getLocalIP() const { return inet_ntoa(local_addr.sin_addr); }

	/**
	* \brief 获取套接口本地端口
	* \return 端口
	*/
	const uint16_t getLocalPort() const { return ntohs(local_addr.sin_port); }

	/**
	* \brief 设置读取超时
	* \param msec 超时，单位毫秒 
	* \return 
	*/
	void setReadTimeout(const int msec) { rd_msec = msec; }

	/**
	* \brief 设置写入超时
	* \param msec 超时，单位毫秒 
	* \return 
	*/
	void setWriteTimeout(const int msec) { wr_msec = msec; }
	void add_epoll(int efd, uint32_t events,void* ptr);
	void del_epoll(int efd,uint32_t events);

	/**
	* \brief 填充pollfd结构
	* \param pfd 待填充的结构
	* \param events 等待的事件参数
	*/
	void fillPollFD(struct pollfd &pfd,short events)
	{
		pfd.fd = sock;
		pfd.events = events;
		pfd.revents = 0;
	}

	//uint32_t snd_queue_size() { return _snd_queue.rd_size() + _enc_queue.rd_size(); }
	uint32_t getBufferSize() const {return _rcv_queue.maxSize() + _snd_queue.maxSize();}

private:
	int sock;                  /**< 套接口 */
	struct sockaddr_in addr;          /**< 套接口地址 */
	struct sockaddr_in local_addr;        /**< 套接口地址 */
	int rd_msec;                /**< 读取超时，毫秒 */
	int wr_msec;                /**< 写入超时，毫秒 */

	//t_BufferCmdQueue    m_RecvBuffer;   // [ranqd]  Iocp接收数据缓冲

	t_BufferCmdQueue _rcv_queue;        /**< 接收缓冲指令队列 */
	uint32_t _rcv_raw_size;          /**< 接收缓冲解密数据大小 */
	t_BufferCmdQueue _snd_queue;        /**< 加密缓冲指令队列 */
	//t_BufferCmdQueue _enc_queue;        /**< 加密缓冲指令队列 */
	uint32_t _current_cmd;
	boost::mutex mutex;

	uint32_t bitmask;            /**< 标志掩码 */

	void set_flag(uint32_t _f) { bitmask |= _f; }
	bool isset_flag(uint32_t _f) const { return bitmask & _f; }
	void clear_flag(uint32_t _f) { bitmask &= ~_f; }
	/**
	* \brief 返回数据包包头最小长度
	* \return 最小长度
	*/
	uint32_t packetMinSize() const { return PH_LEN; }

	/**
	* \brief 返回整个数据包的长度
	* \param in 数据包
	* \return 返回整个数据包的长度
	*/
	uint32_t packetSize(const BYTE *in) const { return PH_LEN + ((*((uint32_t *)in)) & PACKET_MASK); }

	int sendRawData(const void *pBuffer,const int nSize);
	bool sendRawDataIM(const void *pBuffer,const int nSize);
	int sendRawData_NoPoll(const void *pBuffer,const int nSize);
	bool setNonblock();
	int waitForRead();
	int waitForWrite();
	int recvToBuf();
	/*
	uint32_t packetUnpack(BYTE *in,const uint32_t nPacketLen,BYTE *out);
	template<typename buffer_type>
	uint32_t packetAppend(const void *pData,const uint32_t nLen,buffer_type &cmd_queue);
	template<typename buffer_type>
	uint32_t packetAppendNoEnc(const void *pData,const uint32_t nLen,buffer_type &cmd_queue);
	template<typename buffer_type>
	uint32_t packetPackEnc(buffer_type &cmd_queue,const uint32_t current_cmd,uint32_t offset = 0);
	*/
public:
	/*
	template<typename buffer_type>
	static uint32_t packetPackZip(const void *pData,const uint32_t nLen,buffer_type &cmd_queue,const bool _compress = true);
	*/

	/*
	uint32_t               m_SendSize;   // [ranqd] 记录希望发送数据总长度
	uint32_t               m_LastSend;   // [ranqd] 记录单次请求发送数据长度
	uint32_t               m_LastSended; // [ranqd] 已发送所请求数据长度

	*/
};

struct x_processor
{
	virtual bool msgParse(const Cmd::t_NullCmd*, const uint32_t) = 0;
};
