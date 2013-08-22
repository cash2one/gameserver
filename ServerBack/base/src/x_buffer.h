#include "common.h"
#include <vector>

const uint32_t trunkSize = 64 * 1024;
#define unzip_size(zip_size) ((zip_size) * 120 / 100 + 12)
const uint32_t PACKET_ZIP_BUFFER  =  unzip_size(trunkSize - 1) + sizeof(uint32_t) + 8;  /**< 压缩需要的缓冲 */

/**
* 字节缓冲，用于套接口接收和发送数据的缓冲
* \param _type 缓冲区数据类型
*/
template <typename _type>
class ByteBuffer
{

public:
	/**
	* 构造函数
	*/
	ByteBuffer();

	/**
	* 向缓冲填入数据
	* \param buf 待填入缓冲的数据
	* \param size 待填入缓冲数据的长度
	*/
	inline void put(const BYTE *buf,const uint32_t size)
	{
		//首先确认缓冲内存是否足够
		wr_reserve(size);

		if( _maxSize - _currPtr < size )
		{
			Xlogger->fatal("缓冲区溢出");
		}

		bcopy(buf,&_buffer[_currPtr],size);
		_currPtr += size;
	}

	/**
	* 得到当前可写bf的未知
	* 保证在调用此函数写入数据之前需要调用wr_reserve(size)来预留缓冲区大小
	* \return 可写入缓冲开始地址
	*/
	inline BYTE *wr_buf()
	{
		return &_buffer[_currPtr];
	}

	/**
	* 返回缓冲中有效数据的开始地址
	* \return 有效数据地址
	*/
	inline BYTE *rd_buf()
	{
		return &_buffer[_offPtr];
	}

	/**
	* 判断缓冲中时候有有效数据
	* \return 返回缓冲中是否有有效数据
	*/
	inline bool rd_ready()
	{
		bool ret = _currPtr > _offPtr;
		return ret;
	}

	/**
	* 得到缓冲中有效数据的大小
	* \return 返回缓冲中有效数据大小
	*/
	inline uint32_t rd_size()
	{
		uint32_t ret = _currPtr - _offPtr;
		return ret;
	}

	/**
	* 当缓冲的有效数据被使用以后，需要对缓冲进行整理
	* \param size 最后一次使用的有效数据长度
	*/
	inline void rd_flip(uint32_t size)
	{	
		if (_currPtr > (_offPtr + size))
		{
			_offPtr += size;
			uint32_t tmp = _currPtr - _offPtr;
			if (_offPtr >= tmp)
			{
				memmove(&_buffer[0],&_buffer[_offPtr],tmp);
				_offPtr = 0;
				_currPtr = tmp;
			}
		}
		else if(_currPtr == (_offPtr + size))
		{
			_offPtr = 0;
			_currPtr = 0;
		}
		else
			Xlogger->fatal("buffer overflow");
	}

	/**
	* 得到缓冲可写入数据的大小
	* \return 可写入数据的大小
	*/
	inline uint32_t wr_size()
	{
		uint32_t ret = _maxSize - _currPtr;
		return ret;
	}

	/**
	* 实际向缓冲写入了数据，需要对缓冲进行整理
	* \param size 实际写入的数据
	*/
	inline void wr_flip(const uint32_t size)
	{
		if(_currPtr+size > _maxSize)
			Xlogger->fatal("buffer overflow : wr_flip");
		else
			_currPtr += size;
	}

	/**
	* 重值缓冲中的数据，清空无用的垃圾数据
	*/
	inline void reset()
	{
		_offPtr = 0;
		_currPtr = 0;
	}

	/**
	* 返回缓冲最大大小
	* \return 缓冲最大大小
	*/
	inline uint32_t maxSize() const
	{
		return _maxSize;
	}

	/**
	* 对缓冲的内存进行重新整理，向缓冲写数据，如果缓冲大小不足，重新调整缓冲大小，
	* 大小调整原则按照trunkSize的整数倍进行增加
	* \param size 向缓冲写入了多少数据
	*/
	inline void wr_reserve(const uint32_t size);

private:

	uint32_t _maxSize;
	uint32_t _offPtr;
	uint32_t _currPtr;
	_type _buffer;

};

/**
* 动态内存的缓冲区，可以动态扩展缓冲区大小
*/
typedef ByteBuffer<std::vector<BYTE> > t_BufferCmdQueue;

/**
* 模板偏特化
* 对缓冲的内存进行重新整理，向缓冲写数据，如果缓冲大小不足，重新调整缓冲大小，
* 大小调整原则按照trunkSize的整数倍进行增加
* \param size 向缓冲写入了多少数据
*/
template <>
inline void t_BufferCmdQueue::wr_reserve(const uint32_t size)
{
	if (wr_size() < size)
	{
		//块的数量
#define trunkCount(size) (((size) + trunkSize - 1) / trunkSize)
		_maxSize += (trunkSize * trunkCount(size-wr_size()));
		_buffer.resize(_maxSize);
	}
}


/**
* 静态大小的缓冲区，以栈空间数组的方式来分配内存，用于一些临时变量的获取
*/
typedef ByteBuffer<BYTE [PACKET_ZIP_BUFFER]> t_StackCmdQueue;

/**
* 模板偏特化
* 对缓冲的内存进行重新整理，向缓冲写数据，如果缓冲大小不足，重新调整缓冲大小，
* 大小调整原则按照trunkSize的整数倍进行增加
* \param size 向缓冲写入了多少数据
*/
template <>
inline void t_StackCmdQueue::wr_reserve(const uint32_t size)
{
}

/**
* \brief 变长指令的封装，固定大小的缓冲空间
* 在栈空间分配缓冲内存
* \param cmd_type 指令类型
* \param size 缓冲大小
*/
template <typename cmd_type,uint32_t size = 64 * 1024>
class CmdBuffer_wrapper
{

public:

	typedef cmd_type type;
	uint32_t cmd_size;
	uint32_t max_size;
	type *cnt;

	CmdBuffer_wrapper() : cmd_size(sizeof(type)),max_size(size)// : cnt(NULL)
	{
		cnt = (type *)buffer;
		constructInPlace(cnt);
	}

private:

	BYTE buffer[size];

};
