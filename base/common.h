#pragma once

#include "type.h"
#include <boost/smart_ptr.hpp>	//shared_ptr scoped_ptr
#include <boost/utility.hpp>	//noncopyable
#include "x_properties.h"
#include "x_logger.h"
#include <boost/functional/hash.hpp>

#pragma pack(1)
struct GameZone_t
{
	union
	{
		DWORD id;
		struct
		{
			WORD zone;
			WORD game;
		};
	};
	GameZone_t() {
		game = 0;
		zone = 0;
	}
	bool operator == (const GameZone_t& t) const {
		return id == t.id;
	}
};
#pragma pack()

inline std::size_t hash_value(const GameZone_t& t) {
	boost::hash<size_t> hasher;
	return hasher(t.id);
}


enum ServerType
{
	UNKNOWNSERVER  =  0, /** 未知服务器类型 */
	SUPERSERVER      =  1, /** 管理服务器 */
	LOGINSERVER     =  10, /** 登陆服务器 */
	RECORDSERVER  =  11, /** 档案服务器 */
	BILLSERVER      =  12, /** 计费服务器 */
	SESSIONSERVER  =  20, /** 会话服务器 */
	SCENESSERVER  =  21, /** 场景服务器 */
	GATEWAYSERVER  =  22, /** 网关服务器 */
	MINISERVER      =  23    /** 小游戏服务器 */
};

using boost::shared_ptr;
using boost::noncopyable;

namespace Seal
{
	/**
	* \brief 游戏时间
	*
	*/
	extern volatile uint64_t qwGameTime;

	/**
	* \brief 日志指针
	*
	*/
	extern x_logger* logger;

	/**
	* \brief 存取全局变量的容器
	*
	*/
	extern x_properties global;
};

#define Xlogger Seal::logger
#define INVALID_SOCKET (-1)

#define SAFE_DELETE(x) if((x)) { delete (x); (x)=NULL;}

#define PH_LEN 4
#define MAX_MSG_SIZE 65535

#define MAX_NAMESIZE 		32
#define MAX_IP_LENGTH 		16
#define MAX_NUMPASSWORD  32
#define MAX_PASSWORD  16
#define MAX_ACCNAMESIZE 48 

enum {
	state_none = 0,
	state_maintain = 1 <<0,
};

template<class T>
inline void constructInPlace(T *ptr)
{
	new (static_cast<void*>(ptr)) T();
}


enum NetType {
	NetType_near = 0,
	NetType_far = 1,
};
