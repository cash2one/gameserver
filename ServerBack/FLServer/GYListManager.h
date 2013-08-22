#pragma once

#include "common.h"
#include "command.h"
#include <string.h>
#include <boost/thread/mutex.hpp>
#include <boost/unordered_map.hpp>

struct GYList {
	WORD wdServerID;      /**< 服务器编号 */
	DWORD dwpstrIP;  /**< 服务器地址 */
	WORD wdPort;        /**< 服务器端口 */
	WORD wdNumOnline;      /**< 网关在线人数 */
	int  state;          /**< 服务器状态 */
	DWORD zoneGameVersion;

	GYList() {
		memset(this, 0, sizeof(*this));
	}
};

class GYListManager {
public:
	~GYListManager() {
		gyData.clear();
	}

	static GYListManager &getInstance() {
		if (NULL == instance)
			instance = new GYListManager;

		return *instance;
	}

	static void delInstance() { SAFE_DELETE(instance); }

	bool put(const GameZone_t &gameZone,const GYList &gy);
	void disableAll(const GameZone_t &gameZone);
	GYList *getAvl(const GameZone_t &gameZone);
	void full_ping_list(Cmd::stPingList* cmd,const GameZone_t& gameZone);
	bool verifyVer(const GameZone_t &gameZone,DWORD verify_client_version,BYTE &retcode);

	DWORD getOnline(void);
private:
	static GYListManager *instance;
	GYListManager() {}

	/*struct less_str 
	{

	bool operator()(const GameZone_t & x, const GameZone_t & y) const 
	{
	if (x.id < y.id )
	return true;

	return false;
	}
	};*/

	/**
	* \brief hash函数
	*
	*/
	/*struct GameZone_hash : public hash_compare<GameZone_t,less_str>
	{
	size_t operator()(const GameZone_t &gameZone) const
	{
	//Hash<DWORD> H;
	//return Hash<DWORD>(gameZone.id);
	return 1;
	}

	//static const unsigned int bucket_size = 100;
	//static const unsigned int min_buckets = 100;
	};*/
	typedef boost::unordered_multimap<const GameZone_t, GYList> GYListContainer;
	typedef GYListContainer::iterator GYListContainer_iterator;
	typedef GYListContainer::value_type GYListContainer_value_type;
	GYListContainer gyData;
	boost::mutex mlock;
};
