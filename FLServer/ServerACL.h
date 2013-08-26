#pragma once
#include <boost/unordered_map.hpp>
#include "singleton.h"
#include <boost/thread/mutex.hpp>	//for boost::mutex
#include <string>
#include "common.h"

struct ACLZone
{
	GameZone_t gameZone;
	std::string ip;
	WORD port;
	std::string name;
	std::string desc;

	ACLZone()
	{
		port = 0;
	}
};


class ServerACL : public Singleton<ServerACL>
{
public:
	ServerACL() {}
	~ServerACL() {}

	bool init();
	void final();
	bool check(const char *strIP,const WORD port,GameZone_t &gameZone,std::string &name);

private:
	bool add(const ACLZone &zone);

	struct ihash : std::unary_function<GameZone_t, std::size_t>
	{
		std::size_t operator()(const GameZone_t & x) const
		{
			std::size_t seed = 0;
			boost::hash_combine(seed, x.id);
			return seed;
		}
	};

	typedef boost::unordered_map<const GameZone_t,ACLZone,ihash> Container;
	Container datas;
	boost::mutex mutex_;
};
