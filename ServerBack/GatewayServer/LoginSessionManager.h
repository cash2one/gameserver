#pragma once

#include "common.h"
#include <boost/unordered_map.hpp>
#include <boost/thread/mutex.hpp>
#include "flcmd.h"
#include "singleton.h"
using namespace boost::posix_time;	//ptime
using namespace Cmd;
//using namespace Cmd::FL;

class LoginSessionManager: public Singleton<LoginSessionManager> 
{
public:
	LoginSessionManager() {
		lastUpdateTime = microsec_clock::local_time();
	}
	~LoginSessionManager() {}

	void put(const t_NewLoginSession &session);
	bool verify(const DWORD loginTempID, const DWORD accid,char *numPassword/*, ZES_cblock *key=0*/);
	void update(const ptime &ct);
private:

	ptime lastUpdateTime;

	bool checkUpdateTime(const ptime &ct);

	struct LoginSession {
		t_NewLoginSession session;
		ptime timestamp;

		LoginSession(const t_NewLoginSession &ses) : session(ses) {
			timestamp = microsec_clock::local_time();
		}
	};
	typedef boost::unordered_map<DWORD, LoginSession> LoginSessionHashmap;
	typedef LoginSessionHashmap::iterator LoginSessionHashmap_iterator;
	typedef LoginSessionHashmap::value_type LoginSessionHashmap_pair;
	LoginSessionHashmap sessionData;
	boost::mutex mlock;
};
