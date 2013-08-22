#include "LoginSessionManager.h"
#include <string.h>	//for memcpy

template<> LoginSessionManager *Singleton<LoginSessionManager>::ms_Singleton = NULL;

void LoginSessionManager::put(const t_NewLoginSession &session)
{
	boost::mutex::scoped_lock lock(mlock);
	LoginSessionHashmap_iterator it = sessionData.find(session.accid);
	if (it != sessionData.end()) {
		//find, just refresh
		it->second.session = session;
		it->second.timestamp = microsec_clock::local_time();
	}
	else {
		//can't find, add
		sessionData.insert(LoginSessionHashmap_pair(session.accid,LoginSession(session)));
	}
}

bool LoginSessionManager::verify(const DWORD loginTempID,const DWORD accid,char *numPassword/*,ZES_cblock *key*/) {
	bool retval = false;
	boost::mutex::scoped_lock lock(mlock);

	LoginSessionHashmap_iterator it = sessionData.find(accid);
	if (it != sessionData.end() && loginTempID == it->second.session.loginTempID)
	{
		retval = true;
		/*
		if (0!=key)
		{
			//bcopy(it->second.session.des_key,key,sizeof(ZES_cblock),sizeof(ZES_cblock));
		}
		*/
		memcpy(numPassword, it->second.session.numpasswd, sizeof(it->second.session.numpasswd));
		sessionData.erase(it);
	}
	return retval;
}

void LoginSessionManager::update(const ptime &ct)
{
	if (checkUpdateTime(ct))
	{
		boost::mutex::scoped_lock lock(mlock);
		for(LoginSessionHashmap_iterator it = sessionData.begin(); it != sessionData.end();)
		{
			if (ct - it->second.timestamp >= seconds(10))
			{
				Xlogger->debug("login time out:%u,%u,%u",it->second.session.accid,it->second.session.loginTempID,it->second.session.wdGatewayID);
				LoginSessionHashmap_iterator tmp = it;
				it++;
				sessionData.erase(tmp);
			}
			else
				it++;
		}
	}
}

bool LoginSessionManager::checkUpdateTime(const ptime &ct) {
	bool retval = false;
	if (ct >= lastUpdateTime) {
		lastUpdateTime = ct + seconds(1);
		retval = true;
	}
	return retval;
}

