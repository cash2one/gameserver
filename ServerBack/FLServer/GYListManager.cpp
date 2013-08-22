#include "GYListManager.h"
#include "FLServer.h"

GYListManager *GYListManager::instance = NULL;

bool GYListManager::put(const GameZone_t &gameZone,const GYList &gy) {
	boost::mutex::scoped_lock scope_lock(mlock);

	std::pair<GYListContainer_iterator,GYListContainer_iterator> hps = gyData.equal_range(gameZone);
	for(GYListContainer_iterator it = hps.first; it != hps.second; ++it) {
		if (it->second.wdServerID == gy.wdServerID) {
			//refresh
			it->second = gy;
			return true;
		}
	}
	//add 
	gyData.insert(GYListContainer_value_type(gameZone,gy));
	Xlogger->debug("%s", __PRETTY_FUNCTION__);
	return true;
}

void GYListManager::disableAll(const GameZone_t &gameZone) {
	boost::mutex::scoped_lock scope_lock(mlock);
	std::pair<GYListContainer_iterator,GYListContainer_iterator> hps = gyData.equal_range(gameZone);
	for(GYListContainer_iterator it = hps.first; it != hps.second; ++it) {
		it->second.wdPort = 0;
		it->second.wdNumOnline = 0;
		it->second.state = state_maintain;
	}
}

//return the gateway which keep the mininum user
GYList *GYListManager::getAvl(const GameZone_t &gameZone) {
	boost::mutex::scoped_lock scope_lock(mlock);
	GYList *ret = NULL;	//point to the min

	Xlogger->debug("GYListSize = %d",gyData.size());
	std::pair<GYListContainer_iterator, GYListContainer_iterator> hps = gyData.equal_range(gameZone);
	for(GYListContainer_iterator it = hps.first; it != hps.second; ++it) {
		GYList* tmp = &(it->second);
		if (state_none == tmp->state && (NULL == ret || ret->wdNumOnline >= tmp->wdNumOnline)) {
			ret = tmp;
		}
	}
	return ret;
}

DWORD GYListManager::getOnline(void) {
	boost::mutex::scoped_lock scope_lock(mlock);
	DWORD                    dwCount = 0;
	for(GYListContainer_iterator pGYLCI=gyData.begin();pGYLCI != gyData.end();pGYLCI++) {
		GYList * pGYL = &(pGYLCI->second);
		dwCount += pGYL->wdNumOnline;
	}

	return dwCount;
}

void GYListManager::full_ping_list(Cmd::stPingList* cmd,const GameZone_t& gameZone)
{
	/*
	boost::mutex::scoped_lock scope_lock(mlock);
	const int per_num = 5;   // 档数
	int server_num = gyData.count(gameZone);
	int max_per = server_num * 2000;  // 最大人数
	int per_per = max_per/per_num; // 分成五档,每一档的人数
	int total_personal = 0; // 该区总人数
	int i=0;

	std::pair<GYListContainer_iterator,GYListContainer_iterator> hps = gyData.equal_range(gameZone);

	cmd->zone_id = gameZone.id;
	//      Cmd::ping_element* tempElement = cmd->ping_list;

	for (GYListContainer_iterator it = hps.first; it != hps.second; ++it,i++) {
		GYList *ret = &(it->second);
		if (state_none == ret->state)
		{
			if (i<server_num)
			{
				cmd->ping_list.gateway_ip = ret->dwpstrIP;
				total_personal += ret->wdNumOnline;
			}
			else
			{
				break;
			}
		}
	}

	for (int i=0; i<5; i++)
	{
		if (total_personal>=per_per*i && total_personal<(per_per*(i+1)-1))
		{
			cmd->ping_list.state = i;
			break;
		}
	}
	*/
}

bool GYListManager::verifyVer(const GameZone_t &gameZone,DWORD verify_client_version,BYTE &retcode) {
	boost::mutex::scoped_lock scope_lock(mlock);
	bool retval = false;
	GYList *ret = NULL,*tmp = NULL;
	std::pair<GYListContainer_iterator,GYListContainer_iterator> hps = gyData.equal_range(gameZone);
	for(GYListContainer_iterator it = hps.first; it != hps.second; ++it)
	{
		tmp = &(it->second);
		if (state_none == tmp->state && (NULL == ret || ret->wdNumOnline >= tmp->wdNumOnline))
		{
			ret = tmp;
		}
	}
	if (NULL == ret)
	{
		retcode = Cmd::LOGIN_RETURN_GATEWAYNOTAVAILABLE;
	}
	else if (ret->zoneGameVersion && ret->zoneGameVersion != verify_client_version)
	{
		retcode = Cmd::LOGIN_RETURN_VERSIONERROR;
	}
	else
	{
		retval = true;
	}
	return retval;
}

