#include "RecordUserManager.h"
#include "RecordUser.h"

bool RecordUserM::add(shared_ptr<RecordUser> u){
	if (!u) return false;
	bool retval = false;

	boost::mutex::scoped_lock lock(mutex_);

	RecordUserHashmap::const_iterator it = userMap.find(u->accid);
	if ( it == userMap.end()){
		userMap[u->accid] = u;
		retval = true;
	}
	Xlogger->debug("[current user],0,0,0,%s:%lu, retval=%u", __PRETTY_FUNCTION__,userMap.size(),retval);
	return retval;
}

bool RecordUserM::remove(const uint32_t accid, const uint32_t id, const uint32_t dwServerID){
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::iterator it = userMap.find(accid);
	bool ret = false;

	if ( it != userMap.end() ){
		shared_ptr<RecordUser> u = it->second;
		if ( u && u->accid == accid && u->charid == id && u->serverid == dwServerID) {
			userMap.erase(it);
			ret = true;
		}
	}
	Xlogger->debug("[current user],0,0,0,%s:%lu, ret=%u", __PRETTY_FUNCTION__, userMap.size(), ret);
	return ret;
}

bool RecordUserM::remove(shared_ptr<RecordUser> u) {
	if (!u) return false;
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::iterator it = userMap.find(u->accid);
	if (it != userMap.end()){
		userMap.erase(it);
		return true;
	}
	return false;
}

bool RecordUserM::verify(const uint32_t accid, const uint32_t id, const uint32_t dwServerID){
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::iterator it = userMap.find(accid);
	if (it!=userMap.end()){
		shared_ptr<RecordUser> ptr = it->second;
		if (ptr->accid == accid && ptr->charid == id && (ptr->serverid == dwServerID || dwServerID == 0))
			return true;
	}
	return false;
}

void RecordUserM::removeAllByServerID(const uint32_t dwServerID){
	boost::mutex::scoped_lock lock(mutex_);
	for (RecordUserHashmap::iterator it = userMap.begin();it!=userMap.end();){
		if (it->second->serverid == dwServerID){
			userMap.erase(it++);
		}
		else{
			++it;
		}
	}
}

bool RecordUserM::changeScene(const uint32_t accid, const uint32_t id, const uint32_t dwServerID){
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::iterator it = userMap.find(accid);
	if (it!=userMap.end()){
		shared_ptr<RecordUser> ptr = it->second;
		if (ptr->charid == id && ptr->serverid == dwServerID) {
			ptr->serverid = 0;
			return true;
		}
	}
	return false;
}

RecordUserPtr RecordUserM::getUserForWrite(const uint32_t accid, const uint32_t dwServerID){
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::iterator it = userMap.find(accid);
	if (it!=userMap.end()){
		shared_ptr<RecordUser> ptr = it->second;
		if (ptr->serverid == dwServerID) {
			return ptr;
		}
	}
	return RecordUserPtr((RecordUser*)0);
}

RecordUserPtr RecordUserM::getUserByAccid(const uint32_t accid, const uint32_t charid, const uint32_t dwServerID){
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::iterator it = userMap.find(accid);
	if (it!=userMap.end() && it->second->charid == charid){
		shared_ptr<RecordUser> ptr = it->second;
		if (ptr->serverid == dwServerID) {
			return ptr;
		}
		if (ptr->serverid == 0) {
			ptr->serverid = dwServerID;
			return ptr;
		}
	}
	return RecordUserPtr((RecordUser*)0);
}

bool RecordUserM::existAccid(const uint32_t accid){
	boost::mutex::scoped_lock lock(mutex_);
	RecordUserHashmap::const_iterator it = userMap.find(accid);
	return (it!=userMap.end());
}

void RecordUserM::checkAndSave(){
}

bool RecordUserM::empty(){
	removeAllByServerID(0);
	return userMap.empty();
}
