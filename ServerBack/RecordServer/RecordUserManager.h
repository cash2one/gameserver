#pragma once

#include "singleton.h"
#include "common.h"
#include <boost/unordered_map.hpp>
#include <boost/thread/mutex.hpp>
#include "RecordUser.h"

class RecordUser;

class RecordUserM: public Singleton<RecordUserM>{
	~RecordUserM(){ userMap.clear(); }
	bool init() { return true; }
	bool add(RecordUserPtr u);
	bool verify( const DWORD accid, const DWORD id, const DWORD wdServerID);
	bool remove( const DWORD accid, const DWORD id, const DWORD wdServerID);
	bool remove(RecordUserPtr u);
	bool changeScene(const DWORD accid, const DWORD id, const DWORD wdServerID);
	RecordUserPtr getUserByAccid(const DWORD accid, const DWORD id, const DWORD wdServerID);
	RecordUserPtr getUserForWrite(const DWORD accid, const DWORD serverid);

	bool existAccid(const DWORD accid);
	void removeAllByServerID(const DWORD wdServerID);
	void checkAndSave();
	bool empty();
protected:
	RecordUserM() {}

	typedef boost::unordered_map<DWORD, RecordUserPtr > RecordUserHashmap;
	typedef RecordUserHashmap::iterator RecordUserHashmap_iterator;
	RecordUserHashmap userMap;

	boost::mutex mutex_;
};
