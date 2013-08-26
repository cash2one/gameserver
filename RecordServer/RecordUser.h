#pragma once

#include "common.h"
#include <map>
#include <vector>
#include <boost/utility.hpp>
#include <boost/thread/mutex.hpp>
#include "recordcmd.h"

class RecordTask;

class RecordUser : boost::noncopyable{
public:
	RecordUser();
	~RecordUser();
	uint32_t accid;
	uint32_t charid;
	uint32_t serverid;
	uint32_t mapTempID;

	bool readCharbase();
	bool readCharbase(RecordTask* task, uint32_t dwMapID);
	bool saveCharbase();
	bool refreshSaveBase(const Cmd::Record::t_WriteUser_SceneRecord *rev);
	static bool saveCharbase(const Cmd::Record::t_WriteUser_SceneRecord * rev);

	const uint8_t* getRole()const { return role; }
	const uint32_t getRoleSize() const { return role_size; }
private:
	boost::mutex mutex;
	uint32_t role_size;
	uint8_t role[MAX_MSG_SIZE];
};

typedef boost::shared_ptr<RecordUser> RecordUserPtr;
