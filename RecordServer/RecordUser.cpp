#include "RecordUser.h"
#include "RecordServer.h"
#include "RecordTask.h"
#include <string.h>

RecordUser::RecordUser(){
	accid = charid = serverid = role_size = 0;
	memset(role, 0, sizeof(role));
}

RecordUser::~RecordUser(){
}

bool RecordUser::readCharbase(){
	return false;
}

bool RecordUser::readCharbase(RecordTask* task, uint32_t dwMapID){
	return false;
}

bool RecordUser::saveCharbase(const Cmd::Record::t_WriteUser_SceneRecord * rev){
	return false;
}

bool RecordUser::saveCharbase(){
	return false;
}

bool RecordUser::refreshSaveBase(const Cmd::Record::t_WriteUser_SceneRecord * rev){
	return false;
}
