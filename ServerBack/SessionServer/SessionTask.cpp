#include "SessionTask.h"
#include "SessionServer.h"
#include "sessioncmd.h"
#include "ServerManager.h"

bool SessionTask::uniqueAdd()
{
	return ServerManager::getInstance().uniqueAdd(boost::dynamic_pointer_cast<SessionTask>(shared_from_this()));
}

bool SessionTask::uniqueRemove()
{
	return ServerManager::getInstance().uniqueRemove(boost::dynamic_pointer_cast<SessionTask>(shared_from_this()));
}

void SessionTask::addToContainer()
{
	ServerManager::getInstance().addServer(boost::dynamic_pointer_cast<SessionTask>(shared_from_this()));
	//can notify other servers below
}

void SessionTask::removeFromContainer()
{
	//if gatewayserver is closed, notify login server to close gateway
	/*
	if (GATEWAYSERVER == se_.wdServerType)
	{
		Cmd::FL::t_GYList_FL tCmd;

		tCmd.wdServerID = se_.wdServerID;
		bzero(tCmd.pstrIP,sizeof(tCmd.pstrIP));
		tCmd.wdPort = 0;
		tCmd.wdNumOnline = 0;
		tCmd.state = state_maintain;
		tCmd.zoneGameVersion = 0;

		Xlogger->info("gatewayserver is shutdown,send state_maintain to FLServer !");

		//FLClientManager::getInstance().broadcast(&tCmd,sizeof(tCmd));
	}
	*/

	ServerManager::getInstance().removeServer(boost::dynamic_pointer_cast<SessionTask>(shared_from_this()));
}

void SessionTask::handle_msg(const void* ptr, const uint32_t len){
	MessageQueue::msgParse(ptr, len);
	async_read();
}

bool SessionTask::verifyLogin(const Cmd::Session::t_LoginSession *ptCmd)
{
	Xlogger->info("SessionTask::verifyLogin(id=%d type=%u)",ptCmd->wdServerID,ptCmd->wdServerType);
	using namespace Cmd::Session;

	if (CMD_LOGIN == ptCmd->cmd  && PARA_LOGIN == ptCmd->para) {
		const Cmd::Super::ServerEntry *entry = SessionService::getInstance().getServerEntryById(ptCmd->wdServerID);
		if (entry && ptCmd->wdServerType == entry->wdServerType && get_remote_ip() == entry->pstrIP) {
			//remote endpoint serverid servertype 
			wdServerID = ptCmd->wdServerID;
			wdServerType = ptCmd->wdServerType;
			return true;
		}
	}

	return false;
}

void SessionTask::handle_verify(const void* pstrCmd, const uint32_t len) {
	using namespace Cmd::Session;
	if (verifyLogin((t_LoginSession *)pstrCmd)) {
		Xlogger->debug("%s ok", __PRETTY_FUNCTION__);
		set_state(state_okay_);
		return ;
	}
	Xlogger->debug("%s failed", __PRETTY_FUNCTION__);
}

int SessionTask::recycleConn()
{
	Xlogger->debug("SessionTask::recycleConn, close server:%u",getID());
	//SessionSessionManager::getInstance().removeAllByServerID(getID());
	//SessionUserM::getMe().removeAllByServerID(getID());
	//TODO 需要保证存档指令处理完成了
	return 1;
}

bool SessionTask::msgParse_Gateway(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->debug("SessionTask::msgParse_Gateway");
	using namespace Cmd::Session;

	switch(pNullCmd->para)
	{
		case Cmd::Session::PARA_GATE_SESSION_TEST:
			{
				Xlogger->debug("Cmd::Session::PARA_GATE_SESSION_TEST: get msg from id=%u",getID());
				t_GatewaySession_Test cmd;
				sendCmd(&cmd, sizeof(cmd));
				return true;
			}
			break;
		/*
		case PARA_GATE_DELCHAR:
			{
				t_DelChar_GateSession *rev = (t_DelChar_GateSession *)pNullCmd;
				t_DelChar_Return_GateSession cmd;
				char where[128];

				cmd.accid = rev->accid;
				cmd.id = rev->id;
				strncpy(cmd.name,rev->name,sizeof(cmd.name));
				cmd.retcode = 0;

				connHandleID handle = SessionService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					sendCmd(&cmd,sizeof(cmd));
					return false;
				}

				//首先删除原来已经作废的角色
				bzero(where,sizeof(where));
				_snprintf(where,sizeof(where) - 1,"ACCID = %u AND CHARID = %u",rev->accid,rev->id);
				if ((DWORD)-1 == SessionService::dbConnPool->exeDelete(handle,"`CHARBASE`",where))
				{
					SessionService::dbConnPool->putHandle(handle);
					sendCmd(&cmd,sizeof(cmd));
					Xlogger->warn("删除角色时失败:%u,%u",rev->accid,rev->id);
					return false;
				}

				SessionService::dbConnPool->putHandle(handle);
				Xlogger->info("删除角色:%u,%u",rev->accid,rev->id);

				cmd.retcode = 1;
				sendCmd(&cmd,sizeof(cmd));
				//删除角色后重新得到角色列表
				return getSelectInfo(rev->accid,rev->countryid); 

				return true;
			}
			break;
			*/
			//请求国家档案排序
		/*
		case REQUEST_GATE_COUNTRY_ORDER:
			{
				connHandleID handle = SessionService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					return false;
				}

				static const dbCol countryid_define[] = {
					{ "`COUNTRY`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`A`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ NULL,0,0}
				};
				char Buf[200];
				bzero(Buf,sizeof(Buf));
				t_order_Country_GateSession *ret_gate = 
					(t_order_Country_GateSession*)Buf;
				constructInPlace(ret_gate);
				DWORD retcode=0; 
				char where[128];
				bzero(where,sizeof(where));

				strncpy(where,"SELECT `COUNTRY` `A`,count(`COUNTRY`)  AS `A` FROM `CHARBASE` GROUP BY `COUNTRY` ORDER BY `A`",sizeof(where));
				retcode = SessionService::dbConnPool->execSelectSql(handle,
						where,strlen(where),countryid_define,(DWORD)10,(BYTE*)(ret_gate->order.order));

				SessionService::dbConnPool->putHandle(handle);
				if (retcode != (DWORD)-1)
				{
					ret_gate->order.size = retcode;
				}
				for(int i = 0 ; i < (int)ret_gate->order.size ; i ++)
				{
					Xlogger->debug("国家:%d,注册人数:%d",ret_gate->order.order[i].country,ret_gate->order.order[i].count);
				}
				sendCmd(ret_gate,sizeof(t_order_Country_GateSession) 
						+ sizeof(ret_gate->order.order[0]) * ret_gate->order.size); 
				return true;
			}
			break;
			*/
		/*
		case PARA_GATE_CHECKNAME:
			{
				t_CheckName_GateSession * rev = (t_CheckName_GateSession *)pNullCmd;
				t_CheckName_Return_GateSession ret;
				ret.accid = rev->accid;
				strncpy(ret.name,rev->name,MAX_NAMESIZE-1);
				//首先验证名称是否重复

				connHandleID handle = SessionService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					return false;
				}

				static const dbCol verifyname_define[] = {
					{ "`NAME`",zDBConnPool::DB_STR,sizeof(char[MAX_NAMESIZE+1]) },
					{ NULL,0,0}
				};
				char strName[MAX_NAMESIZE+1];
				char where[128];
				bzero(where,sizeof(where));

				std::string upName;
				SessionService::dbConnPool->escapeString(handle,rev->name,upName);

				_snprintf(where,sizeof(where) - 1,"NAME = '%s'",upName.c_str());
				DWORD retcode = SessionService::dbConnPool->exeSelectLimit(handle,"`CHARBASE`",verifyname_define,where,"CHARID DESC",1,(BYTE*)(strName));

				SessionService::dbConnPool->putHandle(handle);
				Xlogger->debug("角色名检查:%s have %d",upName.c_str(),retcode);

				ret.err_code = retcode;
				sendCmd(&ret,sizeof(ret));
				return true;
			}
			break;
			*/
		/*
		case PARA_GATE_CREATECHAR:
			{
				t_CreateChar_GateSession *rev = (t_CreateChar_GateSession *)pNullCmd;
				t_CreateChar_Return_GateSession ret;
				static const dbCol createchar_define[] = {
					{ "`ACCID`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`NAME`",zDBConnPool::DB_STR,sizeof(char[MAX_NAMESIZE+1]) },
					{ "`TYPE`",zDBConnPool::DB_WORD,sizeof(WORD) },
					{ "`LEVEL`",zDBConnPool::DB_WORD,sizeof(WORD) },
					{ "`HAIR`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`MAPID`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`MAPNAME`",zDBConnPool::DB_STR,sizeof(char[MAX_NAMESIZE+1]) },
					{ "`COUNTRY`",zDBConnPool::DB_WORD,sizeof(WORD) },
					{ "`ACCPRIV`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`CREATEIP`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`GRACE`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`FACE`",zDBConnPool::DB_WORD,sizeof(WORD) },
					{ NULL,0,0}
				};
#pragma pack(1)
				struct {
					DWORD accid;
					char name[MAX_NAMESIZE+1];
					WORD type;
					WORD level;
					DWORD hair;
					DWORD mapid;
					char  mapName[MAX_NAMESIZE+1];
					WORD country;
					DWORD accPriv;
					DWORD createip;
					DWORD useJob; //sky 角色职业
					WORD  face;  // ranqd 角色头像
				}// __attribute__ ((packed))

				createchar_data;
#pragma pack()
				connHandleID handle = SessionService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					return false;
				}

				//检查帐号权限
				static const dbCol priv_define[] = {
					{ "`PRIV`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ NULL,0,0}
				};

				//插入数据库角色信息
				bzero(&createchar_data,sizeof(createchar_data));
				createchar_data.accid = rev->accid;
				strncpy(createchar_data.name,rev->name,MAX_NAMESIZE);
				createchar_data.type = rev->type;
				createchar_data.country = rev->country;
				createchar_data.level = 1;
				createchar_data.hair = rev->hair;
				createchar_data.mapid = 0;
				// [ranqd] 增加职业保存
				createchar_data.useJob = rev->JobType;
				// [ranqd] 增加头像保存
				createchar_data.face   = rev->Face;
				if( createchar_data.useJob <= JOB_NULL || createchar_data.useJob > JOB_PASTOR )
				{
					createchar_data.useJob = JOB_FIGHTER;
				}
				strncpy(createchar_data.mapName,rev->mapName,MAX_NAMESIZE);
				createchar_data.createip = rev->createip;
				//Xlogger->debug("创建角色IP %s(%u)",inet_ntoa(*(struct in_addr*)&createchar_data.createip),createchar_data.createip);
				char where[64];
				bzero(where,sizeof(where));
				_snprintf(where,sizeof(where)-1,"ACCID=%u",rev->accid);
				DWORD retcode = SessionService::dbConnPool->exeSelectLimit(handle,"`ACCPRIV`",priv_define,where,NULL,1,(BYTE*)(&createchar_data.accPriv));
				retcode = SessionService::dbConnPool->exeInsert(handle,"`CHARBASE`",createchar_define,(const BYTE *)(&createchar_data));
				SessionService::dbConnPool->putHandle(handle);
				if ((DWORD)-1 == retcode)
				{
					Xlogger->error("创建角色插入数据库出错 %u,%s",rev->accid,rev->name);

					ret.accid = rev->accid;
					ret.retcode = 0;
					bzero(&ret.charinfo,sizeof(ret.charinfo));
					sendCmd(&ret,sizeof(ret));

					return false;
				}

				//返回新创建角色信息到网关
				ret.accid = rev->accid;
				ret.retcode = 1;
				bzero(&ret.charinfo,sizeof(ret.charinfo));
				ret.charinfo.id = retcode;
				strncpy(ret.charinfo.name,createchar_data.name,MAX_NAMESIZE);
				ret.charinfo.type = createchar_data.type;
				ret.charinfo.level = createchar_data.level;
				ret.charinfo.mapid = createchar_data.mapid;
				ret.charinfo.country = createchar_data.country;
				ret.charinfo.JobType = createchar_data.useJob;
				ret.charinfo.face    = createchar_data.face;
				strncpy(ret.charinfo.mapName,createchar_data.mapName,MAX_NAMESIZE);

				return sendCmd(&ret,sizeof(ret));
			}
			break;
			*/
				/*
		case PARA_GATE_GET_SELECTINFO:
			{
				t_Get_SelectInfo_GateSession *rev= (t_Get_SelectInfo_GateSession *)pNullCmd;
				return getSelectInfo(rev->accid,rev->countryid); 
			}
			break;
			*/
	}

	Xlogger->error("SessionTask::msgParse_Gateway(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool SessionTask::msgParse_Scene(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->debug("SessionTask::msgParse_Scene");
	using namespace Cmd::Session;
	switch(pNullCmd->para)
	{
		case PARA_SCENE_SESSION_TEST:
			{
				Xlogger->debug("get from scene id=%u",getID());
				t_SceneSession_Test cmd;
				sendCmd(&cmd, sizeof(cmd));
				return true;
			}
			break;
	}

	/*
	switch(pNullCmd->para)
	{
		case PARA_SCENE_USER_WRITE:
			{
				t_WriteUser_SceneSession *rev = (t_WriteUser_SceneSession *)pNullCmd;
				if (((TIMETICK_WRITEBACK == rev->writeback_type || OPERATION_WRITEBACK == rev->writeback_type)
							&& SessionSessionManager::getInstance().verify(rev->accid,rev->id,getID()))
						|| (LOGOUT_WRITEBACK == rev->writeback_type
							&& SessionSessionManager::getInstance().remove(rev->accid,rev->id,getID()))
						|| (CHANGE_SCENE_WRITEBACK == rev->writeback_type
							&& SessionSessionManager::getInstance().remove(rev->accid,rev->id,getID())))
				{
					if (saveCharBase(rev))
					{
						if (CHANGE_SCENE_WRITEBACK == rev->writeback_type || LOGOUT_WRITEBACK == rev->writeback_type)
						{
							using namespace Cmd::Session;
							t_WriteUser_SceneSession_Ok ok; 
							ok.type=rev->writeback_type;
							ok.id=rev->id;
							ok.accid=rev->accid;
							sendCmd(&ok,sizeof(ok));
						}
						return true;
					}
				}
				else
				{
					Xlogger->error("回写档案验证失败,不能回写档案：%lu,%lu",rev->accid,rev->id);
				}
			}
			break;
		case PARA_SCENE_USER_READ:
			{
				t_ReadUser_SceneSession *rev = (t_ReadUser_SceneSession *)pNullCmd;
				if (SessionSessionManager::getInstance().add(rev->accid,rev->id,getID()))
				{
					if (readCharBase(rev)) 
					{
						return true;
					}
					else
					{
						SessionSessionManager::getInstance().remove(rev->accid,rev->id,getID());
						return true;
					}
				}
				else
				{
					using namespace Cmd::Session;
					t_UserInfo_SceneSession ret;
					ret.id=rev->id;
					ret.dwMapTempID=rev->dwMapTempID;
					ret.dataSize = (DWORD)PARA_SCENE_USER_READ_ERROR;
					sendCmd(&ret,sizeof(t_UserInfo_SceneSession));
					Xlogger->error("添加读取记录失败,不能读取档案信息：%lu,%lu",rev->accid,rev->id);
					return true;
				}
			}
			break;
		case PARA_SCENE_USER_REMOVE:
			{
				t_RemoveUser_SceneSession *rev = (t_RemoveUser_SceneSession *)pNullCmd;
				SessionSessionManager::getInstance().remove(rev->accid,rev->id,getID());
				Xlogger->warn("用户在读取档案过程中退出(accid=%u,id=%u",rev->accid,rev->id);
				return true;
			}
			break;
		case PARA_SCENE_USER_EXIST:
			{
				t_userExist_SceneSession *rev = (t_userExist_SceneSession *)pNullCmd;

				connHandleID handle = SessionService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					return false;
				}
#pragma pack(1)
				struct exist_struct
				{
					DWORD id;
					char name[MAX_NAMESIZE+1];
				};// __attribute__ ((packed));
#pragma pack()
				static const dbCol exist_define[] = {
					{ "`CHARID`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`NAME`",zDBConnPool::DB_STR,sizeof(char[MAX_NAMESIZE+1]) },
					{ NULL,0,0}
				};
				exist_struct * es;
				char where[128];
				bzero(where,sizeof(where));

				//DWORD len = exist_define[1].size*2 + 1;

				//char *strData = new char[len];
				//bzero(strData,len);
				std::string escapeName;

				//std::ostringstream strSql;

				//SessionService::dbConnPool->escapeString(handle,rev->sm.toName,strData,33);

				//strSql << strData;
				SessionService::dbConnPool->escapeString(handle,rev->sm.toName,escapeName);
				_snprintf(where,sizeof(where) - 1,"NAME='%s'",escapeName.c_str());
				DWORD retcode = SessionService::dbConnPool->exeSelect(handle,"`CHARBASE`",exist_define,where,"CHARID DESC",(BYTE **)&es);
				SessionService::dbConnPool->putHandle(handle);

				if (es)
				{
					for (DWORD i=0; i< retcode; i++)
					{
						if (strcmp(es[i].name,rev->sm.toName))
							continue;

						rev->toID = es[i].id;
					}
					SAFE_DELETE_VEC(es);
				}
				sendCmd(rev,sizeof(t_userExist_SceneSession));
				return true;
			}
			break;
#ifdef _TEST_DATA_LOG
		case PARA_SCENE_INSERT_CHARTEST:
			{
				insertCharTest((t_Insert_CharTest_SceneSession *)pNullCmd);
				return true;
			}
			break;
		case PARA_SCENE_UPDATE_CHARTEST:
			{
				updateCharTest((t_Update_CharTest_SceneSession *)pNullCmd);
				return true;
			}
			break;
		case PARA_SCENE_DELETE_CHARTEST:
			{
				deleteCharTest((t_Delete_CharTest_SceneSession *)pNullCmd);
				return true;
			}
			break;
		case PARA_SCENE_READ_CHARTEST:
			{
				readCharTest((t_Read_CharTest_SceneSession *)pNullCmd);
				return true;
			}
			break;
#endif
		default:
			break;
	}
*/

	Xlogger->error("SessionTask::msgParse_Scene(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool SessionTask::cmdMsgParse(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
{
	using namespace Cmd::Session;

	switch(pNullCmd->cmd)
	{
		case Cmd::Session::CMD_GATE:
			if (msgParse_Gateway(pNullCmd,nCmdLen))
			{
				return true;
			}
			break;
		case Cmd::Session::CMD_SCENE:
			if (msgParse_Scene(pNullCmd,nCmdLen))
			{
				return true;
			}
			break;
	}

	Xlogger->error("SessionTask::msgParse(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

