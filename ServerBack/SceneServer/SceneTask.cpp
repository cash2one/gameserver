#include "SceneTask.h"
#include "SceneServer.h"

void SceneTask::handle_msg(const void* ptr, const uint32_t len){
	MessageQueue::msgParse(ptr, len);
	async_read();
}

bool SceneTask::verifyLogin(const Cmd::Scene::t_LoginScene *ptCmd)
{
	Xlogger->info("SceneTask::verifyLogin(id=%d type=%u)",ptCmd->wdServerID,ptCmd->wdServerType);
	using namespace Cmd::Scene;

	if (CMD_LOGIN == ptCmd->cmd  && PARA_LOGIN == ptCmd->para) {
		const Cmd::Super::ServerEntry *entry = SceneService::getInstance().getServerEntryById(ptCmd->wdServerID);
		if (entry && ptCmd->wdServerType == entry->wdServerType && get_remote_ip() == entry->pstrIP) {
			//remote endpoint serverid servertype 
			wdServerID = ptCmd->wdServerID;
			wdServerType = ptCmd->wdServerType;
			return true;
		}
	}

	return false;
}

void SceneTask::handle_verify(const void* pstrCmd, const uint32_t len) {
	using namespace Cmd::Scene;
	if (verifyLogin((t_LoginScene *)pstrCmd)) {
		Xlogger->debug("%s ok", __PRETTY_FUNCTION__);
		if (uniqueAdd())
		{
			set_state(state_okay_);
			return ;
		}
	}
	Xlogger->debug("%s failed", __PRETTY_FUNCTION__);
}

int SceneTask::recycleConn()
{
	Xlogger->debug("SceneTask::recycleConn, close server:%u",getID());
	//SceneSceneManager::getInstance().removeAllByServerID(getID());
	//SceneUserM::getMe().removeAllByServerID(getID());
	//TODO 需要保证存档指令处理完成了
	return 1;
}
bool SceneTask::msgParse_Scene(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->debug("SceneTask::msgParse_Scene");

	using namespace Cmd::Scene;

	switch(pNullCmd->para)
	{
		/*
		case PARA_CHK_USER_EXIST:
			{
				t_chkUserExist_SceneScene *rev = (t_chkUserExist_SceneScene *)pNullCmd;
				connHandleID handle = SceneService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					return false;
				}
#pragma pack(1)
				struct exist_struct
				{
					DWORD id;
					DWORD level;
					char name[MAX_NAMESIZE+1];
				};// __attribute__ ((packed));
#pragma pack()
				static const dbCol exist_define[] = {
					{ "`CHARID`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`LEVEL`",zDBConnPool::DB_DWORD,sizeof(DWORD) },
					{ "`NAME`",zDBConnPool::DB_STR,sizeof(char[MAX_NAMESIZE+1]) },
					{ NULL,0,0}
				};
				exist_struct * es;
				char where[128];
				bzero(where,sizeof(where));

				std::string escapeName;
				_snprintf(where,sizeof(where) - 1,"NAME='%s'",
						SceneService::dbConnPool->escapeString(handle,rev->name,escapeName).c_str());

				DWORD retcode = SceneService::dbConnPool->exeSelect(handle,"`CHARBASE`",exist_define,where,"CHARID DESC",(BYTE **)&es);
				SceneService::dbConnPool->putHandle(handle);

				if (es)
				{
					for (DWORD i=0; i< retcode; i++)
					{
						if (strcmp(es[i].name,rev->name) == 0)
						{
							rev->user_id = es[i].id;
							rev->user_level = es[i].level;
							break;
						}
					}
					SAFE_DELETE_VEC(es);
					sendCmd(rev,sizeof(t_userExist_SceneScene));
				}
				return true;
			}
			*/
		default:
			break;
	}

	Xlogger->error("SceneTask::msgParse_Scene(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool SceneTask::msgParse_Gateway(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->debug("SceneTask::msgParse_Gateway");
	using namespace Cmd::Scene;

	switch(pNullCmd->para)
	{
		/*
		case PARA_GATE_DELCHAR:
			{
				t_DelChar_GateScene *rev = (t_DelChar_GateScene *)pNullCmd;
				t_DelChar_Return_GateScene cmd;
				char where[128];

				cmd.accid = rev->accid;
				cmd.id = rev->id;
				strncpy(cmd.name,rev->name,sizeof(cmd.name));
				cmd.retcode = 0;

				connHandleID handle = SceneService::dbConnPool->getHandle();
				if ((connHandleID)-1 == handle)
				{
					Xlogger->error("不能获取数据库句柄");
					sendCmd(&cmd,sizeof(cmd));
					return false;
				}

				//首先删除原来已经作废的角色
				bzero(where,sizeof(where));
				_snprintf(where,sizeof(where) - 1,"ACCID = %u AND CHARID = %u",rev->accid,rev->id);
				if ((DWORD)-1 == SceneService::dbConnPool->exeDelete(handle,"`CHARBASE`",where))
				{
					SceneService::dbConnPool->putHandle(handle);
					sendCmd(&cmd,sizeof(cmd));
					Xlogger->warn("删除角色时失败:%u,%u",rev->accid,rev->id);
					return false;
				}

				SceneService::dbConnPool->putHandle(handle);
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
				connHandleID handle = SceneService::dbConnPool->getHandle();
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
				t_order_Country_GateScene *ret_gate = 
					(t_order_Country_GateScene*)Buf;
				constructInPlace(ret_gate);
				DWORD retcode=0; 
				char where[128];
				bzero(where,sizeof(where));

				strncpy(where,"SELECT `COUNTRY` `A`,count(`COUNTRY`)  AS `A` FROM `CHARBASE` GROUP BY `COUNTRY` ORDER BY `A`",sizeof(where));
				retcode = SceneService::dbConnPool->execSelectSql(handle,
						where,strlen(where),countryid_define,(DWORD)10,(BYTE*)(ret_gate->order.order));

				SceneService::dbConnPool->putHandle(handle);
				if (retcode != (DWORD)-1)
				{
					ret_gate->order.size = retcode;
				}
				for(int i = 0 ; i < (int)ret_gate->order.size ; i ++)
				{
					Xlogger->debug("国家:%d,注册人数:%d",ret_gate->order.order[i].country,ret_gate->order.order[i].count);
				}
				sendCmd(ret_gate,sizeof(t_order_Country_GateScene) 
						+ sizeof(ret_gate->order.order[0]) * ret_gate->order.size); 
				return true;
			}
			break;
			*/
		/*
		case PARA_GATE_CHECKNAME:
			{
				t_CheckName_GateScene * rev = (t_CheckName_GateScene *)pNullCmd;
				t_CheckName_Return_GateScene ret;
				ret.accid = rev->accid;
				strncpy(ret.name,rev->name,MAX_NAMESIZE-1);
				//首先验证名称是否重复

				connHandleID handle = SceneService::dbConnPool->getHandle();
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
				SceneService::dbConnPool->escapeString(handle,rev->name,upName);

				_snprintf(where,sizeof(where) - 1,"NAME = '%s'",upName.c_str());
				DWORD retcode = SceneService::dbConnPool->exeSelectLimit(handle,"`CHARBASE`",verifyname_define,where,"CHARID DESC",1,(BYTE*)(strName));

				SceneService::dbConnPool->putHandle(handle);
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
				t_CreateChar_GateScene *rev = (t_CreateChar_GateScene *)pNullCmd;
				t_CreateChar_Return_GateScene ret;
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
				connHandleID handle = SceneService::dbConnPool->getHandle();
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
				DWORD retcode = SceneService::dbConnPool->exeSelectLimit(handle,"`ACCPRIV`",priv_define,where,NULL,1,(BYTE*)(&createchar_data.accPriv));
				retcode = SceneService::dbConnPool->exeInsert(handle,"`CHARBASE`",createchar_define,(const BYTE *)(&createchar_data));
				SceneService::dbConnPool->putHandle(handle);
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
				t_Get_SelectInfo_GateScene *rev= (t_Get_SelectInfo_GateScene *)pNullCmd;
				return getSelectInfo(rev->accid,rev->countryid); 
			}
			break;
			*/
	}

	Xlogger->error("SceneTask::msgParse_Gateway(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

/**
 * \brief 解析来自各个服务器连接的指令
 *
 * \param pNullCmd 待处理的指令
 * \param nCmdLen 指令长度
 * \return 处理是否成功
 */
bool SceneTask::cmdMsgParse(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
{
	using namespace Cmd::Scene;

	switch(pNullCmd->cmd)
	{
		case CMD_GATE:
			if (msgParse_Gateway(pNullCmd,nCmdLen))
			{
				return true;
			}
			break;
		case CMD_SESSION:
			if (msgParse_Scene(pNullCmd,nCmdLen))
			{
				return true;
			}
			break;
	}

	Xlogger->error("SceneTask::msgParse(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

