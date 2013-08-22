#include "BillTask.h"
#include "BillServer.h"
#include "BillTaskManager.h"

using namespace boost;

void BillTask::handle_msg(const void* ptr, const uint32_t len){
	MessageQueue::msgParse(ptr, len);
	async_read();
}

bool BillTask::verifyLogin(const Cmd::Bill::t_LoginBill *ptCmd)
{
	Xlogger->info("%s(id=%d type=%u)", __PRETTY_FUNCTION__, ptCmd->wdServerID,ptCmd->wdServerType);
	using namespace Cmd::Bill;

	if (CMD_LOGIN == ptCmd->cmd  && PARA_LOGIN == ptCmd->para) {
		const Cmd::Super::ServerEntry *entry = BillService::getInstance().getServerEntryById(ptCmd->wdServerID);
		if (entry && ptCmd->wdServerType == entry->wdServerType && get_remote_ip() == entry->pstrIP) {
			//remote endpoint serverid servertype 
			wdServerID = ptCmd->wdServerID;
			wdServerType = ptCmd->wdServerType;
			return true;
		}
	}

	return false;
}

void BillTask::handle_verify(const void* pstrCmd, const uint32_t len) {
	using namespace Cmd::Bill;
	if (verifyLogin((t_LoginBill *)pstrCmd)) {
		Xlogger->debug("%s ok", __PRETTY_FUNCTION__);
		if (uniqueAdd())
		{
			set_state(state_okay_);
			return ;
		}
	}
	Xlogger->debug("%s failed", __PRETTY_FUNCTION__);
}

/**
 * \brief 确认一个服务器连接的状态是可以回收的
 *
 * 当一个连接状态是可以回收的状态,那么意味着这个连接的整个生命周期结束,可以从内存中安全的删除了：）<br>
 * 实现了虚函数<code>zTCPTask::recycleConn</code>
 *
 * \return 是否可以回收
 */
int BillTask::recycleConn()
{
	Xlogger->debug("BillTask::recycleConn, close server:%u",getID());
	//BillSessionManager::getInstance().removeAllByServerID(getID());
	//BillUserM::getMe().removeAllByServerID(getID());
	//TODO 需要保证存档指令处理完成了
	return 1;
}

bool BillTask::uniqueAdd(){
	return BillTaskManager::getInstance().uniqueAdd(boost::dynamic_pointer_cast<BillTask>(shared_from_this()));
}

bool BillTask::uniqueRemove(){
	return BillTaskManager::getInstance().uniqueRemove(boost::dynamic_pointer_cast<BillTask>(shared_from_this()));
}

/*
bool BillTask::msgParse_Scene(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen) {
	Xlogger->debug("BillTask::msgParse_Scene");
	using namespace Cmd::Bill;

	Xlogger->error("BillTask::msgParse_Scene(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}
*/

bool BillTask::cmdMsgParse(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen) {
	using namespace Cmd::Bill;

	switch(pNullCmd->cmd)
	{
		/*
		case CMD_GATE:
			{
				switch(pNullCmd->para)
				{
					case PARA_GATE_LOGOUT:
						{
							t_Logout_Gateway *ptCmd = (t_Logout_Gateway *)pNullCmd;

							Xlogger->debug("[bill],0,0,0,靠靠靠 %u,%u",ptCmd->accid,ptCmd->loginTempID);
							shared_ptr<BillUser> pUser=BillUserManager::getInstance()->getUserByID(ptCmd->accid);
							if (pUser) {
								pUser->logout(ptCmd->loginTempID);
							}

							return true;
						}
						break;
					case PARA_GATE_LOGINVERIFY:
						{
							t_LoginVerify_Gateway *ptCmd = (t_LoginVerify_Gateway *)pNullCmd;
							t_LoginVerify_Gateway_Return tCmd;

							tCmd.accid = ptCmd->accid;
							tCmd.loginTempID = ptCmd->loginTempID;
							BillUser *pUser=BillUserManager::getInstance()->getUserByID(ptCmd->accid);
							if (pUser && pUser->login(ptCmd->loginTempID))
							{
								//ok
								tCmd.retcode = 1;
							}
							else
							{
								//fail
								tCmd.retcode = 0;
							}

							return sendCmd(&tCmd,sizeof(tCmd));
						}
					default:
						break;
				}
			}
			break;
		case CMD_FORWARD:
			{
				switch(pNullCmd->para)
				{
					case PARA_SCENE_FORWARD_BILL:
						{
							const t_Scene_ForwardBill *ptCmd = (const t_Scene_ForwardBill *)pNullCmd;
							shared_ptr<BillUser> pUser=BillUserManager::getInstance()->getUserByID(ptCmd->dwAccid);
							if (pUser) {
								pUser->usermsgParseScene((Cmd::t_NullCmd *)ptCmd->data,ptCmd->size);
							}
						}
						break;
					case PARA_FORWARD_BILL:
						{
							const t_Bill_ForwardBill *ptCmd = (const t_Bill_ForwardBill *)pNullCmd;
							shared_ptr<BillUser> pUser=BillUserManager::getInstance()->getUserByID(ptCmd->dwAccid);
							if (pUser) {
								pUser->usermsgParse((Cmd::t_NullCmd *)ptCmd->data,ptCmd->size);
							}
						}
						break;
					default:
						break;
				}
				return true;
			}
			break;
			*/
#if 0
		case CMD_REDEEM:
			{
				//补偿金币
				switch(pNullCmd->para)
				{
					case PARA_REQUEST_GATE_REDEEM_GOLD:
						{
							t_Request_Redeem_Gold_Gateway *ptCmd = (t_Request_Redeem_Gold_Gateway *)pNullCmd;
							BillUser *pUser=BillUserManager::getInstance()->getUserByID(ptCmd->accid);
							if (pUser)
							{
								if (!ptCmd->point)
								{
									Xlogger->debug("兑换指令点数为0(%s)",ptCmd->account);
									return true;
								}
								BillData bd;
								bzero(&bd,sizeof(bd));
								//strncpy(bd.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								bd.uid=ptCmd->accid;
								bd.at = Cmd::UserServer::AT_CONSUME;
								bd.point = ptCmd->point;
								strncpy(bd.ip,pUser->getIp(),sizeof(bd.ip));

								if (Bill_action(&bd))
								{
									if (!pUser->begin_tid(bd.tid))
									{
										Xlogger->debug("添加兑换金币流水错误%s",ptCmd->account);
									}
									else
									{
										return true;
									}
								}
								else
								{
									Xlogger->debug("兑换金币错误Bill_action%s",ptCmd->account);
								}
								t_Redeem_Gold_Gateway rgg; 
								strncpy(rgg.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								rgg.accid=ptCmd->accid;              /// 账号编号
								rgg.charid=ptCmd->charid;        /// 角色ID
								rgg.dwGold=0;        ///   当前拥有金币数
								rgg.dwBalance=0;        ///   当前拥有金币数
								rgg.byReturn= Cmd::REDEEM_FAIL;  //返回类型
								sendCmd(&rgg,sizeof(rgg));
							}
							else
							{
								Xlogger->debug("收到兑换金币指令,但是用户不存在%s(%d)",ptCmd->account,ptCmd->accid);
							}
							return true;
						}
						break;
					case PARA_REQUEST_GATE_REDEEM_MONTH_CARD:
						{
							t_Request_Redeem_MonthCard_Gateway *ptCmd = (t_Request_Redeem_MonthCard_Gateway *)pNullCmd;
							BillUser *pUser=BillUserManager::getInstance()->getUserByID(ptCmd->accid);
							if (pUser)
							{
								BillData bd;
								bzero(&bd,sizeof(bd));
								//strncpy(bd.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								bd.uid=ptCmd->accid;
								bd.at = Cmd::UserServer::AT_MCARD;
								strncpy(bd.ip,pUser->getIp(),sizeof(bd.ip));

								if (Bill_action(&bd))
								{
									if (!pUser->begin_tid(bd.tid))
									{
										Xlogger->debug("添加兑换月卡流水错误%s",ptCmd->account);
									}
									else
									{
										return true;
									}
								}
								else
								{
									Xlogger->debug("兑换月卡错误Bill_action%s",ptCmd->account);
								}
								t_Redeem_MonthCard_Gateway rgg; 
								strncpy(rgg.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								rgg.accid=ptCmd->accid;              /// 账号编号
								rgg.charid=ptCmd->charid;        /// 角色ID
								rgg.dwNum=0;        ///   当前拥有金币数
								rgg.dwBalance=0;        ///   当前拥有金币数
								rgg.byReturn= Cmd::REDEEM_FAIL;  //返回类型
								sendCmd(&rgg,sizeof(rgg));
							}
							else
							{
								Xlogger->debug("收到兑换月卡指令,但是用户不存在%s(%d)",ptCmd->account,ptCmd->accid);
							}
							return true;
						}
						break;
					case PARA_GATE_REQUECT_CARD_GOLD:
						{

							t_Request_Card_Gold_Gateway *ptCmd = (t_Request_Card_Gold_Gateway *)pNullCmd;
							t_Return_Card_Gold rcg; 
							strncpy(rcg.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
							rcg.accid=ptCmd->accid;              /// 账号编号
							rcg.charid=ptCmd->charid;        /// 角色ID
							//rcg.dwMonthCard = BillManager::getInstance().getVipTime(ptCmd->accid);  //月卡
							//rcg.dwGold = (DWORD)BillManager::getInstance().getGold(ptCmd->accid);  //金币
							rcg.byReturn= Cmd::REDEEM_SUCCESS;  //返回类型
							sendCmd(&rcg,sizeof(rcg));
							return true;
						}
						break;
					case PARA_GATE_REQUECT_POINT:
						{

							t_Request_Point_Gateway *ptCmd = (t_Request_Point_Gateway *)pNullCmd;
							BillUser *pUser=BillUserManager::getInstance()->getUserByID(ptCmd->accid);
							if (pUser)
							{
								pUser->restoregold();
								BillData bd;
								bzero(&bd,sizeof(bd));
								//strncpy(bd.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								bd.uid=ptCmd->accid;
								bd.at = Cmd::UserServer::AT_QBALANCE;
								strncpy(bd.ip,pUser->getIp(),sizeof(bd.ip));

								if (Bill_action(&bd))
								{
									Xlogger->debug("tradeSN:%s",bd.tid);
									if (!pUser->begin_tid(bd.tid))
									{
										Xlogger->debug("添加查询剩余点数流水错误%s",ptCmd->account);
									}
									else
									{
										return true;
									}
								}
								else
								{
									Xlogger->debug("查询剩余点数错误Bill_action%s",ptCmd->account);
								}
								t_Return_Point rpg; 
								strncpy(rpg.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								rpg.accid=ptCmd->accid;              /// 账号编号
								rpg.charid=ptCmd->charid;        /// 角色ID
								rpg.dwPoint=0;        ///   当前点数
								rpg.byReturn= Cmd::REDEEM_FAIL;  //返回类型
								sendCmd(&rpg,sizeof(rpg));
							}
							else
							{
								Xlogger->debug("收到查询月卡点数指令,但是用户不存在%s(%d)",ptCmd->account,ptCmd->accid);
							}
							return true;
						}
						break;
					case PARA_GATE_CONSUME_CARD:
						{
							stConSumeCardCard_Gateway *ptCmd = (stConSumeCardCard_Gateway *)pNullCmd; 
							//Xlogger->debug("%s(%d)请求消费道具卡:%s",this->account,this->id,rev->cardid);
							BillUser *pUser=BillUserManager::getInstance()->getUserByID(ptCmd->accid);
							if (pUser)
							{
								pUser->restorecard();
								BillData bd;
								bzero(&bd,sizeof(bd));
								//strncpy(bd.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								bd.uid=ptCmd->accid;
								switch(ptCmd->type)
								{
									case Cmd::ZONE_CARD_OBJECT:
										{
											bd.at = Cmd::UserServer::AT_PCARD;
										}
										break;
									case Cmd::ZONE_CARD_PROFRESSION:
										{
											bd.at = Cmd::UserServer::AT_SCARD;
										}
										break;
									default:
										break;
								}
								strncpy(bd.ip,pUser->getIp(),sizeof(bd.ip));
								bzero(bd.cardid,sizeof(bd.cardid));
								strncpy(bd.cardid,ptCmd->cardid,sizeof(ptCmd->cardid));

								if (Bill_action(&bd))
								{
									Xlogger->debug("tradeSN:%s",bd.tid);
									if (!pUser->begin_tid(bd.tid))
									{
										Xlogger->debug("添加消费道具卡流水错误%s",ptCmd->account);
									}
									else
									{
										return true;
									}
								}
								else
								{
									Xlogger->debug("消费道具卡错误Bill_action%s",ptCmd->account);
								}
								t_Return_Point rpg; 
								strncpy(rpg.account,ptCmd->account,Cmd::UserServer::ID_MAX_LENGTH);
								rpg.accid=ptCmd->accid;              /// 账号编号
								rpg.dwPoint=0;        ///   当前点数
								rpg.byReturn= Cmd::REDEEM_FAIL;  //返回类型
								sendCmd(&rpg,sizeof(rpg));
							}
							else
							{
								Xlogger->debug("收到查询月卡点数指令,但是用户不存在%s(%d)",ptCmd->account,ptCmd->accid);
							}
							return true;
							Xlogger->debug("请求消费道具卡:%s",ptCmd->cardid);
							return  true;
						}
						break;
				}
			}
			break;
#endif
		default:
			break;
	}

	Xlogger->error("BillTask::cmdMsgParse(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

bool BillTask::sendCmdToScene(const uint32_t id,const void *pstrCmd,const DWORD nCmdLen) {
	using namespace Cmd::Bill;
	using namespace Cmd;

	BYTE buf[MAX_MSG_SIZE];
	t_Bill_ForwardBillToScene *scmd=(t_Bill_ForwardBillToScene *)buf;
	constructInPlace(scmd);

	scmd->id=id;
	scmd->size=nCmdLen;
	memcpy(scmd->data,pstrCmd,nCmdLen);
	return sendCmd(scmd,sizeof(t_Bill_ForwardBillToScene)+nCmdLen);
}

bool BillTask::sendCmdToUser(const uint32_t id,const void *pstrCmd,const DWORD nCmdLen) {
	using namespace Cmd::Bill;
	using namespace Cmd;

	BYTE buf[MAX_MSG_SIZE];
	t_Bill_ForwardUser *scmd=(t_Bill_ForwardUser *)buf;
	constructInPlace(scmd);

	scmd->dwAccid=id;
	scmd->size=nCmdLen;
	memcpy(scmd->data,pstrCmd,nCmdLen);
	return sendCmd(scmd,sizeof(t_Bill_ForwardUser)+nCmdLen);
}

