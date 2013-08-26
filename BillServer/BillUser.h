#pragma once

#include "common.h"
#include <boost/date_time/posix_time/posix_time.hpp>	//for ptime
#include "BillTask.h"
using namespace boost::posix_time;

class BillUser //:public zEntry 
{
  public:
    enum LoginState
    {
      WAIT_LOGIN,   /**< 等待通过登陆验证的客户端登陆网关服务器 */
      CONF_LOGIN,   /**< login to gatewayserver success*/
      CONF_LOGOUT, /**< wait to quit */
      WAIT_LOGIN_TIMEOUT,
    }
    state;          /**< session state */ 
  private:
    static const int session_timeout_value = 10;
    //DWORD loginTempID;        /**< 登陆临时编号 */


    DWORD gold;    /**< 金币数量 */
    DWORD money;    /**< 银币数量 */
    DWORD all_in_gold;    /**< 总冲值金币数量 */
    DWORD all_in_money;    /**< 总冲值银币数量 */
    DWORD all_out_gold;    /**< 总提取金币数量 */
    DWORD all_out_money;    /**< 总提取银币数量 */
    DWORD all_tax_gold;    /**< 总税收 */
    DWORD all_tax_money;  /**< 总税收 */ 
    DWORD vip_time;    /**< vip到期时间 */

    ptime timestamp;

    /// 交易
    char   tid[Cmd::UserServer::SEQ_MAX_LENGTH+1];                     /// 交易流水号

    /// 密码
    char password[MAX_PASSWORD+1];
    /// 是否已经登陆
    bool stock_login;
    DWORD goldlistNum;  /// 个人股票卖单数量
    DWORD moneylistNum;  /// 个人股票买单数量
    //char     client_ip[MAX_IP_LENGTH];              //客户请求ip
	DWORD client_ip;
  public:
    const char *getIp();
    char account[Cmd::UserServer::ID_MAX_LENGTH+1];
    shared_ptr<BillTask> gatewaytask;
    BillUser(DWORD acc,DWORD logintemp,const char *count,const DWORD ip,shared_ptr<BillTask> gate);
    void increaseGoldListNum();
    void increaseMoneyListNum();
    void decreaseGoldListNum();
    void decreaseMoneyListNum();


    bool sendCmd(const void *pstrCmd,const int nCmdLen)
    {
      if (gatewaytask)
      {
        return gatewaytask->sendCmd(pstrCmd,nCmdLen);
      }
      return false;
    }
    bool sendCmdToMe(const void *pstrCmd,const int nCmdLen)
    {
      if (gatewaytask)
      {
        return gatewaytask->sendCmdToUser(id,pstrCmd,nCmdLen);
      }
      return false;
    }
    bool sendCmdToScene(const void *pstrCmd,const int nCmdLen)
    {
      if (gatewaytask)
      {
        return gatewaytask->sendCmdToScene(id,pstrCmd,nCmdLen);
      }
      return false;
    }

    bool restoregold();
    bool restorecard();
    static bool redeem_gold_err(const BillData* bd);
    static bool redeem_object_card_err(const BillData* bd);
    bool login(const DWORD loginTempID);
    bool logout(const DWORD loginTempID);
    bool query_point(const BillData* bd);
    bool redeem_gold(const BillData* bd);
    bool redeem_moth_card(const BillData* bd);
    bool redeem_object_card(const BillData* bd);
    bool begin_tid(const char *t);
    bool putList(DWORD num,DWORD price,BYTE type);
    bool addGold(DWORD num,const char *disc,bool transfer=false,bool tax=false);
    bool addMoney(DWORD num,const char *disc,bool transfer=false,bool tax=false);
    bool removeGold(DWORD num,const char *disc,bool transfer=false,bool tax=false);
    bool removeMoney(DWORD num,const char *disc,bool transfer=false,bool tax=false);
    static DWORD getRealMinTime();
    static void logger(const char *coin_type,DWORD acc,const char *act,DWORD cur,DWORD change,DWORD type,const char *action);
    void end_tid();
    DWORD loginTimeOut(zTime current);
    bool usermsgParse(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
    bool usermsgParseScene(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
  private:
    bool check_tid(const char *t);
    bool checkStockLogin();
};
