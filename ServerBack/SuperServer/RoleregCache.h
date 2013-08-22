#pragma once
#include "common.h"
#include <set>

enum NetType
{
  NetType_near = 0,//近程路由，电信区连电信服务器，网通区连网通服务器
  NetType_far = 1,  //远端路由，电信区连网通服务器，网通区连电信服务器
};


/**
 * \brief 保存服务器之间的依赖关系
 *
 */
extern hash_map<int,std::vector<int> > serverSequence;

/**
 * \brief 初始化服务器之间的依赖关系
  
   gcc 
 *
 */
void initServerSequence();




class RoleregCache
{

  public:

    struct Data
    {
      WORD wdServerID;      /**< 服务器编号 */
      DWORD accid;        /**< 账号编号 */
      char name[MAX_NAMESIZE];  /**< 角色名称 */
      WORD state;          /**< 各种状态的位组合 */

      Data(const Cmd::Super::t_Charname_Gateway &cmd)
      {
        wdServerID = cmd.wdServerID;
        accid = cmd.accid;
        strncpy(name,cmd.name,sizeof(name));
        state = cmd.state;
      }

      Data(const Data &data)
      {
        wdServerID = data.wdServerID;
        accid = data.accid;
        strncpy(name,data.name,sizeof(name));
        state = data.state;
      }

      Data &operator=(const Data &data)
      {
        wdServerID = data.wdServerID;
        accid = data.accid;
        strncpy(name,data.name,sizeof(name));
        state = data.state;
        return *this;
      }
    };

    ~RoleregCache() {};

    static RoleregCache &getInstance()
    {
      if (NULL == instance)
        instance = new RoleregCache();

      return *instance;
    }

    static void delInstance()
    {
      SAFE_DELETE(instance);
    }

    void add(const Cmd::Super::t_Charname_Gateway &cmd);
    void timeAction(const zTime &ct);

    bool msgParse_loginServer(WORD wdServerID,DWORD accid,char name[MAX_NAMESIZE],WORD state);

  private:

    RoleregCache() {};

    static RoleregCache *instance;

    zTime actionTimer;

    typedef std::list<Data> DataCache;
    zMutex mlock;
    DataCache datas;

};

