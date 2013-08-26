/**
 * \brief 实现统一用户平台客户端连接的管理容器
 */


#include "SuperServer.h"

/**
 * \brief 类的唯一实例指针
 */
FLClientManager *FLClientManager::instance = NULL;

/**
 * \brief 构造函数
 */
FLClientManager::FLClientManager()
{
  flClientPool = NULL;
}

/**
 * \brief 析构函数
 */
FLClientManager::~FLClientManager()
{
  SAFE_DELETE(flClientPool);
}

/**
 * \brief 初始化管理器
 * \return 初始化是否成功
 */
bool FLClientManager::init()
{
  Xlogger->debug("FLClientManager::init");
  flClientPool = new x_tcp_clientTaskPool(atoi(Seal::global["threadPoolClient"].c_str()));
  if (NULL == flClientPool
      || !flClientPool->init())
    return false;

  zXMLParser xml;
  if (!xml.initFile(Seal::global["confdir"] + "loginServerList.xml"))
  {
    Xlogger->error("加载统一用户平台登陆服务器列表文件失败");
    return false;
  }
  xmlNodePtr root = xml.getRootNode("Seal");
  if (root)
  {
    xmlNodePtr zebra_node = xml.getChildNode(root,"LoginServerList");
    while(zebra_node)
    {
      if (strcmp((char *)zebra_node->name,"LoginServerList") == 0)
      {
        xmlNodePtr node = xml.getChildNode(zebra_node,"server");
        while(node)
        {
          if (strcmp((char *)node->name,"server") == 0)
          {
              std::string FLServer,FLPort;

            FLServer = "";
            FLPort   = "";
            if (xml.getNodePropStr(node,"ip",FLServer)
                && xml.getNodePropStr(node,"port",FLPort))
            {
              Xlogger->debug("LoginServer: %s,%s",FLServer.c_str(),FLPort.c_str());
              flClientPool->put(new FLClient(FLServer,atoi(FLPort.c_str())));
            }
          }

          node = xml.getNextNode(node,NULL);
        }
      }

      zebra_node = xml.getNextNode(zebra_node,NULL);
    }
  }

  Xlogger->info("加载统一用户平台登陆服务器列表文件成功");
  return true;
}

/**
 * \brief 周期间隔进行连接的断线重连工作
 * \param ct 当前时间
 */
void FLClientManager::timeAction(const zTime &ct)
{
  Xlogger->debug("FLClientManager::timeAction");
  if (actionTimer.elapse(ct) > 4)
  {
    if (flClientPool)
      flClientPool->timeAction(ct);
    actionTimer = ct;
  }
}

/**
 * \brief 向容器中添加已经成功的连接
 * \param flClient 待添加的连接
 */
void FLClientManager::add(FLClient *flClient)
{
  Xlogger->debug("FLClientManager::add");
  if (flClient)
  {
    zRWLock_scope_wrlock scope_wrlock(rwlock);
    const_iter it = allClients.find(flClient->getTempID());
    if (it == allClients.end())
    {
      allClients.insert(value_type(flClient->getTempID(),flClient));
    }
  }
}

/**
 * \brief 从容器中移除断开的连接
 * \param flClient 待移除的连接
 */
void FLClientManager::remove(FLClient *flClient)
{
  Xlogger->debug("FLClientManager::remove");
  if (flClient)
  {
    zRWLock_scope_wrlock scope_wrlock(rwlock);
    iter it = allClients.find(flClient->getTempID());
    if (it != allClients.end())
    {
      allClients.erase(it);
    }
  }
}

/**
 * \brief 向成功的所有连接广播指令
 * \param pstrCmd 待广播的指令
 * \param nCmdLen 待广播指令的长度
 */
void FLClientManager::broadcast(const void *pstrCmd,int nCmdLen)
{
  Xlogger->debug("FLClientManager::broadcast");
  zRWLock_scope_rdlock scope_rdlock(rwlock);
  for(iter it = allClients.begin(); it != allClients.end(); ++it)
  {
    it->second->sendCmd(pstrCmd,nCmdLen);
  }
}

/**
 * \brief 向指定的成功连接广播指令
 * \param tempid 待广播指令的连接临时编号
 * \param pstrCmd 待广播的指令
 * \param nCmdLen 待广播指令的长度
 */
void FLClientManager::sendTo(const WORD tempid,const void *pstrCmd,int nCmdLen)
{
  Xlogger->debug("FLClientManager::sendTo");
  zRWLock_scope_rdlock scope_rdlock(rwlock);
  iter it = allClients.find(tempid);
  if (it != allClients.end())
  {
    it->second->sendCmd(pstrCmd,nCmdLen);
  }
}

