#pragma once

#include "common.h"
#include <boost/unordered_map.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/smart_ptr.hpp>

using boost::shared_ptr;

class ServerTask;

class ServerManager : boost::noncopyable
{
  public:
    ~ServerManager() {};

    static ServerManager &getInstance() {
      if (NULL == instance)
        instance = new ServerManager();

      return *instance;
    }

    static void delInstance() { SAFE_DELETE(instance); }

    void addServer(shared_ptr<ServerTask> task);
    void removeServer(shared_ptr<ServerTask> task);
    shared_ptr<ServerTask> getServer(WORD wdServerID);
    bool uniqueAdd(shared_ptr<ServerTask> task);
    bool uniqueVerify(const WORD wdServerID);
    bool uniqueRemove(shared_ptr<ServerTask> task);
    bool broadcast(const void *pstrCmd,int nCmdLen);
    bool broadcastByID(const WORD wdServerID,const void *pstrCmd,int nCmdLen);
    bool broadcastByType(const WORD wdType,const void *pstrCmd,int nCmdLen);
    const DWORD caculateOnlineNum();
    void responseOther(const WORD srcID,const WORD wdServerID);
	//void execEvery();
	void checkSequence();

  private:

    typedef std::list<shared_ptr<ServerTask> > Container;
    typedef Container::iterator Container_iterator;
    typedef Container::const_iterator Containter_const_iterator;
    typedef boost::unordered_map<WORD,shared_ptr<ServerTask> > ServerTaskHashmap;
    typedef ServerTaskHashmap::iterator ServerTaskHashmap_iterator;
    typedef ServerTaskHashmap::const_iterator ServerTaskHashmap_const_iterator;
    typedef ServerTaskHashmap::value_type ServerTaskHashmap_pair;
	boost::mutex mutex_container;
    Container container;
	boost::mutex mutex_hashmap;
    ServerTaskHashmap taskUniqueContainer;

    static ServerManager *instance;

    ServerManager() {};

};
