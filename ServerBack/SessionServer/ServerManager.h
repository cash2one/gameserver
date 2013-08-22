#pragma once

#include "common.h"
#include <boost/unordered_map.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/smart_ptr.hpp>

using boost::shared_ptr;

class SessionTask;

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

    void addServer(shared_ptr<SessionTask> task);
    void removeServer(shared_ptr<SessionTask> task);
    shared_ptr<SessionTask> getServer(WORD wdServerID);
    bool uniqueAdd(shared_ptr<SessionTask> task);
    bool uniqueVerify(const WORD wdServerID);
    bool uniqueRemove(shared_ptr<SessionTask> task);
    bool broadcast(const void *pstrCmd,int nCmdLen);
    bool broadcastByID(const WORD wdServerID,const void *pstrCmd,int nCmdLen);
    bool broadcastByType(const WORD wdType,const void *pstrCmd,int nCmdLen);
	void execEvery();

private:

    typedef std::list<shared_ptr<SessionTask> > Container;
    typedef Container::iterator Container_iterator;
    typedef Container::const_iterator Containter_const_iterator;
    typedef boost::unordered_map<WORD,shared_ptr<SessionTask> > SessionTaskHashmap;
    typedef SessionTaskHashmap::iterator SessionTaskHashmap_iterator;
    typedef SessionTaskHashmap::const_iterator SessionTaskHashmap_const_iterator;
    typedef SessionTaskHashmap::value_type SessionTaskHashmap_pair;
	boost::mutex mutex;
    Container container;
    SessionTaskHashmap taskUniqueContainer;

    static ServerManager *instance;

    ServerManager() {};

};
