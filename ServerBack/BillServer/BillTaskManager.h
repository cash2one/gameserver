#pragma once

#include "common.h"
#include <boost/unordered_map.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/smart_ptr.hpp>

using boost::shared_ptr;

class BillTask;
class BillTaskManager : boost::noncopyable
{
public:
    ~BillTaskManager() {};

    static BillTaskManager &getInstance() {
      if (NULL == instance)
        instance = new BillTaskManager();

      return *instance;
    }

    static void delInstance() { SAFE_DELETE(instance); }

    //void addServer(shared_ptr<BillTask> task);
    //void removeServer(shared_ptr<BillTask> task);
    //shared_ptr<BillTask> getServer(WORD wdServerID);
    //bool uniqueVerify(const WORD wdServerID);
    bool uniqueAdd(shared_ptr<BillTask> task);
    bool uniqueRemove(shared_ptr<BillTask> task);
    void broadcast(const void *pstrCmd, const int nCmdLen);
    bool broadcastByID(const uint32_t wdServerID, const void *pstrCmd, const int nCmdLen);
	shared_ptr<BillTask> getTaskByID(const uint32_t dwServerID);
	void execEvery();

  private:

    //typedef std::list<shared_ptr<BillTask> > Container;
    //typedef Container::iterator Container_iterator;
    //typedef Container::const_iterator Containter_const_iterator;
    typedef boost::unordered_map<uint32_t,shared_ptr<BillTask> > BillTaskHashmap;
    typedef BillTaskHashmap::iterator BillTaskHashmap_iterator;
    typedef BillTaskHashmap::const_iterator BillTaskHashmap_const_iterator;
    typedef BillTaskHashmap::value_type BillTaskHashmap_pair;
	boost::mutex mutex;
    //Container container;
    BillTaskHashmap taskUniqueContainer;

    static BillTaskManager *instance;

    BillTaskManager() {};

};
