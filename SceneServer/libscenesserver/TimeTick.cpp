/**
 * \brief 时间回调函数
 */
//#include <zebra/ScenesServer.h>
#include "scriptTickTask.h"
#include "duplicateManager.h"

#define MAX_CMD_GROUP 10
zRTime SceneTimeTick::currentTime;
SceneTimeTick *SceneTimeTick::instance = NULL;

/**
 * \brief 地图回调函数
 */
struct EverySceneEntryAction : public SceneCallBack
{
  const DWORD group;
  EverySceneEntryAction(const DWORD group) : group(group) {}
  bool exec(Scene *scene)
  {
    if (scene)
    {
      if (scene->SceneEntryAction(SceneTimeTick::currentTime,group))
      {
        /**
         * 这里如果需要动态加载卸载地图会死锁哦
         * ^-^ 不会死锁,现在单线程,场景管理器没有锁,只是要注意遍历的容器的迭代器
         */
        SceneTaskManager::getInstance().execEvery();
      }
    }
    return true;
  }
};

/**
 * \brief 把特殊npc加到ai处理列表中
 */
/*class AddSpecialNpcCallBack : public specialNpcCallBack
{
  private:
    MonkeyNpcs &affectNpc;
    const DWORD group;
    const bool _every;
  public:
    AddSpecialNpcCallBack(MonkeyNpcs &affectNpc,const DWORD g,const bool every):affectNpc(affectNpc),group(g),_every(every){}
    bool exec(SceneNpc * npc)
    {
      if (_every || npc->tempid%MAX_NPC_GROUP==group)
      {
        affectNpc.insert(npc);
      }
      return true;
    }
};*/

/**
 * \brief 时间循环,发送定时事件,处理受影响npc ai等
 */
void SceneTimeTick::run()
{
  const int timeout_value = 500;
  const int timeout_value2 = 300;
  DWORD step = 0;
  int t = 0;
  while(!isFinal())
  {
    zThread::msleep((10-t)>0?(10-t):1);
    //获取当前时间
    currentTime.now();

	//sky 一秒记时器循环遍历队伍处理Roll事宜
	if(_one_sec(currentTime)) {
		SceneManager::getInstance().TeamRollItme();
	}

    if (_five_sec(currentTime)) {
      OnTimer event(1);
      EventTable::instance().execute(event);
      ScenesService::getInstance().checkAndReloadConfig();
    }
    sessionClient->doCmd();
    recordClient->doCmd();
    SceneTaskManager::getInstance().execEvery();

    //specialNpc
    //MonkeyNpcs affectNpc;
    //AddSpecialNpcCallBack asncb(affectNpc,step,t > timeout_value2);
    //SceneNpcManager::getMe().execAllSpecialNpc(asncb);
    SceneNpc::AI(currentTime,SceneNpcManager::getMe().getSepcialNpc(),step,t > timeout_value2);

    //250 usec
    EverySceneEntryAction esea(step);
    //对所有地图调用回调函数
    SceneManager::getInstance().execEveryScene(esea);

#if 0
    if (0==step)
    {
      //20-25 usec
      sessionClient->doCmd();
      recordClient->doCmd();
      SceneTaskManager::getInstance().execEvery();
    }
#endif

    if (_one_min(currentTime))
    {//竞赛处理,一分钟判断一次全国竞赛
      CountryDareM::getMe().timer();

      //刷新所有全局变量
      if (GlobalVar::server_id()) { //ugly,TO BE FIXED

        ALLVARS(update);
        ALLVARS(save);
      }

      SceneManager::getInstance().checkUnloadOneScene();
    }

    step = (++step) % MAX_NPC_GROUP;

    zRTime e;
    t = currentTime.elapse(e);
    if (t > timeout_value)
    {
      Xlogger->debug("---------- 1次循环用时 %u 毫秒----------",t);
    }

	scriptTaskManagement::getInstance().execAll();

	duplicateManager::getInstance().doClear();
	/*scriptTaskManagement::iterator it = _tasklist->begin();
	scriptTaskManagement::iterator end = _tasklist->end();
	for( ; it != end; ++it)
	{
		time_t t = (time(NULL) - it->second->lastTime);
		if(it->second->doTask(t))
		{
			it->second->lastTime = time(NULL);
		}
	}*/

  }
}
