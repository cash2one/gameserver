#pragma once

#include "tcp_task.h"
#include <string>
#include <boost/timer.hpp>
#include <boost/unordered_map.hpp>
#include "command.h"

//class Cmd::t_NullCmd;

class LoginTask : public tcp_task
{
	//friend class ServerManager;
	public:
		static DWORD uniqueID;

		LoginTask(io_service& ios):tcp_task(ios) { }

		virtual ~LoginTask();

		void handle_verify(const void* ptr, const uint32_t len);
		//void handle_wait_sync(const void* ptr, const uint32_t len);
		//bool wait_sync_msg(const Cmd::t_NullCmd* cmd, const uint32_t len);
		int recycleConn();
		/*
		void addToContainer();
		void removeFromContainer();
		*/
		bool uniqueAdd();
		bool uniqueRemove();
		bool msgParse(const Cmd::t_NullCmd *,const DWORD);
		virtual void handle_msg(const void* ptr, const uint32_t len);

		/*
		bool checkSequenceTime()
		{
			if (lastSequenceTime.elapsed() > 2.0)
			{
				lastSequenceTime.restart();
				return true;
			}

			return false;
		}
		*/

		void genTempID() { tempid = ++uniqueID; }
		DWORD getTempID() const { return tempid; }

		void LoginReturn(const BYTE retcode,const bool tm = true);
	private:
		DWORD tempid;

		//boost::timer lastSequenceTime;        /**< 最后一次处理启动顺序的时间 */

		DWORD dwClientVersion;
		bool requestLogin(const Cmd::stUserRequestLoginCmd *ptCmd);
};

