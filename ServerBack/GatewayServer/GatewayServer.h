#pragma once

#include "common.h"
#include "x_subnetservice.h"
#include <string>
#include <boost/unordered_map.hpp>
#include "supercmd.h"
#include <boost/thread/mutex.hpp>
#include <boost/thread.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "LoginSessionManager.h"
using namespace boost::posix_time;

class LoginSessionManager;

class RecordClient;
class SessionClient;
class BillClient;

class GatewayService : public x_subnetservice {
	public:
		bool msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
		virtual ~GatewayService() { }

		static GatewayService &getInstance() {
			if (NULL == instance)
				instance = new GatewayService();
			return *instance;
		}

		static void delInstance() { SAFE_DELETE(instance); }
		void reloadConfig();

		boost::shared_ptr<RecordClient> recordClient;
		boost::shared_ptr<SessionClient> sessionClient;
		boost::shared_ptr<BillClient> billClient;
		virtual void exec();
		bool notifyLoginServer();
		ptime currentTime;

		DWORD verify_client_version;
	private:
		//std::string pstrIP;
		boost::scoped_ptr<boost::thread> timetickThread;
		boost::scoped_ptr<LoginSessionManager> pLoginSessionM;

		static GatewayService *instance;

		GatewayService():x_subnetservice("gateway server", GATEWAYSERVER) {
		}

		bool init();
		tcp_task_ptr newTCPTask(boost::asio::io_service& ios);
		void final();
};

