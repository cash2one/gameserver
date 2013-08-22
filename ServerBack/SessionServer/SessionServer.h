#pragma once

#include "common.h"
#include "x_subnetservice.h"
#include <string>
#include <boost/unordered_map.hpp>
#include "supercmd.h"
#include <boost/thread/mutex.hpp>
#include <boost/thread.hpp>
#include <boost/smart_ptr.hpp>
//for db
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
//end db

class RecordClient;

class SessionService : public x_subnetservice {
	public:
		bool msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen);
		virtual ~SessionService() { }

		static SessionService &getInstance() {
			if (NULL == instance)
				instance = new SessionService();
			return *instance;
		}

		static void delInstance() { SAFE_DELETE(instance); }
		void reloadConfig();

		static boost::shared_ptr<sql::Connection> s_dbConn;
		static bool init_db(const std::string& hostname,
				const std::string& user,
				const std::string& password,
				const std::string& db);

		boost::shared_ptr<RecordClient> recordClient;
		void exec();
	private:
		//std::string pstrIP;
		boost::scoped_ptr<boost::thread> timetickThread;

		static SessionService *instance;

		SessionService():x_subnetservice("session server",SESSIONSERVER) {
		}

		bool init();
		tcp_task_ptr newTCPTask(boost::asio::io_service& ios);
		void final();
};

