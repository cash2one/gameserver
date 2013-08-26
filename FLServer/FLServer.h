#pragma once

#include "common.h"
#include "x_service.h"
#include "x_util.h"
#include <string>
#include <boost/smart_ptr.hpp>
#include <boost/thread.hpp>
#include "flcmd.h"
#include <boost/asio.hpp>
#include "tcp_task.h"
#include "server.h"

#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

//class sql::Connection;

class FLService : public x_service {
public:
	~FLService() { instance = NULL; }

	static FLService &getInstance() {
		if (NULL == instance)
			instance = new FLService();

		return *instance;
	}

	static void delInstance() { SAFE_DELETE(instance); }
	const WORD getType() const { return wdServerType; }

	static boost::shared_ptr<sql::Connection> s_dbConn;
	static bool init_db(const std::string& hostname,
						const std::string& user,
						const std::string& password,
						const std::string& db);

	virtual void exec();
	void handleHup();
private:
	static FLService *instance;

	boost::scoped_ptr<boost::thread> timetickThread;

	FLService() : x_service("flserver") {
		wdServerType = LOGINSERVER;
	}
	WORD wdServerType;

	bool init();
	tcp_task_ptr newLoginTask(boost::asio::io_service& ios);
	//tcp_task_ptr newPingTask(boost::asio::io_service& ios);
	tcp_task_ptr newServerTask(boost::asio::io_service& ios);
	void final();

	boost::shared_ptr<server> loginServer;
	boost::shared_ptr<server> serverServer;
	//boost::shared_ptr<server> serverServer;
};
