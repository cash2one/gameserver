#pragma once

#include "common.h"
#include "x_service.h"
#include <string>
#include <boost/smart_ptr.hpp>
#include <boost/thread.hpp>
#include "x_simple_db_table.h"
#include "supercmd.h"
#include <boost/asio.hpp>
#include "tcp_task.h"
#include "server.h"
#include "FLClient.h"

//class sql::Connection;

class SuperService : public x_service {
public:
	~SuperService() { instance = NULL; }

	static SuperService &getInstance() {
		if (NULL == instance)
			instance = new SuperService();

		return *instance;
	}

	static void delInstance() { SAFE_DELETE(instance); }
	void handleHup();

	const GameZone_t &getZoneID() const { return gameZone; }
	void setZoneID(const GameZone_t &gameZone) { this->gameZone = gameZone; }

	const std::string &getZoneName() const { return zoneName; }
	void setZoneName(const char *zoneName) { this->zoneName = zoneName; }

	const WORD getID() const { return se_.wdServerID; }
	const WORD getType() const { return se_.wdServerType; }

	const char *getIP() const { return se_.pstrIP; }
	const WORD getPort() const { return se_.wdPort; }

	static boost::shared_ptr<sql::Connection> s_dbConn;
	static bool init_db(const std::string& hostname,
						const std::string& user,
						const std::string& password,
						const std::string& db);

	//store simple data id->value(uint32_t -> uint32_t)
	boost::shared_ptr<x_simple_db_table> simple_table;

	void get_recordset(const uint32_t type, const std::string& ip,std::vector<const Cmd::Super::ServerEntry*>& ) const;
	void get_recordset_by_type(const uint32_t type, std::vector<const Cmd::Super::ServerEntry*>& ) const;
	std::vector<Cmd::Super::ServerEntry> ses_;

	virtual void exec();
	boost::shared_ptr<FLClient> flClient;
private:
	GameZone_t gameZone;

	Cmd::Super::ServerEntry se_;

	/*
	//keep serverlist data
	typedef boost::unordered_map<Cmd::Super::ServerEntry,bool,Cmd::Super::key_hash,Cmd::Super::key_equal> Container;
	Container ses;
	*/

	std::string zoneName;

	static SuperService *instance;

	boost::scoped_ptr<boost::thread> timetickThread;

	SuperService() : x_service("superserver") {
	}

	bool init();
	tcp_task_ptr newTCPTask(boost::asio::io_service& ios);
	void final();

	bool loadServerlist();
	bool getServerInfo();
	boost::shared_ptr<server> tcpServer;        /**< TCP服务器实例指针 */
};
