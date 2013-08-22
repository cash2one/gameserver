#include "common.h"
#include "SuperServer.h"
#include <sstream>
#include <iostream>
#include <string.h>	//for strncpy
#include "x_config.h"

//for db
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
//end db

#include <boost/thread.hpp>
#include <boost/ref.hpp>
#include <boost/unordered_map.hpp>
#include <boost/chrono.hpp>

#include "ServerTask.h"
#include "ServerManager.h"
#include "MassiveFlag.h"
#include <ctime>
#include "x_util.h"	//getIPByIfName
//#include "FLClient.h"
#include <iostream>

typedef boost::chrono::milliseconds ms;

using namespace Cmd;
using namespace Cmd::Super;

boost::shared_ptr<sql::Connection> SuperService::s_dbConn;
SuperService *SuperService::instance = NULL;

bool SuperService::loadServerlist()
try
{
	boost::scoped_ptr< sql::Statement > stmt(s_dbConn->createStatement());
	boost::scoped_ptr< sql::ResultSet > res(stmt->executeQuery("SELECT * FROM serverlist"));
	while(res->next())
	{
		Cmd::Super::ServerEntry se;

		se.wdServerID = res->getUInt("id");
		se.wdServerType = res->getUInt("type");
		strncpy(se.pstrName,res->getString("name").c_str(),sizeof(se.pstrName)-1);

		strncpy(se.pstrIP,res->getString("ip").c_str(),sizeof(se.pstrIP)-1);
		se.wdPort = res->getUInt("port");

		strncpy(se.pstrExtIP,res->getString("extip").c_str(),sizeof(se.pstrExtIP)-1);
		se.wdExtPort = res->getUInt("extport");

		se.wdNetType = res->getUInt("nettype");

		ses_.push_back(se);
	}
	if(ses_.empty())
	{
		Xlogger->fatal("serverlist is empty");
		return false;
	}
	return true;
} catch (sql::SQLException &e) {
	using namespace std;
	cout << "# ERR: SQLException in " << __FILE__;
	cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
	// Use what(), getErrorCode() and getSQLState()
	cout << "# ERR: " << e.what();
	cout << " (MySQL error code: " << e.getErrorCode();
	cout << ", SQLState: " << e.getSQLState() << " )" << endl;

	return false;
} catch (std::runtime_error &e) {
	using namespace std;
	cout << "# ERR: runtime_error in " << __FILE__;
	cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
	cout << "# ERR: " << e.what() << endl;
	cout << "not ok 1 - examples/resultset_binary.cpp" << endl;

	return false;
}

void SuperService::get_recordset(const uint32_t type, const std::string& ip,std::vector<const Cmd::Super::ServerEntry*>& ses) const
{
	for (size_t i=0;i<ses_.size();++i)
	{
		if (ses_[i].wdServerType == type && ip == ses_[i].pstrIP)
		{
			ses.push_back(&ses_[i]);
		}
   	}
}

void SuperService::get_recordset_by_type(const uint32_t type, std::vector<const Cmd::Super::ServerEntry*>& ses) const
{
	for (size_t i=0;i<ses_.size();++i)
	{
		if (ses_[i].wdServerType == type)
		{
			ses.push_back(&ses_[i]);
		}
   	}
}

bool SuperService::getServerInfo()
{
	std::string strIP(se_.pstrIP);
	for (size_t i=0;i<ses_.size();++i)
	{
		if (ses_[i].wdServerType == SUPERSERVER && strIP == ses_[i].pstrIP)
		{
			se_ = ses_[i];
			return true;
		}
   	}
	return false;
}

bool SuperService::init_db(const std::string& hostname,
						   const std::string& user,
						   const std::string& password,
						   const std::string& db)
try
{
	sql::Driver * driver = get_driver_instance();
	if(!driver){ 
		Xlogger->error("%s, get db driver error",__PRETTY_FUNCTION__);
		return false;
	}
	s_dbConn.reset(driver->connect(hostname, user, password));
	if(!s_dbConn){
		Xlogger->error("%s, connect to db failed",__PRETTY_FUNCTION__);
		return false;
	}
	s_dbConn->setSchema(db);
	return true;
} catch (sql::SQLException &e) {
	/*
	   The MySQL Connector/C++ throws three different exceptions:

	   - sql::MethodNotImplementedException (derived from sql::SQLException)
	   - sql::InvalidArgumentException (derived from sql::SQLException)
	   - sql::SQLException (derived from std::runtime_error)
	 */
	std::ostringstream os;
	os << "# ERR: SQLException in " << __FILE__;
	os << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
	/* Use what() (derived from std::runtime_error) to fetch the error message */
	os << "# ERR: " << e.what();
	os << " (MySQL error code: " << e.getErrorCode();
	os << ", SQLState: " << e.getSQLState() << " )" << std::endl;

	Xlogger->fatal(os.str().c_str());

	return false;
}

bool SuperService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);

	if(!x_service::init())
		return false;

	//init database
	if(!init_db(Seal::global["url"],Seal::global["user"],Seal::global["password"],Seal::global["database"]))
		return false;

	initServerSequence();

	strncpy(se_.pstrIP,getIPByIfName(Seal::global["ifname"].c_str()),sizeof(se_.pstrIP));
	se_.pstrIP[sizeof(se_.pstrIP)-1] = '\0';
	Xlogger->debug("superserver ip=%s",se_.pstrIP);

	if (!loadServerlist()) {
		Xlogger->error("load serverlist");
		return false;
	}

	if (!getServerInfo()) {
		Xlogger->error("get server info");
		return false;
	}

	simple_table.reset(new x_simple_db_table(s_dbConn,std::string("supermassive")));

	flClient.reset(new FLClient(io_service_pool_.get_io_service()));
	if (!flClient->connect(Seal::global["flserver"], atoi(Seal::global["flport"].c_str()))) {
		Xlogger->error("connet to FL Server failed: ip=%s,port=%u", Seal::global["flserver"].c_str(), Seal::global["flport"].c_str());
		std::cout<<"can't connect to flserver ip = "<<Seal::global["flserver"]<<" port = "<<Seal::global["flport"]<<std::endl;
		//return true;
	}
	else {
		Cmd::FL::t_LoginFL cmd;
		cmd.dwstrIP = 111;
		//cmd.port = se_.wdPort;
		cmd.port = atoi(Seal::global["flport"].c_str());
		flClient->sendCmd(&cmd,sizeof(cmd));
	}

	/*
	if (!FLClientManager::getInstance().init())
		return false;
		*/

	////---if (!InfoClientManager::getInstance().init())
	////---  return false;

	//init thread pool
	/*
	int state = state_none;
	if ("repair" == Seal::global["threadPoolState"] || "maintain" == Seal::global["threadPoolState"])
		state = state_maintain;
		*/

	std::ostringstream os;
	os<<se_.wdPort;

	tcpServer.reset(new server(se_.pstrIP,os.str(),io_service_pool_,boost::bind(&SuperService::newTCPTask,this,_1)));
	/*
	if (!x_netservice::init(se_.wdPort)) {
		Xlogger->error("init netservice, port=%u",se_.wdPort);
		return false;
	}
	*/

	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&SuperService::exec,this)));
	Xlogger->debug("init complete");

	return true;
}

shared_ptr<tcp_task> SuperService::newTCPTask(io_service& ios)
{
	//can use object pool, for efficiency
	shared_ptr<ServerTask> tcpTask(new ServerTask(ios));
	return tcpTask;
}

//before final() ,the main thread call of accept() has been shutdown
void SuperService::final() {
	Terminate();
	//shutdown logical process
	if (timetickThread)
		timetickThread->join();

	//release tcpserver
	//x_netservice::final();

	//ServerManager::delInstance();
	////---InfoClientManager::delInstance();
	//FLClientManager::delInstance();
	//RoleregCache::delInstance();

	Xlogger->debug("SuperService::final");
}

void SuperService::handleHup()
{
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","SuperServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("SuperServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","SuperServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;	
		daemon(1,1);
	}

	SuperService::getInstance().main();
	SuperService::delInstance();

	return EXIT_SUCCESS;
}

void SuperService::exec() {
	using namespace Cmd;
	Seal::qwGameTime = simple_table->get(Super::SimpleTable::ST_GAMETIME_HIGH);
	Seal::qwGameTime <<= 32;
	Seal::qwGameTime += simple_table->get(Super::SimpleTable::ST_GAMETIME_LOW);

	const uint32_t qwGameStartTime = Seal::qwGameTime;

	//boost::timer startTimer;

	while(!isTerminate()) {
		boost::this_thread::sleep_for(ms(5000));
		Xlogger->debug("SuperTimeTick");
		ServerManager::getInstance().checkSequence();

		static time_t t = time(0);
		Seal::qwGameTime = qwGameStartTime + (uint32_t)(time(0) - t);
		if (Seal::qwGameTime !=0 && Seal::qwGameTime % 100 == 0)
		{
			//save db
			uint32_t uHigh = Seal::qwGameTime >> 32;
			uint32_t uLow = Seal::qwGameTime & 0x00000000ffffffff;
			simple_table->set(Super::SimpleTable::ST_GAMETIME_HIGH,uHigh,true);
			simple_table->set(Super::SimpleTable::ST_GAMETIME_LOW,uLow,true);
		}

		Cmd::Super::t_GameTime tCmd;
		tCmd.qwGameTime = Seal::qwGameTime;
		ServerManager::getInstance().broadcast(&tCmd,sizeof(tCmd));
	}

	//save db
	uint32_t uHigh = Seal::qwGameTime >> 32;
	uint32_t uLow = Seal::qwGameTime & 0x00000000ffffffff;
	simple_table->set(Super::SimpleTable::ST_GAMETIME_HIGH,uHigh,true);
	simple_table->set(Super::SimpleTable::ST_GAMETIME_LOW,uLow,true);
}
