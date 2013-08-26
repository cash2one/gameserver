#include "common.h"
#include <sstream>
#include <iostream>
#include <string.h>	//for strncpy
#include "x_config.h"


/*
//for db
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
//end db
*/

#include "FLServer.h"
#include "LoginTask.h"
#include "ServerTask.h"

#include <boost/thread.hpp>
#include <boost/ref.hpp>
#include <boost/unordered_map.hpp>
#include <boost/chrono.hpp>

#include "ServerACL.h"

typedef boost::chrono::milliseconds ms;

using namespace Cmd;
using namespace Cmd::FL;

boost::shared_ptr<sql::Connection> FLService::s_dbConn;
FLService *FLService::instance = NULL;

bool FLService::init_db(const std::string& hostname,
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

bool FLService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	if(!x_service::init())
		return false;

	//init database
	if(!init_db(Seal::global["url"],Seal::global["user"],Seal::global["password"],Seal::global["database"]))
		return false;

	std::string ip = getIPByIfName(Seal::global["ifname"].c_str());

	new ServerACL();
	if (!ServerACL::getSingleton().init())
	{
		return false;
	}
	loginServer.reset(new server(ip, Seal::global["login_port"], io_service_pool_,boost::bind(&FLService::newLoginTask,this,_1)));
	serverServer.reset(new server(ip, Seal::global["inside_port"], io_service_pool_,boost::bind(&FLService::newServerTask,this,_1)));

	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&FLService::exec,this)));
	Xlogger->debug("init complete");

	return true;
}

shared_ptr<tcp_task> FLService::newLoginTask(io_service& ios)
{
	//can use object pool, for efficiency
	/*
	shared_ptr<ServerTask> tcpTask(new ServerTask(ios));
	return tcpTask;
	*/
	return shared_ptr<tcp_task>(new LoginTask(ios));
}

shared_ptr<tcp_task> FLService::newServerTask(io_service& ios)
{
	//can use object pool, for efficiency
	/*
	shared_ptr<ServerTask> tcpTask(new ServerTask(ios));
	return tcpTask;
	*/
	return shared_ptr<tcp_task>(new ServerTask(ios));
}

//before final() ,the main thread call of accept() has been shutdown
void FLService::final() {
	Terminate();
	//shutdown logical process
	if (timetickThread)
		timetickThread->join();

	delete ServerACL::getSingletonPtr();

	//ServerManager::delInstance();
	////---InfoClientManager::delInstance();
	//FLClientManager::delInstance();
	//RoleregCache::delInstance();

	Xlogger->debug("FLService::final");
}

void FLService::handleHup()
{
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","FLServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("FLServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","FLServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;	
		daemon(1,1);
	}

	FLService::getInstance().main();
	FLService::delInstance();

	return EXIT_SUCCESS;
}

void FLService::exec() {
	using namespace Cmd;

	while(!isTerminate()) {
		boost::this_thread::sleep_for(ms(5000));
		Xlogger->debug("FLTimeTick");
	}

}
