#include "SessionServer.h"
#include "x_config.h"
#include <stdlib.h>
#include <string.h>
#include <boost/thread.hpp>
#include "SessionTask.h"
#include "RecordClient.h"
#include "super_client.h"
#include <boost/chrono.hpp>
#include "ServerManager.h"

typedef boost::chrono::milliseconds ms;
boost::shared_ptr<sql::Connection> SessionService::s_dbConn;
SessionService* SessionService::instance = NULL;

bool SessionService::msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
{
	return false;
}

bool SessionService::init_db(const std::string& hostname,
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


bool SessionService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);

	if(!init_db(Seal::global["url"],Seal::global["user"],Seal::global["password"],Seal::global["database"]))
		return false;

	if (!x_subnetservice::init()) { return false; }

	{
		const Cmd::Super::ServerEntry *serverEntry = getServerEntryByType(RECORDSERVER);
		if (!serverEntry) {
			Xlogger->error("can't find Sessionserver info");
			return false;
		}
		recordClient.reset(new RecordClient(io_service_pool_.get_io_service()));
		if (!recordClient->connect(serverEntry->pstrIP, serverEntry->wdPort)){
			Xlogger->error("connet to Record Server failed: ip=%s,port=%u",serverEntry->pstrExtIP,serverEntry->wdExtPort);
			return false;
		}
		Cmd::Record::t_LoginRecord tCmd;
		tCmd.wdServerID = wdServerID;
		tCmd.wdServerType = wdServerType;
		recordClient->sendCmd(&tCmd, sizeof(tCmd));
	}

	//if (!SessionUserM::getMe().init())
		//return false;
	
	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&SessionService::exec,this)));
	Xlogger->debug("init complete");

	//SessionInfoManager::getMe().init();
	return true;
}

tcp_task_ptr SessionService::newTCPTask(io_service& ios) {
	//can use object pool, for efficiency
	tcp_task_ptr tcpTask(new SessionTask(ios));
	return tcpTask;
}

/*
bool SessionService::msgParse_SessionService(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->error("SessionService::msgParse_SessionService(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}
*/

void SessionService::final() {
	Xlogger->debug("SessionService::final");

	//shutdown logical process
	Terminate();
	if (timetickThread)
		    timetickThread->join();
	x_subnetservice::final();
	    
	/*
	while(!SessionSessionManager::getInstance().empty())
	{
		zThread::msleep(10);
	}
	*/


	//SessionSessionManager::delInstance();
}


/**
 * \brief 重新读取配置文件,为HUP信号的处理函数
 *
 */
void SessionService::reloadConfig()
{
	Xlogger->debug("SessionService::reloadConfig");
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","SessionServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("SessionServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","SessionServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;
		daemon(1,1);
	}

	SessionService::getInstance().main();
	SessionService::delInstance();
	return EXIT_SUCCESS;
}

void SessionService::exec() {
	while(!isTerminate())
	{
		boost::this_thread::sleep_for(ms(20));

		superClient->doCmd();
		recordClient->doCmd();

		ServerManager::getInstance().execEvery();
	}

}
