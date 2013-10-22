#include "SceneServer.h"
#include "x_config.h"
#include <stdlib.h>
#include <string.h>
#include <boost/ref.hpp>
#include <boost/thread.hpp>
#include "SceneTask.h"
#include "RecordClient.h"
#include "SessionClient.h"
#include "super_client.h"
#include <ctime>
#include <boost/chrono.hpp>

typedef boost::chrono::milliseconds ms;
boost::shared_ptr<sql::Connection> SceneService::s_dbConn;
SceneService* SceneService::instance = NULL;

bool SceneService::msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
{
	return false;
}

bool SceneService::init_db(const std::string& hostname,
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


bool SceneService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);

	if(!init_db(Seal::global["url"],Seal::global["user"],Seal::global["password"],Seal::global["database"]))
		return false;

	if (!x_subnetservice::init()) { return false; }

	{
		const Cmd::Super::ServerEntry *serverEntry = getServerEntryByType(RECORDSERVER);
		if (!serverEntry) {
			Xlogger->error("can't find recordserver info");
			return false;
		}
		recordClient.reset(new RecordClient(io_service_pool_.get_io_service()));
		if (!recordClient->connect(serverEntry->pstrIP, serverEntry->wdPort)){
			Xlogger->error("connet to Record Server failed: ip=%s,port=%u",serverEntry->pstrExtIP,serverEntry->wdExtPort);
			return false;
		}
		recordClient->start();
		Cmd::Record::t_LoginRecord tCmd;
		tCmd.wdServerID = wdServerID;
		tCmd.wdServerType = wdServerType;
		recordClient->sendCmd(&tCmd, sizeof(tCmd));
	}
	{
		const Cmd::Super::ServerEntry *serverEntry = getServerEntryByType(SESSIONSERVER);
		if (!serverEntry) {
			Xlogger->error("can't find sessionserver info");
			return false;
		}
		sessionClient.reset(new SessionClient(io_service_pool_.get_io_service()));
		if (!sessionClient->connect(serverEntry->pstrIP, serverEntry->wdPort)){
			Xlogger->error("connet to Session Server failed: ip=%s,port=%u",serverEntry->pstrExtIP,serverEntry->wdExtPort);
			return false;
		}
		sessionClient->start();
		Cmd::Session::t_LoginSession tCmd;
		tCmd.wdServerID = wdServerID;
		tCmd.wdServerType = wdServerType;
		sessionClient->sendCmd(&tCmd, sizeof(tCmd));
	}

	//if (!SceneUserM::getMe().init())
		//return false;
	
	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&SceneService::exec,this)));
	Xlogger->debug("init complete");

	//SceneInfoManager::getMe().init();
	return true;
}

tcp_task_ptr SceneService::newTCPTask(io_service& ios) {
	//can use object pool, for efficiency
	tcp_task_ptr tcpTask(new SceneTask(ios));
	return tcpTask;
}

/*
bool SceneService::msgParse_SceneService(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->error("SceneService::msgParse_SceneService(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}
*/

void SceneService::final() {
	Xlogger->debug("SceneService::final");

	//shutdown logical process
	Terminate();
	if (timetickThread)
		    timetickThread->join();
	x_subnetservice::final();
	    
	/*
	while(!SceneSceneManager::getInstance().empty())
	{
		zThread::msleep(10);
	}
	*/


	//SceneSceneManager::delInstance();
}


/**
 * \brief 重新读取配置文件,为HUP信号的处理函数
 *
 */
void SceneService::reloadConfig()
{
	Xlogger->debug("SceneService::reloadConfig");
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","SceneServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("SceneServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","SceneServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;
		daemon(1,1);
	}

	SceneService::getInstance().main();
	SceneService::delInstance();
	return EXIT_SUCCESS;
}


void SceneService::exec() {
	while(!isTerminate())
	{
		boost::this_thread::sleep_for(ms(1000));

		superClient->doCmd();
		recordClient->doCmd();
		sessionClient->doCmd();
		//Xlogger->debug("scene elapsed time =%lf", startTimer.elapsed());
		static time_t ti = time(0);
		if (time(0) > ti + 3){
			ti = time(0);
			Cmd::Record::t_Test_SceneRecord test;
			recordClient->async_write(&test, sizeof(test));

			Cmd::Session::t_SceneSession_Test test1;
			sessionClient->async_write(&test1, sizeof(test1));
		}
	}

}
