#include "RecordServer.h"
#include "x_config.h"
#include <stdlib.h>
#include <string.h>
#include <boost/ref.hpp>
#include <boost/thread.hpp>
#include "RecordTask.h"
#include <boost/chrono.hpp>
#include <ctime>
#include <boost/timer.hpp>
#include "super_client.h"

typedef boost::chrono::milliseconds ms;
boost::shared_ptr<sql::Connection> RecordService::s_dbConn;
RecordService* RecordService::instance = NULL;

bool RecordService::msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
{
	return false;
}

bool RecordService::init_db(const std::string& hostname,
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


bool RecordService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);

	if(!init_db(Seal::global["url"],Seal::global["user"],Seal::global["password"],Seal::global["database"]))
		return false;

	if (!x_subnetservice::init()) { return false; }

	//if (!RecordUserM::getMe().init())
		//return false;
	
	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&RecordService::exec,this)));
	Xlogger->debug("init complete");

	//RecordInfoManager::getMe().init();
	return true;
}

tcp_task_ptr RecordService::newTCPTask(io_service& ios) {
	//can use object pool, for efficiency
	tcp_task_ptr tcpTask(new RecordTask(ios));
	return tcpTask;
}

/*
bool RecordService::msgParse_RecordService(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->error("RecordService::msgParse_RecordService(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}
*/

void RecordService::final() {
	Xlogger->debug("RecordService::final");

	//shutdown logical process
	Terminate();
	if (timetickThread)
		    timetickThread->join();
	x_subnetservice::final();
	    
	/*
	while(!RecordSessionManager::getInstance().empty())
	{
		zThread::msleep(10);
	}
	*/


	//RecordSessionManager::delInstance();
}


/**
 * \brief 重新读取配置文件,为HUP信号的处理函数
 *
 */
void RecordService::reloadConfig()
{
	Xlogger->debug("RecordService::reloadConfig");
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","RecordServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("RecordServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","RecordServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;
		daemon(1,1);
	}

	RecordService::getInstance().main();
	RecordService::delInstance();
	return EXIT_SUCCESS;
}

void RecordService::exec() {
	boost::timer startTimer;
	while(!isTerminate())
	{
		boost::this_thread::sleep_for(ms(50));

		superClient->doCmd();
		static time_t t = time(0);
		if (time(0) > t+2 )
		{
			t = time(0);
			Cmd::Super::t_Startup_test cmd;
			//RecordService::getInstance().superClient->sendCmd(&cmd, sizeof(cmd));
			superClient->async_write(&cmd, sizeof(cmd));
		}
	}
}
