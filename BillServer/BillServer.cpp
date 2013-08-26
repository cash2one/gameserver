#include "BillServer.h"
#include "x_config.h"
#include <stdlib.h>
#include <string.h>
#include <boost/ref.hpp>
#include <boost/thread.hpp>
#include "BillTask.h"
#include <boost/chrono.hpp>
#include "supercmd.h"
#include "super_client.h"
#include "BillTaskManager.h"

typedef boost::chrono::milliseconds ms;
boost::shared_ptr<sql::Connection> BillService::s_dbConn;
BillService* BillService::instance = NULL;

bool BillService::init_db(const std::string& hostname,
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


bool BillService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);

	if(!init_db(Seal::global["url"],Seal::global["user"],Seal::global["password"],Seal::global["database"]))
		return false;

	if (!x_subnetservice::init()) { return false; }

	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&BillService::exec,this)));
	Xlogger->debug("init complete");

	//RecordInfoManager::getMe().init();
	return true;
}

tcp_task_ptr BillService::newTCPTask(io_service& ios) {
	//can use object pool, for efficiency
	tcp_task_ptr tcpTask(new BillTask(ios));
	return tcpTask;
}

bool BillService::msgParse_SuperService(const Cmd::t_NullCmd* pNullCmd, const uint32_t nCmdLen)
{
	using namespace Cmd::Super;

	switch(pNullCmd->para)
	{
		case PARA_BILL_NEWSESSION:
			{
				t_NewSession_Bill *ptCmd = (t_NewSession_Bill *)pNullCmd;
				Cmd::Bill::t_NewSession_Gateway tCmd;
				shared_ptr<BillTask> task=BillTaskManager::getInstance().getTaskByID(ptCmd->session.wdGatewayID);
				if (!task)
				{
					Xlogger->error("the gateway is closed : account = %u",ptCmd->session.accid);
					t_idinuse_Bill ret;
					ret.accid = ptCmd->session.accid;
					ret.loginTempID = ptCmd->session.loginTempID;
					ret.wdLoginID = ptCmd->session.wdLoginID;
					strncpy(ret.name, ptCmd->session.account, sizeof(ret.name));
					return sendCmdToSuperServer(&ret,sizeof(ret));
				}
				/*
				shared_ptr<BillUser> OldUser = BillUserManager::getInstance()->getUserByID(ptCmd->session.accid);
				if (OldUser) {
					Cmd::stUserReLoginCmd send;
					OldUser->sendCmdToMe(&send, sizeof(send));
					Xlogger->error("[BILL LOGIN],account is already login %s(%u,%u)",
							ptCmd->session.account,ptCmd->session.accid,ptCmd->session.loginTempID);

					t_idinuse_Bill ret;
					ret.accid = ptCmd->session.accid;
					ret.loginTempID = ptCmd->session.loginTempID;
					ret.wdLoginID = ptCmd->session.wdLoginID;
					strncpy(ret.name, ptCmd->session.name, sizeof(ret.name));
					return sendCmdToSuperServer(&ret,sizeof(ret));
				}
				shared_ptr<BillUser> pUser(new BillUser(ptCmd->session.accid,ptCmd->session.loginTempID,ptCmd->session.account,ptCmd->session.client_ip,task));
				if (!pUser || !BillUserManager::getInstance()->addUser(pUser))
				{
					Xlogger->error("[BILL LOGIN],account login failed :½%s(%d,%d)"
							,ptCmd->session.account,ptCmd->session.accid,ptCmd->session.loginTempID);
					return true;
				}
				Xlogger->info("account login success ½%s%d,%d)",pUser->account,pUser->id,pUser->tempid);
				tCmd.session = ptCmd->session;
				*/

				return BillTaskManager::getInstance().broadcastByID(ptCmd->session.wdGatewayID,&tCmd,sizeof(tCmd));
			}
			break;
	}

	Xlogger->error("BillService::msgParse_SuperService(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

void BillService::final() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	//shutdown logical process
	Terminate();
	if (timetickThread)
		timetickThread->join();
	x_subnetservice::final();
}

void BillService::reloadConfig()
{
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","BillServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("BillServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","BillServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;
		daemon(1,1);
	}

	BillService::getInstance().main();
	BillService::delInstance();
	return EXIT_SUCCESS;
}

void BillService::exec() {
	while(!isTerminate()) {
		boost::this_thread::sleep_for(ms(2000));
		BillService::getInstance().superClient->doCmd();
	}
}
