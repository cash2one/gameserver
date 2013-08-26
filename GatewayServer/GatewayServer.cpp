#include "GatewayServer.h"
#include "x_config.h"
#include <stdlib.h>
#include <string.h>
#include <boost/ref.hpp>
#include <boost/thread.hpp>
#include "GatewayTask.h"
#include "RecordClient.h"
#include "SessionClient.h"
#include "BillClient.h"
#include <boost/chrono.hpp>
#include <ctime>
//#include <boost/timer.hpp>
#include "super_client.h"
//#include "LoginSessionManager.h"
typedef boost::chrono::milliseconds ms;

GatewayService* GatewayService::instance = NULL;

bool GatewayService::notifyLoginServer()
{
  Xlogger->debug("GatewayService::notifyLoginServer");
  using namespace Cmd::Super;
  t_GYList_Gateway tCmd;

  tCmd.wdServerID = wdServerID;
  tCmd.wdPort     = wdPort;
  tCmd.dwpstrIP = inet_addr(pstrIP.c_str());
  tCmd.wdNumOnline = 100;
  tCmd.state = 1;
  tCmd.zoneGameVersion = verify_client_version;

  Xlogger->debug("[GS], gateway current user count = %d",tCmd.wdNumOnline);

  return sendCmdToSuperServer(&tCmd,sizeof(tCmd));
}

bool GatewayService::msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen)
{
	using namespace Cmd::Super;
	if (CMD_GATEWAY == pNullCmd->cmd)
	{
		switch(pNullCmd->para)
		{
			case PARA_GATEWAY_RQGYLIST:
				return notifyLoginServer();
		}
	}
	return false;
}

bool GatewayService::init() {
	Xlogger->debug("%s",__PRETTY_FUNCTION__);

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
	{
		const Cmd::Super::ServerEntry *serverEntry = getServerEntryByType(BILLSERVER);
		if (!serverEntry) {
			Xlogger->error("can't find billserver info");
			return false;
		}
		billClient.reset(new BillClient(io_service_pool_.get_io_service()));
		if (!billClient->connect(serverEntry->pstrIP, serverEntry->wdPort)){
			Xlogger->error("connet to Bill Server failed: ip=%s,port=%u",serverEntry->pstrExtIP,serverEntry->wdExtPort);
			return false;
		}
		billClient->start();
		Cmd::Bill::t_LoginBill tCmd;
		tCmd.wdServerID = wdServerID;
		tCmd.wdServerType = wdServerType;
		billClient->sendCmd(&tCmd, sizeof(tCmd));
	}

	pLoginSessionM.reset(new LoginSessionManager());
	notifyLoginServer();
	//if (!GatewayUserM::getMe().init())
		//return false;
	
	//GatewayTimeTick
	//create logical thread
	timetickThread.reset(new boost::thread(boost::bind(&GatewayService::exec,this)));
	Xlogger->debug("init complete");

	//GatewayInfoManager::getMe().init();
	return true;
}

tcp_task_ptr GatewayService::newTCPTask(io_service& ios) {
	//can use object pool, for efficiency
	tcp_task_ptr tcpTask(new GatewayTask(ios));
	return tcpTask;
}

/*
bool GatewayService::msgParse_GatewayService(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	Xlogger->error("GatewayService::msgParse_GatewayService(%u,%u,%u)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}
*/

void GatewayService::final() {
	Xlogger->debug("GatewayService::final");

	//shutdown logical process
	terminate = true;
	if (timetickThread)
		timetickThread->join();
	x_subnetservice::final();

	/*
	while(!GatewayGatewayManager::getInstance().empty())
	{
		zThread::msleep(10);
	}
	*/
}

void GatewayService::reloadConfig() {
	Xlogger->debug("GatewayService::reloadConfig");
	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","GatewayServer");
}

int main(int argc,char **argv)
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";

	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("GatewayServer")));

	//parse config file para
	x_config config(Seal::global["configdir"] + "config.xml","GatewayServer");

	//default command line para

	//Xlogger->setLevel(Seal::global["log"]);

	if ( Seal::global["daemon"] == "1" )
	{
		Xlogger->info("Program will be run as a daemon");
		cout<<"Program will be run as a daemon"<<endl;
		daemon(1,1);
	}

	GatewayService::getInstance().main();
	GatewayService::delInstance();
	return EXIT_SUCCESS;
}

void GatewayService::exec() {
	while(!isTerminate())
	{
		boost::this_thread::sleep_for(ms(1000));
		currentTime = microsec_clock::local_time();

		superClient->doCmd();
		recordClient->doCmd();
		sessionClient->doCmd();

		LoginSessionManager::getSingleton().update(currentTime);
		static ptime ti = currentTime;
		if (currentTime > ti + seconds(5)){
			Xlogger->debug("gateway elapsed time 5s");
			ti = currentTime;
			Cmd::Record::t_Test_GatewayRecord test;
			recordClient->async_write(&test, sizeof(test));

			Cmd::Session::t_GatewaySession_Test test1;
			sessionClient->async_write(&test1, sizeof(test1));
		}
	}
}
