#include "x_subnetservice.h"

#include <iostream>
#include <string>
#include <deque>
#include "super_client.h"
#include "x_util.h"

template<> x_subnetservice* Singleton<x_subnetservice>::ms_Singleton = 0;

x_subnetservice::x_subnetservice(const std::string &name,const uint16_t wdType) 
	:x_service(name)
{
	superClient.reset(new super_client(io_service_pool_.get_io_service()));

	wdServerID   = 0;
	wdServerType = wdType;
	wdPort        = 0;
}

x_subnetservice::~x_subnetservice()
{
	Xlogger->debug("x_subnetservice::~x_subnetservice");
	serverList.clear();
}

bool x_subnetservice::init()
{
	Xlogger->debug("x_subnetservice::init");
	if (!x_service::init())
		return false;

	pstrIP = getIPByIfName(Seal::global["ifname"].c_str());
	Xlogger->debug("ip=%s", pstrIP.c_str());
	//create connect to super server
	if (!superClient->connect(Seal::global["server"], atoi(Seal::global["port"].c_str())))
	{
		Xlogger->error("connect to super server (%s:%s) failed",Seal::global["server"].c_str(),Seal::global["port"].c_str());
		return false;
	}

	//send login cmd to super server
	Cmd::Super::t_Startup_Request tCmd;
	tCmd.wdServerType = wdServerType;
	strncpy(tCmd.pstrIP, pstrIP.c_str(), sizeof(tCmd.pstrIP));
	Xlogger->debug("type=%u,ip=%s", wdServerType, pstrIP.c_str());
	if (!superClient->sendCmd(&tCmd,sizeof(tCmd)))
	{
		Xlogger->error("send cmd to super server");
		return false;
	}
	Xlogger->debug("waiting startup");

	//wait super server to response
	while(!superClient->verified) {
		uint8_t pstrCmd[65535];
		int nCmdLen = superClient->read_cmd(pstrCmd, sizeof(pstrCmd));    
		if (-1 == nCmdLen) {
			Xlogger->error("wait superserver response failed");
			return false;
		}
		else if (nCmdLen > 0) {
			if (!superClient->msgParse_Startup((Cmd::t_NullCmd *)pstrCmd,nCmdLen)) {
				Xlogger->error("subnet msgParse (%d:%d)",((Cmd::t_NullCmd *)pstrCmd)->cmd, ((Cmd::t_NullCmd *)pstrCmd)->para);
				return false;
			}
		}
	}
	superClient->start();

	Xlogger->info("x_subnetservice::init %d,%d,%s:%d",wdServerType,wdServerID,pstrIP.c_str(),wdPort);
	//superThread.reset(new boost::thread(bind(&boost::asio::io_service::run, &io_service_)));
	std::ostringstream os;
	os<<wdPort;
	tcpServer.reset(new server(pstrIP,os.str(),io_service_pool_,boost::bind(&x_subnetservice::newTCPTask,this,_1)));

	return true;
}

bool x_subnetservice::validate() {
	Cmd::Super::t_Startup_OK tCmd;

	Xlogger->debug("x_subnetservice::validate");  
	tCmd.wdServerID = wdServerID;
	superClient->async_write(&tCmd,sizeof(tCmd));
	return true;
}

void x_subnetservice::final()
{
	Xlogger->debug("x_subnetservice::final");

	if (superClient) {
		superClient.reset();
	}
	//close super client
	/*
	if (!io_service_.stopped())
		io_service_.stop();
		*/
	/*
	if (superThread)
		superThread->join();
		*/
}

bool x_subnetservice::sendCmdToSuperServer(const void *pstrCmd,const int nCmdLen)
{
	//Xlogger->debug("x_subnetservice::sendCmdToSuperServer");
	return superClient->sendCmd(pstrCmd,nCmdLen);
}

void x_subnetservice::setServerInfo(const Cmd::Super::t_Startup_Response *ptCmd)
{  
	//Xlogger->info("x_subnetservice::setServerInfo(%d,%s:%d) %s",wdServerID,ptCmd->pstrExtIP,wdPort,pstrIP.c_str());
	wdServerID = ptCmd->wdServerID;
	wdPort     = ptCmd->wdPort;
	//pstrIP = ptCmd->pstrIP;  
	for(uint16_t i = 0; i < ptCmd->wdSize; i++) {
		addServerEntry(ptCmd->entry[i]);
	}
}

void x_subnetservice::addServerEntry(const Cmd::Super::ServerEntry &entry)
{
	Xlogger->error("-----x_subnetservice::addServerEntry(%d,%s:%d,%u)------",entry.wdServerID,entry.pstrIP,entry.wdPort,entry.state);

	boost::mutex::scoped_lock lock(mlock);
	//check if it is already in deque
	std::deque<Cmd::Super::ServerEntry>::iterator it;
	bool found = false;
	for(it = serverList.begin(); it != serverList.end(); it++)
	{
		if (entry.wdServerID == it->wdServerID)
		{
			found = true;
			(*it) = entry;
			break;
		}
	}
	if (!found)
		serverList.push_back(entry);
}

const Cmd::Super::ServerEntry *x_subnetservice::getServerEntryById(const uint16_t wdServerID)
{
	Xlogger->debug("x_subnetservice::getServerEntryById(%d)",wdServerID);
	Cmd::Super::ServerEntry *ret = NULL;
	std::deque<Cmd::Super::ServerEntry>::iterator it;

	boost::mutex::scoped_lock lock(mlock);
	for(it = serverList.begin(); it != serverList.end(); it++)
	{
		if (wdServerID == it->wdServerID)
		{
			ret = &(*it);
			break;
		}
	}
	return ret;
}

const Cmd::Super::ServerEntry *x_subnetservice::getServerEntryByType(const uint16_t wdServerType)
{
	Xlogger->debug("x_subnetservice::getServerEntryByType(type=%d)",wdServerType);
	Cmd::Super::ServerEntry *ret = NULL;
	std::deque<Cmd::Super::ServerEntry>::iterator it;
	
	boost::mutex::scoped_lock lock(mlock);
	for(it = serverList.begin(); it != serverList.end(); it++)
	{
		if (wdServerType == it->wdServerType)
		{
			ret = &(*it);
			break;
		}
	}
	return ret;
}

const Cmd::Super::ServerEntry *x_subnetservice::getNextServerEntryByType(const uint16_t wdServerType,const Cmd::Super::ServerEntry **prev)
{
	Xlogger->debug("x_subnetservice::getNextServerEntryByType");
	Cmd::Super::ServerEntry *ret = NULL;
	bool found = false;
	std::deque<Cmd::Super::ServerEntry>::iterator it;

	boost::mutex::scoped_lock lock(mlock);
	for(it = serverList.begin(); it != serverList.end(); it++)
	{
		Xlogger->debug("服务器信息：%d,%d",wdServerType,it->wdServerType);
		if (wdServerType == it->wdServerType)
		{
			if (NULL == prev || found)
			{
				ret = &(*it);
				break;
			}
			else if (!found && (*prev)->wdServerID == it->wdServerID)
			{
				found = true;
			}
		}
	}
	return ret;
}

