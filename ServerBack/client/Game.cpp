#include "Game.h"
#include "common.h"
#include "NetworkManager.h"

ClientConn* gClient = NULL;

template<>
Game* Singleton<Game>::ms_Singleton = NULL;

Game::Game()
{
}

Game::~Game()
{
	Xlogger->debug("%s,%d ok",__PRETTY_FUNCTION__,__LINE__);
}

bool Game::init()
{
	gClient = NetworkManager::getSingleton().createClientConn();
	Xlogger->debug("%s,%d ok",__PRETTY_FUNCTION__,__LINE__);
	return true;
}

bool Game::login(const std::string username, const std::string passwd)
{
	const std::string serverip = Seal::global["server"];
	const unsigned short  port = atoi(Seal::global["port"].c_str());
	if (!gClient->connect(serverip, port))
	{
		Xlogger->error("connet to Server failed: ip=%s,port=%u", serverip.c_str(),port);
		return false;
	}
	Xlogger->debug("connect ok");

	{
		Cmd::stUserVerifyVerCmd cmd;
		cmd.version = 123;
		gClient->sendCmd(&cmd, sizeof(cmd));
	}


	{
		Cmd::stUserRequestLoginCmd cmd;
		strncpy(cmd.pstrName, username.c_str(),sizeof(cmd.pstrName));
		strncpy(cmd.pstrPassword, passwd.c_str(),sizeof(cmd.pstrPassword));
		//later add other fields
		gClient->sendCmd(&cmd, sizeof(cmd));
	}
	return true;
}
