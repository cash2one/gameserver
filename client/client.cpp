#include "common.h"
#include <iostream>
#include "x_config.h"
#include <string>

#include "NetworkManager.h"
#include "Game.h"
using namespace std;
using namespace boost;


int main()
{
	using namespace std;
	using namespace log4cxx;
	Seal::global["configdir"] = "./Config/";
	//init logger first
	PropertyConfigurator::configure(Seal::global["configdir"] + "conf.log");
	Xlogger = (new x_logger(Logger::getLogger("Client")));

	new Game();
	new NetworkManager();

	//parse config file para
	x_config config(Seal::global["configdir"] + "client.xml","Client");

	if (!Game::getSingleton().init())
	{
		Xlogger->debug("Game init failed");
		return 0;
	}

	if (!Game::getSingleton().login(Seal::global["username"],Seal::global["passwd"]))
	{
		Xlogger->debug("Game login failed");
		return 0;
	}

	//gClient->start();
	/*
	Cmd::Record::t_LoginRecord tCmd;
	tCmd.wdServerID = wdServerID;
	tCmd.wdServerType = wdServerType;
	gClient->sendCmd(&tCmd, sizeof(tCmd));
	*/

	Xlogger->debug("client running");
	cout<<"hello world"<<endl;
	NetworkManager::getSingleton().run();
	return 0;
}
