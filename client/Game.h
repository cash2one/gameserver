#pragma once
#include "singleton.h"
#include "ClientConn.h"

//class ClientConn;
extern ClientConn* gClient;

class Game : public Singleton<Game>
{
	public:
		Game();
		virtual ~Game();

		virtual bool init();

		virtual bool login(const std::string username, const std::string passwd);
};
