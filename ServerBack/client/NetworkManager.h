#pragma once
#include "singleton.h"
#include <boost/asio.hpp>
#include "io_service_pool.h"
using namespace boost;

class ClientConn;

class NetworkManager : public Singleton<NetworkManager>
{
protected:

	io_service_pool io_service_pool_;
public:
	NetworkManager();
	~NetworkManager();
	asio::io_service& get_io_service()
	{
		return io_service_pool_.get_io_service();
	}

	void run()
	{
		io_service_pool_.run();
	}

	ClientConn* createClientConn();


};
