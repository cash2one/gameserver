#include "NetworkManager.h"
#include "ClientConn.h"

template<>
NetworkManager* Singleton<NetworkManager>::ms_Singleton = NULL;

NetworkManager::NetworkManager():io_service_pool_(1)
{
}

NetworkManager::~NetworkManager()
{
}

ClientConn* NetworkManager::createClientConn()
{
	return new ClientConn(io_service_pool_.get_io_service());
}
