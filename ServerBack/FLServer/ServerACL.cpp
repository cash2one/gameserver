#include "ServerACL.h"
#include "tinyxml.h"

template<> ServerACL* Singleton<ServerACL>::ms_Singleton = NULL;

bool ServerACL::add(const ACLZone &zone)
{
	Container::const_iterator it = datas.find(zone.gameZone);
	if (it == datas.end())
	{
		std::pair<Container::iterator,bool> p = datas.insert(Container::value_type(zone.gameZone,zone));
		return p.second;
	}
	else
		return false;
}

bool ServerACL::init() {
	boost::mutex::scoped_lock lock(mutex_);
	datas.clear();

	std::string file(Seal::global["configdir"] + "zoneInfo.xml");
	TiXmlDocument doc(file);
	if(!doc.LoadFile()) {
		Xlogger->error("can not load xml file : %s, error : %s",doc.Value(), doc.ErrorDesc());
		return false;
	}
	TiXmlElement* pconfig = doc.FirstChildElement("zoneInfo");
	if (pconfig) {
		TiXmlElement* pZone = pconfig->FirstChildElement("zone");
		while (pZone)
		{
			ACLZone zone;
			pZone->QueryValueAttribute("game",&zone.gameZone.game);
			pZone->QueryValueAttribute("zone",&zone.gameZone.zone);
			pZone->QueryValueAttribute("ip",&zone.ip);
			pZone->QueryValueAttribute("port",&zone.port);
			pZone->QueryValueAttribute("name",&zone.name);
			pZone->QueryValueAttribute("desc",&zone.desc);
			Xlogger->warn("game=%u,zone=%u,ip=%s,port=%u,name=%s,desc=%s", zone.gameZone.game, zone.gameZone.zone,
					zone.ip.c_str(), zone.port, zone.name.c_str(), zone.desc.c_str());
			if (!add(zone)) {
			}

			pZone = pZone->NextSiblingElement("zone");
		}
	}
	Xlogger->debug("[ZONEINFO],size = %lu", datas.size());
	return true;
}

void ServerACL::final()
{
	Xlogger->debug("ServerACL::final");
	boost::mutex::scoped_lock(mutex_);
	datas.clear();
}

bool ServerACL::check(const char *strIP,const WORD port,GameZone_t &gameZone,std::string &name) {
	boost::mutex::scoped_lock(mutex_);
	for(Container::const_iterator it = datas.begin(); it != datas.end(); ++it) {
		if (it->second.ip == strIP && it->second.port == port) {
			gameZone = it->first;
			name = it->second.name;
			return true;
		}
	}
	return false;
}

