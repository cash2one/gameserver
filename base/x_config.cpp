#include "x_config.h"
#include "x_properties.h"
#include <sstream>

x_config::x_config(const std::string& file, const std::string& node)
{
	file_ = file;
	node_ = node;
	load();
}

bool x_config::load()
{
	TiXmlDocument doc(file_);
	if(!doc.LoadFile())
	{
		Xlogger->error("can not load xml file : %s, error : %s",doc.Value(), doc.ErrorDesc());
		return false;
	}
	TiXmlElement* pconfig = doc.FirstChildElement("Config");
	if (pconfig)
	{
		//load global
		TiXmlElement* pglobal = pconfig->FirstChildElement("global");
		if (pglobal)
		{
			for (TiXmlElement* element = pglobal->FirstChildElement();element;element = element->NextSiblingElement())
			{
				if (element->GetText())
					Seal::global[element->ValueStr()] = element->GetText();
			}
		}

		//load custom
		TiXmlElement* pcustom = pconfig->FirstChildElement(node_);
		if (pcustom)
		{
			for (TiXmlElement* element = pcustom->FirstChildElement();element;element = element->NextSiblingElement())
			{
				if (element->GetText())
					Seal::global[element->ValueStr()] = element->GetText();
			}
			std::ostringstream os;
			Seal::global.dump(os);
			Xlogger->debug(os.str().c_str());
			return true;
		}
	}
	return false;
}
