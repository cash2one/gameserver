#pragma once

#include "common.h"
#include <string>
#include "tinyxml.h"

class x_config
{
	public:
		x_config(const std::string& file, const std::string& node);
		bool load();
	private:
		std::string file_;
		std::string node_;
};
