#include "common.h"

namespace Seal
{
	using namespace boost;
	volatile uint64_t qwGameTime = 0;

	x_logger* logger = NULL;

	x_properties global;

	/*
	static void initGlobal()  __attribute__ ((constructor));
	void initGlobal()
	{
		global["threadPoolClient"] = "512";
		global["threadPoolServer"] = "2048";
		global["server"]           = "127.0.0.1";
		global["port"]             = "10000";
		global["ifname"]           = "127.0.0.1";
		global["mysql"]            = "mysql://zebra:zebra@127.0.0.1:3306/zebra";
		global["log"]              = "error";
	}
	static void finalGlobal() __attribute__ ((destructor));
	void finalGlobal()
	{
		//SAFE_DELETE(logger);
	}
	*/
};
