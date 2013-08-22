#include "common.h"
#include "x_service.h"

bool x_service::init()
{
	signals_int_.add(SIGINT);
	signals_int_.add(SIGTERM);
#if defined(SIGQUIT)
	signals_int_.add(SIGQUIT);
#endif // defined(SIGQUIT)
	signals_int_.async_wait(boost::bind(&x_service::handleInterrupt, this));

	signals_hup_.add(SIGHUP);
	signals_hup_.async_wait(boost::bind(&x_service::handleHup, this));

	srand(time(NULL));
	return true;
}

void x_service::main() {
	if (init() && validate()) {
		run();
	}
	final();
}


