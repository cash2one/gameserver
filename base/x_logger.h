#pragma once

#include <log4cxx/logger.h>
#include <log4cxx/logstring.h>
#include <log4cxx/propertyconfigurator.h>
#include <boost/thread/mutex.hpp>

/*
* a simple wrapper to log4cxx::LoggerPtr
*/
class x_logger: boost::noncopyable
{
public:
	static const int MAX_LOG_SIZE = 4096;

	x_logger(log4cxx::LoggerPtr log);
	~x_logger();

	log4cxx::LoggerPtr operator->()
	{
		return logger;
	}
	
	const log4cxx::LoggerPtr operator->() const
	{
		return logger;
	}

	void trace(const char * pattern,...);
	void debug(const char * pattern,...);
	void info(const char * pattern,...);
	void warn(const char * pattern,...);
	void error(const char * pattern,...);
	void fatal(const char * pattern,...);
private:
	boost::mutex io_mutex;	//for thread safe
	log4cxx::LoggerPtr logger;
	char buff[MAX_LOG_SIZE];
};
