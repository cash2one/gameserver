#include "x_logger.h"
#include <stdarg.h>
#include <stdio.h>

#define avar(buff, len, pat) \
	va_list ap;\
	va_start(ap, pat);\
	vsnprintf(buff, len-1, pat, ap);\
	buff[len-1] = '\0';\
	va_end(ap);

x_logger::x_logger(log4cxx::LoggerPtr log):logger(log)
{
}

void x_logger::trace(const char * pattern,...)
{
	boost::mutex::scoped_lock lock( io_mutex );
	avar(buff,MAX_LOG_SIZE,pattern);
	logger->trace(buff);
}

void x_logger::debug(const char * pattern,...)
{
	boost::mutex::scoped_lock lock( io_mutex );
	avar(buff,MAX_LOG_SIZE,pattern);
	logger->debug(buff);
}

void x_logger::info(const char * pattern,...)
{
	boost::mutex::scoped_lock lock( io_mutex );
	avar(buff,MAX_LOG_SIZE,pattern);
	logger->info(buff);
}

void x_logger::warn(const char * pattern,...)
{
	boost::mutex::scoped_lock lock( io_mutex );
	avar(buff,MAX_LOG_SIZE,pattern);
	logger->warn(buff);
}

void x_logger::error(const char * pattern,...)
{
	boost::mutex::scoped_lock lock( io_mutex );
	avar(buff,MAX_LOG_SIZE,pattern);
	logger->error(buff);
}

void x_logger::fatal(const char * pattern,...)
{
	boost::mutex::scoped_lock lock( io_mutex );
	avar(buff,MAX_LOG_SIZE,pattern);
	logger->fatal(buff);
}

x_logger::~x_logger()
{
	logger->debug(__PRETTY_FUNCTION__);
}
