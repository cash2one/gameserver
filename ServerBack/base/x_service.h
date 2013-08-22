#ifndef _SERVICE_H_
#define _SERVICE_H_

#include "common.h"
#include <string>
#include <boost/utility.hpp>
#include "x_properties.h"
#include "io_service_pool.h"
//#include <boost/enable_shared_from_this.hpp>

class x_service : private boost::noncopyable
{
public:
	virtual ~x_service() {}
	bool isTerminate() const { return terminate; }
	virtual void Terminate() { 
		terminate = true; 
		io_service_pool_.stop();
	}
	//signal process
	virtual void handleInterrupt() { Terminate();}
	virtual void handleHup() {}

	void main();
	virtual void exec() = 0;
	x_properties env;        /**< 存储当前运行系统的环境变量 */

protected:
	x_service(const std::string &name):
		name_(name),
		io_service_pool_(atoi(Seal::global["threadsNum"].c_str())),
		signals_int_(io_service_pool_.get_io_service()),
		signals_hup_(io_service_pool_.get_io_service())
	{ 
		terminate = false; 
	}

	virtual bool init();

	/**
	* \brief 确认服务器初始化成功，即将进入主回调函数
	*
	* \return 确认是否成功
	*/
	virtual bool validate() { return true; }
	virtual void run() {
		io_service_pool_.run();
	}

	/**
	* \brief 结束服务器程序，回收资源，纯虚函数，子类需要实现这个函数
	*
	*/
	virtual void final() = 0;

	std::string name_;          /**< 服务名称 */
	bool terminate;            /**< 服务结束标记 */

	io_service_pool io_service_pool_;
	boost::asio::signal_set signals_int_;
	boost::asio::signal_set signals_hup_;
};

#endif
