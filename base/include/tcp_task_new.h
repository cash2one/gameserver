#pragma once
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>

using namespace boost;
using namespace boost::asio;

class tcp_task
{
	dealline_timer timer_;
	boost::function<void (void*,uint32_t)> msg_parser_;
public:
	tcp_task(io_service& ios):ios_(ios),socket_(ios_),timer_(ios_){
	}
	//start->verify->wait_sync->work->del
	virtual void start(){
		verify();
	}
	virtual void verify(){
		//验证时候的消息处理函数
		msg_parse_ = bind(&tcp_task::handle_verify,this,_1,_2);
		//超时处理
		timer_.expires_from_now(boost::posix_time::seconds(5));
		timer_.async_wait(bind(&tcp_task::handle_verify_timeout,this));
		//post a read request
		async_read_msg();
	}
	virtual void wait_sync(){
		//如果不需要同步 可以直接调用work()
	}
	virtual void work(){
		msg_parse_ = bind(&tcp_task::msg_parse, this , _1, _2);
		async_read_msg();
	}

	virtual void handle_verify(const void* ptr, const uint32_t len)
	{
		Cmd::t_NullCmd * cmd = (Cmd::t_NullCmd)ptr;
		if (cmd->cmd == 0){
			//read error
			return;
		}
		if (cmd->cmd == 1 && cmd->para = 1) {
			//put shared_from_this() to container

			async_read_msg();
		}
		else {
			Xlogger->debug("verify failed");
		}
	}
	
	io_service & get_io_service(){ return ios_; }
	ip::tcp::socket & get_socket(){ return socket_; }

	void handle_verify_timeout(const boost::system::error_code& error)
	{
		if (!error){
		}
		close();
	}
	virtual void async_read_msg(){
		boost::asio::async_read(boost::asio::buffer(header_),bind(&tcp_task::handle_read_header,shared_from_this(),_1));
	}
};
