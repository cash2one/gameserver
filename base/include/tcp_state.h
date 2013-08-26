#pragma once

#include "tcp_task.h"

class tcp_state
{
	shared_ptr<tcp_task> task_;
public:
	tcp_state(shared_ptr<tcp_task> task):task_(task){
		start();
	}
	virtual void start(){}
	virtual void run(){}

	virtual void msg_parse(){}

	virtual void read_error(){}
	virtual void write_error(){}
	virtual void timeout(const boost::system::error_code& error){}

	//调用这个函数之后不能访问非静态任何成员,因为对象已经被析够掉了
	virtual void get_next_state() = 0;

	virtual ~tcp_state(){}
};

class state_verify: public tcp_state{
private:
	dealline_timer timer_;
public:
	state_verify(shared_ptr<tcp_task> task):tcp_state(task){
	}
	virtual void start(){
		timer_.expires_from_now(boost::posix_time::seconds(3));
		timer_.async_wait(bind(&state_verify::timeout, shared_from_this()));
		task_->async_read_msg();
	}
	virtual void run(){}

	virtual void msg_parse(const Cmd::t_NullCmd * cmd, uint32_t len){
		timer_.cancel();
		if (cmd->cmd == 0){
			//read error
			return;
		}
		if (cmd->cmd == 1 && cmd->para = 1) {
			if (task_->unique_add()){
				get_next_state();
			}
		}
		else {
			Xlogger->debug("verify failed");
		}
	}

	virtual void read_error(){ timer_.cancel(); }
	virtual void write_error(){ timer_.cancel(); }
	virtual void timeout(const boost::system::error_code& error){
		//delete self;
		task_->set_state(0);
	}

	virtual void get_next_state(){
		task_->set_state(new state_wait_sync(task_));
	}
};

class state_wait_sync: public tcp_state{
private:
	dealline_timer timer_;
public:
	state_wait_sync(shared_ptr<tcp_task> task):tcp_state(task){
	}
	virtual void start(){
		timer_.expires_from_now(boost::posix_time::seconds(3));
		timer_.async_wait(bind(&state_wait_sync::timeout, shared_from_this()));
		task_->async_read_msg();
		get_next_state();
	}
	virtual void run(){}

	virtual void msg_parse(const Cmd::t_NullCmd * cmd, uint32_t len){
		timer_.cancel();
		if (cmd->cmd == 0){
			//read error
			task_->set_state(0);
			return;
		}
		if (cmd->cmd == 1 && cmd->para = 1) {
			task_->add_to_container();
			get_next_state();
		}
		else {
			Xlogger->debug("verify failed");
			task_->set_state(0);
		}
	}

	virtual void read_error(){ timer_.cancel(); }
	virtual void write_error(){ timer_.cancel(); }
	virtual void timeout(const boost::system::error_code& error){
		//delete self;
		task_->set_state(0);
	}

	virtual void get_next_state(){
		task_->set_state(new state_okay(task_));
	}
};

class state_okay: public tcp_state{
};
