
#pragma once
#include "common.h"
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

using namespace boost;
using namespace boost::asio;

class tcp_task;
typedef boost::shared_ptr<tcp_task> task_state_ptr;
typedef boost::weak_ptr<tcp_task> task_weak_ptr;

class task_state : public enable_shared_from_this<task_state>
{
protected:
	task_weak_ptr task_weak_;
public:
	task_state(task_weak_ptr task):task_weak_(task){}
	virtual void on_change_state() = 0;
	virtual void handle_timeout(const boost::system::error_code& error){}
	virtual void handle_error(const boost::system::error_code& error){}
	virtual void handle_msg(const void* ptr, const uint32_t len){}
	virtual const char* get_name() const = 0;
	virtual ~task_state() {}
};

typedef shared_ptr<task_state> state_ptr;

//verify -> wait_sync -> okay ->closed
class state_verify : public task_state
{
	bool waiting;
public:
	state_verify(task_weak_ptr task):task_state(task){waiting = true;}
	virtual void on_change_state() ;
	virtual void handle_timeout(const boost::system::error_code& error);
	virtual void handle_error(const boost::system::error_code& error);
	virtual void handle_msg(const void* ptr, const uint32_t len);
	const char* get_name() const { return "verify";}
};
class state_wait_sync : public task_state
{
	bool waiting;
public:
	state_wait_sync(task_weak_ptr task):task_state(task){waiting = true;}
	void on_change_state();
	virtual void handle_timeout(const boost::system::error_code& error);
	virtual void handle_error(const boost::system::error_code& error);
	virtual void handle_msg(const void* ptr, const uint32_t len);
	const char* get_name() const { return "wait_sync";}
};
//no need for sync
class state_no_wait_sync : public task_state
{
public:
	state_no_wait_sync(task_weak_ptr task):task_state(task){}
	void on_change_state();
	const char* get_name() const { return "no_wait_sync";}
};
class state_okay : public task_state
{
public:
	state_okay(task_weak_ptr task):task_state(task){}
	void on_change_state();
	virtual void handle_timeout(const boost::system::error_code& error);
	virtual void handle_error(const boost::system::error_code& error);
	virtual void handle_msg(const void* ptr, const uint32_t len);
	const char* get_name() const { return "okay";}
};
class state_closed : public task_state
{
public:
	state_closed(task_weak_ptr task):task_state(task){}
	void on_change_state();
	const char* get_name() const { return "closed";}
};

class state_wait : public task_state
{
public:
	state_wait(task_weak_ptr task):task_state(task){}
	void on_change_state();
	virtual void handle_timeout(const boost::system::error_code& error);
	virtual void handle_error(const boost::system::error_code& error);
	const char* get_name() const { return "wait";}
};
