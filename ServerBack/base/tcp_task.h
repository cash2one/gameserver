#pragma once
#include "common.h"
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include "x_nullcmd.h"
#include <string>
//#include "task_state.h"

using namespace boost;
using namespace boost::asio;

class task_state;

typedef shared_ptr<task_state> state_ptr;

class tcp_task : public enable_shared_from_this<tcp_task> {
	friend class state_closed;
	friend class state_verify;
	friend class state_okay;
	friend class state_wait_sync;
	friend class state_no_wait_sync;
	friend class state_wait;
public:
	tcp_task(io_service& ios);
	virtual ~tcp_task();
	const std::string get_remote_ip() const;
	void set_state(state_ptr state);
	const std::string get_state_name() const;
	virtual void start();
	virtual bool uniqueAdd(){return true;}
	virtual bool uniqueRemove(){return true;}
	virtual void addToContainer(){}
	virtual void removeFromContainer(){}
	//virtual bool verify_msg(const Cmd::t_NullCmd* cmd, const uint32_t len) { return false; }
	//virtual bool wait_sync_msg(const Cmd::t_NullCmd* cmd, const uint32_t len) { return false; }

	virtual void handle_verify(const void* ptr, const uint32_t len) = 0;
	//virtual void handle_timeout(const boost::system::error_code& error) = 0;
	virtual void handle_wait_sync(const void* ptr, const uint32_t len){}

	virtual void async_read();
	bool sendCmd(const void* data, const int len);

	io_service & get_io_service(){ return ios_; }
	ip::tcp::socket & get_socket(){ return sock_; }
	virtual void handle_msg(const void* ptr, const uint32_t len) = 0; 
private:
	void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred);
	void handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred);
	bool decode_header();
	void handle_write( const boost::system::error_code& error, std::size_t bytes_transferred);
protected:
	void handle_error(const boost::system::error_code& error);
	virtual void close();
protected:
	boost::asio::io_service& ios_;
	boost::asio::ip::tcp::socket sock_;
	boost::asio::deadline_timer timer_;

	state_ptr state_verify_;
	state_ptr state_closed_;
	state_ptr state_okay_;
	state_ptr state_;

	typedef asio::streambuf buffer_type;
	//buffer_type m_read_buf;
	buffer_type m_write_buf;

	char header_[PH_LEN];
	uint16_t msg_length_;
	char msg_[MAX_MSG_SIZE];

};

typedef boost::shared_ptr<tcp_task> tcp_task_ptr;
