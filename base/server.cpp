#include "server.h"
#include <boost/bind.hpp>

server::server(const std::string& address, const std::string& port, io_service_pool& pool, handle_new_task_t task_handle) 
	:io_service_pool_(pool), acceptor_(io_service_pool_.get_io_service())
{
	// Register to handle the signals that indicate when the server should exit.
	// It is safe to register for the same signal multiple times in a program,
	// provided all registration for the specified signal is made through Asio.
	new_tcp_task_ = task_handle;

	// Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
	boost::asio::ip::tcp::resolver resolver(acceptor_.get_io_service());
	boost::asio::ip::tcp::resolver::query query(address, port);
	boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
	acceptor_.open(endpoint.protocol());
	acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	acceptor_.bind(endpoint);
	acceptor_.listen();

	start_accept();
}

void server::run() {
	io_service_pool_.run();
}

void server::start_accept() {
	shared_ptr<tcp_task> new_task = new_tcp_task_(io_service_pool_.get_io_service());
	if (new_task)
		acceptor_.async_accept(new_task->get_socket(), boost::bind(&server::handle_accept,this, new_task, boost::asio::placeholders::error));
}

void server::handle_accept(shared_ptr<tcp_task> new_task, const boost::system::error_code& e) {
	if (!e) {
		new_task->start();
	}

	start_accept();
}

