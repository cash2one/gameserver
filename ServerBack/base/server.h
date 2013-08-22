#pragma once

#include <boost/asio.hpp>
#include <string>
#include <vector>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
//#include "connection.hpp"
#include "tcp_task.h"
#include "io_service_pool.h"
#include <boost/function.hpp>

class server : private boost::noncopyable
{
	public:
		typedef boost::function<tcp_task_ptr (io_service&)> handle_new_task_t;
		/// Construct the server to listen on the specified TCP address and port, and
		/// serve up files from the given directory.
		explicit server(const std::string& address, 
				const std::string& port, 
				io_service_pool& pool,
				boost::function<tcp_task_ptr (io_service&)> func);

		/// Run the server's io_service loop.
		void run();

	private:
		/// Initiate an asynchronous accept operation.
		void start_accept();

		/// Handle completion of an asynchronous accept operation.
		void handle_accept(shared_ptr<tcp_task> new_task, const boost::system::error_code& e);


		//for acceptor
		/// The pool of io_service objects used to perform asynchronous operations.
		io_service_pool& io_service_pool_;

		/*
		/// The signal_set is used to register for process termination notifications.
		boost::asio::signal_set signals_;
		*/

		/// Acceptor used to listen for incoming connections.
		boost::asio::ip::tcp::acceptor acceptor_;

		/// The handler for all incoming requests.
		//request_handler request_handler_;
		//boost::function<tcp_task_ptr (io_service&)> new_tck_task_;
		handle_new_task_t new_tcp_task_;
};

