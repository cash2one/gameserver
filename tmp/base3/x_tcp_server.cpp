#include "x_tcp_server.h"

class chat_server
{
	public:
		chat_server(boost::asio::io_service& io_service,
				const tcp::endpoint& endpoint)
			: io_service_(io_service),
			acceptor_(io_service, endpoint)
	{
		start_accept();
	}

		void start_accept()
		{
			chat_session_ptr new_session(new chat_session(io_service_, room_));
			acceptor_.async_accept(new_session->socket(),
					boost::bind(&chat_server::handle_accept, this, new_session,
						boost::asio::placeholders::error));
		}

		void handle_accept(chat_session_ptr session,
				const boost::system::error_code& error)
		{
			if (!error)
			{
				session->start();
			}

			start_accept();
		}

	private:
		boost::asio::io_service& io_service_;
		tcp::acceptor acceptor_;
		chat_room room_;
};


