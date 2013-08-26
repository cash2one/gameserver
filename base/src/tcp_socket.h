#pragma once
#include <boost/asio.hpp>
#include <vector>
#include <strings.h>
#include <boost/bind.hpp>
#include <enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
using namespace boost;
using namespace boost::asio;

#define PH_LEN 4
#define MAX_MSG_SIZE 65535

struct processor
{
	virtual bool msg_parse(const void * ptr, const uint32_t len) = 0;
};

class tcp_socket : public enable_shared_from_this<tcp_socket>{
public:
	tcp_socket(io_service& ios, shared_ptr<processor> proc):sock_(ios),proc_(proc) {
		msg_length_ = 0;
	}
	virtual ~tcp_socket(){ }

	//conncet to server
	bool connect(const std::string& ip, const uint16_t port) {
		system::error_code ec;
		tcp::endpoint endpoint(ip::address::from_string(ip.c_str()), port);
		sock_.connect(endpoint, ec);
		if (ec) return false;
		else return true;
	}

	//send_cmd sync mode
	size_t sendCmd(const void* data, const size_t len) {
		//对data 进行压缩 加密 later
		std::vector<char> tmp(PH_LEN + len);
		uint32_t n = len;
		memcpy(&tmp[0], &n, PH_LEN);
		memcpy(&tmp[PH_LEN], data, len);
		return boost::asio::write(sock_, boost::asio::buffer(tmp));
	}

	//同步接收
	int read_cmd(void* ptr, const int nlen) {
		char header[PH_LEN] = {0};
		boost::asio::read(sock_,boost::buffer(header));
		uint32_t len = *(uint32_t *)header;
		if (len > 65535)
			return -1;	//error
		std::vector<char> raw(len);
		boost::asio::read(sock_, boost::buffer(raw));
		//解密
		//解压
		uint32_t reallen = len;
		if (realen > nlen)
			return -1;
		bcopy(&raw[0], ptr, reallen);
		return reallen;
	}

	void start() {
		boost::asio::async_read(boost::asio::buffer(header_),bind(&tcp_socket::handle_read_header,shared_from_this(),_1));
	}

	void async_write(void* data, const int len)
	{
		//对data 进行压缩 加密 later
		std::vector<char> tmp(PH_LEN + len);
		uint32_t n = len;
		bcopy(&n, &tmp[0], PH_LEN);
		bcopy(data, &tmp[PH_LEN],len);
		m_write_buf.sputn(&tmp[0], tmp.size());
		//send 
		sock_.async_write_some(m_write_buf.data(),bind(&tcp_socket::handle_write,shared_from_this(),_1,_2));
		//可以使用async_write 更简单 但使用async_write_some可能更高效
	}

	void handle_write( const boost::system::error_code& error, std::size_t bytes_transferred) {
		if(error) {
			close();
			return ;
		}
		m_write_buf.consume(bytes_transferred);	//头部的数据减少

		//没发完 继续发送
		if (m_write_buf.size() > 0)
			sock_.async_write_some(m_write_buf.data(),bind(&tcp_socket::handle_write,shared_from_this(),_1,_2));
	}

	void close() {
		boost::system::error_code ec;
		sock_.shutdown(ip::tcp::socket::shutdown_both, ec);
		sock_.close(ec);
	}

	void handle_read_header(const boost::system::error_code& error) {
		if (!error && decode_header()) {
			asio::async_read(asio::buffer(msg_),bind(&tcp_socket::handle_read_body,shared_from_this(),_1));
		}
		else
			close();
	}

	void handle_read_body(const boost::system::error_code& error) {
		if (!error) {
			//decode
			//uncompress
			uint32_t reallen = msg_length_;
			//put to cmd queue
			//msgParse(msg_, reallen);
			if (proc_)
				proc_->msg_parse(msg_, reallen);
			start();
		}
		else
			close();
	}
	//virtual bool cmdMsgParse(const Cmd::t_NullCmd *cmd, const uint32_t len) = 0;
	virtual bool decode_header() {
		msg_length_ = *(uint32_t*)header_;
		if (msg_length_ > MAX_MSG_SIZE)
		{
			msg_length_ = 0;
			return false;
		}
		else
			return true;
	}
	//virtual bool msgParse(void* ptr, const int len) {}
protected:
	ip::tcp::socket sock_;
	shared_ptr<processor> proc_;

	typedef asio::streambuf buffer_type;
	//buffer_type m_read_buf;
	buffer_type m_write_buf;

	char header_[PH_LEN];
	uint16_t msg_length_;
	char msg_[MAX_MSG_SIZE];
};
