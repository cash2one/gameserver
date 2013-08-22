#include <boost/asio.hpp>
#include <iostream>
#include <strings.h>
using namespace std;
using namespace boost;
using namespace boost::asio;

/*
class connection
{
	ip::tcp::socket sock;
	public:
	enum
	{
		PACK_ENCRYPT = 0x80000000,
		PACK_ZIP = 0x40000000,
	};
	public:
	void send_cmd(void* ptr, const size_t len)
	{
		const uint32_t nenc = len + 2;
		const uint32_t nflag = nenc;
		nflag &= PACK_ENCRYPT;
		if (len > 32)
			nflag &= PACK_ZIP;
	}
};
*/

int main()
{
	cout<<"client start"<<endl;
	io_service ios;
	ip::tcp::socket sock(ios);

	ip::tcp::endpoint ep(ip::address::from_string("127.0.0.1"),30000);
	boost::system::error_code ec;
	sock.connect(ep,ec);

	if (ec)
	{
		cout<<"connect error"<<endl;
		cout<<ec<<endl;
		return 1;
	}

	string str("hello world");

	uint32_t len = str.size();
	vector<char> sendbuf(4+len);
	bcopy((char*)&len,&sendbuf[0],4);
	bcopy(str.c_str(),&sendbuf[4],len);
	
	sock.write_some(buffer(sendbuf));

	vector<char> v(100,0);
	size_t n = sock.read_some(buffer(v));
	cout<< n <<endl;
	cout<< &v[0] << endl;
	return 0;
}

