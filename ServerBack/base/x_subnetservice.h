#pragma once
#include <deque>
#include <string>
#include "x_service.h"
//#include "x_netservice.h"
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/asio.hpp>
#include "server.h"
#include "singleton.h"

#include "supercmd.h"

class super_client;

/**
* \brief 网络服务器框架代码
*
* 在需要与管理服务器建立连接的网络服务器中使用
*
*/
class x_subnetservice : public x_service , public Singleton<x_subnetservice>
{
public:

	virtual ~x_subnetservice();

	/**
	* \brief 解析来自管理服务器的指令
	*
	* 这些指令是与具体的服务器有关的，因为通用的指令都已经处理了
	*
	* \param pNullCmd 待处理的指令
	* \param nCmdLen 指令长度
	* \return 解析是否成功
	*/
	virtual bool msgParse_SuperService(const Cmd::t_NullCmd *pNullCmd,const uint32_t nCmdLen) = 0;

	bool sendCmdToSuperServer(const void *pstrCmd,const int nCmdLen);
	void setServerInfo(const Cmd::Super::t_Startup_Response *ptCmd);
	void addServerEntry(const Cmd::Super::ServerEntry &entry);
	const Cmd::Super::ServerEntry *getServerEntryById(const uint16_t wdServerID);
	const Cmd::Super::ServerEntry *getServerEntryByType(const uint16_t wdServerType);
	const Cmd::Super::ServerEntry *getNextServerEntryByType(const uint16_t wdServerType,const Cmd::Super::ServerEntry **prev);

	const uint16_t getServerID() const { return wdServerID; }
	const uint16_t getServerType() const { return wdServerType; }
	virtual tcp_task_ptr newTCPTask(boost::asio::io_service& ios) = 0;
	shared_ptr<super_client> superClient;    /**< 管理服务器的客户端实例 */
protected:
	x_subnetservice(const std::string &name,const uint16_t wdType);

	bool init();
	bool validate();
	void final();

	uint16_t wdServerID;          /**< 服务器编号，一个区唯一的 */
	uint16_t wdServerType;          /**< 服务器类型，创建类实例的时候已经确定 */
	std::string pstrIP;      /**< 服务器内网地址 */
	uint16_t wdPort;            /**< 服务器内网端口 */
	boost::shared_ptr<server> tcpServer;        /**< TCP服务器实例指针 */
private:
	boost::mutex mlock;                    /**< 关联服务器信息列表访问互斥体 */
	std::deque<Cmd::Super::ServerEntry> serverList;    /**< 关联服务器信息列表，保证服务器之间的验证关系 */
};
