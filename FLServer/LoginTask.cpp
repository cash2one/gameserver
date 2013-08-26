#include "command.h"
#include "LoginTask.h"
#include "FLServer.h"
#include "LoginManager.h"

#include "flcmd.h"
#include "x_util.h"

DWORD LoginTask::uniqueID = 0;

LoginTask::~LoginTask() { }

void LoginTask::handle_verify(const void* ptr, const uint32_t len)
{
	const Cmd::stUserVerifyVerCmd *ptCmd = (const Cmd::stUserVerifyVerCmd *)ptr;
	if (Cmd::LOGON_USERCMD == ptCmd->byCmd && Cmd::USER_VERIFY_VER_PARA == ptCmd->byParam) {
		dwClientVersion = ptCmd->version;
		Xlogger->debug("%s : success", __PRETTY_FUNCTION__);
		if (uniqueAdd())
		{
			set_state(state_okay_);
			return ;
		}
	}
	handle_error(boost::system::error_code());
}

int LoginTask::recycleConn() { return 1; }

/*
void LoginTask::addToContainer()
{
	LoginManager::getInstance().addServer(boost::dynamic_pointer_cast<LoginTask>(shared_from_this()));
	//can notify other servers below
}

void LoginTask::removeFromContainer()
{
	LoginManager::getInstance().removeServer(boost::dynamic_pointer_cast<LoginTask>(shared_from_this()));
}
*/

bool LoginTask::uniqueAdd() {
	return LoginManager::getInstance().add(boost::dynamic_pointer_cast<LoginTask>(shared_from_this()));
}

bool LoginTask::uniqueRemove() {
	return LoginManager::getInstance().remove(boost::dynamic_pointer_cast<LoginTask>(shared_from_this()));
}

bool LoginTask::msgParse(const Cmd::t_NullCmd *pNullCmd,const DWORD nCmdLen)
{
	using namespace Cmd;
	stLogonUserCmd *logonCmd = (stLogonUserCmd *)pNullCmd;
	switch(logonCmd->byCmd)
	{
		case LOGON_USERCMD:
			switch(logonCmd->byParam)
			{
				case USER_REQUEST_LOGIN_PARA:
					{
						Xlogger->info("USER_REQUEST_LOGIN_PARA");
						if (requestLogin((stUserRequestLoginCmd *)logonCmd)) return true;
					}
					break;
				default:
					break;
			}
			break;
	}
	Xlogger->error("LoginTask::msgParse(%d,%d,%d)",pNullCmd->cmd,pNullCmd->para,nCmdLen);
	return false;
}

void LoginTask::handle_msg(const void* ptr, const uint32_t len) {
	msgParse((const Cmd::t_NullCmd*)ptr,len);
	async_read();
}

bool LoginTask::requestLogin(const Cmd::stUserRequestLoginCmd *ptCmd)
{
	using namespace Cmd;

	GameZone_t gameZone;
	gameZone.game = ptCmd->game;
	gameZone.zone = ptCmd->zone;
	Xlogger->info("request login zone: gameid=%u(game=%u,zone=%u)",
			gameZone.id,gameZone.game,gameZone.zone);

	t_NewLoginSession session;
	session.gameZone    = gameZone;
	session.loginTempID = tempid;
	//strncpy(session.client_ip, getIP(), MAX_IP_LENGTH);    
	session.client_ip = 0;
	strncpy(session.account, ptCmd->pstrName, sizeof(session.account));
	strncpy(session.passwd, ptCmd->pstrPassword, sizeof(session.passwd));

	/* do not use jpeg iamge verify code
	if (FLService::getInstance().jpeg_passport && strncmp(jpegPassport,ptCmd->jpegPassport,sizeof(jpegPassport)))
	{
		Xlogger->error("图形验证码错误：%s,%s",jpegPassport,ptCmd->jpegPassport);
		LoginReturn(LOGIN_RETURN_JPEG_PASSPORT);
		return false;
	}
	*/

	//验证用户名称和密码合法性
	if (strlen(ptCmd->pstrName) == 0
		|| strlen(ptCmd->pstrName) >= MAX_NAMESIZE
		|| strlen(ptCmd->pstrPassword) == 0
		|| strlen(ptCmd->pstrPassword) >= MAX_PASSWORD)
	{
		LoginReturn(LOGIN_RETURN_PASSWORDERROR);
		return false;
	}

	boost::scoped_ptr< sql::Statement > stmt(FLService::s_dbConn->createStatement());
	if (!stmt) {
		Xlogger->error("database error");
		LoginReturn(LOGIN_RETURN_DB);
		return false;
	}
	std::stringstream msg;
	msg<<"SELECT ISUSED,ISFORBID,USERID,PASSWORD FROM `LOGIN` WHERE LOGINID = '"<<ptCmd->pstrName<<"'";
	bool bOK = stmt->execute(msg.str());
	if (!bOK) {
		LoginReturn(LOGIN_RETURN_PASSWORDERROR);
		Xlogger->error("can't find record LOGINID=", ptCmd->pstrName);
		return false;
	}
	else {

		boost::scoped_ptr< sql::ResultSet > res(stmt->getResultSet());
		while(res->next()) {
			if (res->getString("PASSWORD") != ptCmd->pstrPassword) {
				LoginReturn(LOGIN_RETURN_PASSWORDERROR);
				return false;
			}
			msg.str("");
			msg<<"UPDATE `LOGIN` SET `LASTACTIVEDATE` = now() WHERE LOGINID = '" << ptCmd->pstrName<<"'";
			int affected_rows = stmt->executeUpdate(msg.str());
			if (affected_rows != 1) {
				msg.str("");
				msg << "Expecting one row to be changed, but " << affected_rows << "change(s) reported";
				throw std::runtime_error(msg.str());
			}

			if (res->getUInt("ISUSED")) {
				LoginReturn(LOGIN_RETURN_IDINUSE);
				Xlogger->error("the accound is been used");    
				return false;
			}
			if (res->getUInt("ISFORBID")) {
				LoginReturn(LOGIN_RETURN_IDINCLOSE);
				Xlogger->error("the account is forbidden");
				return false;
			}

			session.state = 0;
			session.accid = res->getUInt("USERID");
			LoginManager::getInstance().verifyReturn(session);
			return true;  
		}
	}
	return false;
}

void LoginTask::LoginReturn(const BYTE retcode,const bool tm)
{
	Xlogger->debug("%s retcode = %u, tm = %u",__PRETTY_FUNCTION__, retcode, tm);
	using namespace Cmd;
	stServerReturnLoginFailedCmd tCmd;

	tCmd.byReturnCode = retcode;
	sendCmd(&tCmd,sizeof(tCmd));

	if (tm) close();
}

