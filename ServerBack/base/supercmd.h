#pragma once

#include "x_nullcmd.h"
#include <functional>
#include "flcmd.h"

#pragma pack(1)

namespace Cmd
{
	namespace Super
	{
		const BYTE CMD_STARTUP = 1;
		const BYTE CMD_BILL = 3;
		const BYTE CMD_GATEWAY = 4;
		const BYTE CMD_SESSION = 5;
		const BYTE CMD_COUNTRYONLINE = 166;

		struct ServerEntry
		{
			WORD wdServerID;
			WORD wdServerType;
			char pstrName[MAX_NAMESIZE];
			char pstrIP[MAX_IP_LENGTH];
			WORD wdPort;
			char pstrExtIP[MAX_IP_LENGTH];
			WORD wdExtPort;
			WORD wdNetType;
			WORD state;
			ServerEntry()
			{
				bzero(this,sizeof(*this));
			}
			//maybe for unordered map
			bool operator == (const ServerEntry& se) const {
				return wdServerID == se.wdServerID;
			}
			//for map
			bool operator < (const ServerEntry& se) const {
				return wdServerID < se.wdServerID;
			}
		};
		//generate hash code
		struct key_hash
		{
			size_t operator()(const Cmd::Super::ServerEntry &x) const
			{
				std::size_t seed = 0;
				boost::hash_combine(seed, x.wdServerID);
				return seed;
			}
		};

		//equal or not
		struct key_equal : public std::binary_function<Cmd::Super::ServerEntry,Cmd::Super::ServerEntry,bool>
		{
			bool operator()(const Cmd::Super::ServerEntry &s1,const Cmd::Super::ServerEntry &s2) const
			{
				return s1.wdServerID == s2.wdServerID;
			}
		};

		//init relative command
		struct t_Startup_Cmd: t_NullCmd
		{
			t_Startup_Cmd()
			{
				cmd = CMD_STARTUP;
			}
		};

		const BYTE PARA_STARTUP_REQUEST = 1;
		struct t_Startup_Request : t_Startup_Cmd
		{
			WORD wdServerType;
			char pstrIP[MAX_IP_LENGTH];
			t_Startup_Request()
			{
				para = PARA_STARTUP_REQUEST;
				wdServerType = 0;
				bzero(pstrIP,sizeof(pstrIP));
			}
		};

		const BYTE PARA_STARTUP_RESPONSE = 2;
		struct t_Startup_Response : t_Startup_Cmd
		{
			WORD wdServerID;
			WORD wdPort;
			char pstrExtIP[MAX_IP_LENGTH];
			WORD wdExtPort;
			WORD wdNetType;
			WORD wdSize;
			ServerEntry entry[0];
			t_Startup_Response()
			{
				para = PARA_STARTUP_RESPONSE;
				bzero(pstrExtIP,sizeof(pstrExtIP));
				wdServerID = 0;
				wdPort = 0;
				wdExtPort = 0;
				wdNetType = 0;
				wdSize = 0;
			}
		};

		const BYTE PARA_STARTUP_SERVERENTRY_NOTIFYME = 3;
		struct t_Startup_ServerEntry_NotifyMe : t_Startup_Cmd
		{
			//WORD size;
			//ServerEntry entry[0];
			t_Startup_ServerEntry_NotifyMe()
			{
				para = PARA_STARTUP_SERVERENTRY_NOTIFYME;
				//size = 0;
			}
		};

		const BYTE PARA_STARTUP_SERVERENTRY_NOTIFYOTHER = 4;
		struct t_Startup_ServerEntry_NotifyOther : t_Startup_Cmd
		{
			WORD srcID;
			ServerEntry entry;
			t_Startup_ServerEntry_NotifyOther()
			{
				para = PARA_STARTUP_SERVERENTRY_NOTIFYOTHER;
				srcID = 0;
			}
		};

		const BYTE PARA_STARTUP_OK = 5;
		struct t_Startup_OK : t_Startup_Cmd
		{
			WORD wdServerID;
			t_Startup_OK()
			{
				para = PARA_STARTUP_OK;
				wdServerID = 0;
			}
		};

		const BYTE PARA_GAMETIME = 6;
		struct t_GameTime : t_Startup_Cmd
		{
			QWORD qwGameTime;
			t_GameTime()
			{
				para = PARA_GAMETIME;
				qwGameTime = 0;
			}
		};

		const BYTE PARA_RESTART_SERVERENTRY_NOTIFYOTHER = 9;
		struct t_Restart_ServerEntry_NotifyOther : t_Startup_Cmd
		{
			WORD srcID;
			WORD dstID;
			t_Restart_ServerEntry_NotifyOther()
			{
				para = PARA_RESTART_SERVERENTRY_NOTIFYOTHER;
			}
		};

		const BYTE PARA_STARTUP_TEST = 10;
		struct t_Startup_test: t_Startup_Cmd {
			t_Startup_test(){
				para = PARA_STARTUP_TEST;
			}
		};


		/////////////////////////////////////////
		// CMD_SESSION
		//////////////////////
		struct t_Session_Cmd : t_NullCmd
		{
			t_Session_Cmd()
			{
				cmd = CMD_SESSION;
			}
		};

		const BYTE PARA_SHUTDOWN = 1;
		struct t_shutdown_Super : t_Session_Cmd
		{
			t_shutdown_Super()
			{
				para = PARA_SHUTDOWN;
			}
		};


		//////////////////////////
		// CMD_BILL
		//////////////////////////
		struct t_Bill_Cmd : t_NullCmd {
			t_Bill_Cmd() {
				cmd = CMD_BILL;
			}
		};

		const BYTE PARA_BILL_NEWSESSION = 1;
		struct t_NewSession_Bill : t_Bill_Cmd {
			t_NewLoginSession session;
			t_NewSession_Bill() {
				para = PARA_BILL_NEWSESSION;
			}
		};

		const BYTE PARA_BILL_IDINUSE = 2;
		struct t_idinuse_Bill : t_Bill_Cmd {
			DWORD accid;
			DWORD loginTempID;
			WORD wdLoginID;
			char name[MAX_ACCNAMESIZE];
			t_idinuse_Bill() {
				memset(name, 0, sizeof(name));
			}
		};

		//////////////////////////////
		// CMD_GATEWAY
		//////////////////////////////
		struct t_Super_Gate : t_NullCmd {
			t_Super_Gate() {
				cmd = CMD_GATEWAY;
			}
		};

		const BYTE PARA_GATEWAY_GYLIST = 1;
		struct t_GYList_Gateway : t_Super_Gate {
			WORD wdServerID;
			DWORD dwpstrIP;
			WORD wdPort;
			WORD wdNumOnline;
			int state;
			DWORD zoneGameVersion;
			WORD wdNetType;
			t_GYList_Gateway() {
				para = PARA_GATEWAY_GYLIST;
			}
		};

		const BYTE PARA_GATEWAY_RQGYLIST = 2;
		struct t_RQGYList_Gateway : t_Super_Gate {
			t_RQGYList_Gateway() {
				para = PARA_GATEWAY_RQGYLIST;
			}
		};

		const BYTE PARA_GATEWAY_NEWSESSION = 3;
		struct t_NewSession_Gateway : t_Super_Gate {
			t_NewLoginSession session;
			t_NewSession_Gateway() {
				para = PARA_GATEWAY_NEWSESSION;
			}
		};

	};
};

#pragma pack()
