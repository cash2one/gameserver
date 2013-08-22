
#pragma once

#include "x_nullcmd.h"
#include <functional>
#include "type.h"

#pragma pack(1)

namespace Cmd
{
	struct t_NewLoginSession {
		WORD wdLoginID;
		WORD wdGatewayID;
		DWORD loginTempID;
		DWORD dwpstrIP;
		WORD wdPort;
		GameZone_t gameZone;
		DWORD accid;
		BYTE state;
		DWORD type;
		char account[MAX_ACCNAMESIZE];
		char passwd[MAX_PASSWORD];
		//des key
		//DES_cblock des_key;
		DWORD client_ip;
		char numpasswd[MAX_NUMPASSWORD];
		char passwd2[MAX_PASSWORD];
		BYTE accSafe;
		WORD wdNetType;	//gate net type : 0 dianxing, 1 wangtong
		WORD userType;	//user belong type :the first bit :gaint user;the second bit : 51 net user
		DWORD createTime;	// user register time

		t_NewLoginSession() {
			memset(this, 0, sizeof(*this));
		}

	};

	namespace FL
	{
		const BYTE CMD_LOGIN = 1;
		const BYTE CMD_GYLIST = 2;
		const BYTE CMD_SESSION = 3;

		//////////////////////////////////////
		struct t_FL_Login : t_NullCmd {
			t_FL_Login() {
				cmd = CMD_LOGIN;
			}
		};
		
		const BYTE PARA_LOGIN = 1;
		struct t_LoginFL : t_FL_Login
		{
			DWORD dwstrIP;
			WORD port;
			t_LoginFL(){
				para = PARA_LOGIN;
				dwstrIP = 0;
				port = 0;
			}
		};

		const BYTE PARA_LOGIN_OK = 2;
		struct t_LoginFL_OK : t_NullCmd {
			GameZone_t gameZone;
			char name[MAX_NAMESIZE];
			BYTE netType;
			t_LoginFL_OK() {
				para = PARA_LOGIN_OK;
				memset(name, 0 ,sizeof(name));
				netType = 0;
			}
		};

		struct t_FL_GY : t_NullCmd
		{
			t_FL_GY()
			{
				para = CMD_GYLIST;
			}
		};


		const BYTE PARA_FL_GYLIST = 1;
		struct t_GYList_FL : t_FL_GY
		{
			WORD wdServerID;
			DWORD dwpstrIP;
			WORD wdPort;
			WORD wdNumOnline;
			int state;
			DWORD zoneGameVersion;
			WORD wdNetType;
			t_GYList_FL()
			{
				para = PARA_FL_GYLIST;
			}
		};

		const BYTE PARA_FL_RQGYLIST = 2;
		struct t_RQGYList_FL : t_NullCmd {
			t_RQGYList_FL() {
				para = PARA_FL_RQGYLIST;
			}
		};

		//////////////////////////////////////
		struct t_FL_Session : t_NullCmd
		{
			t_FL_Session()
			{
				cmd = CMD_SESSION;
			}
		};

		const BYTE PARA_SESSION_NEWSESSION = 1;
		struct t_NewSession_Session : t_FL_Session {
			t_NewLoginSession session;
			t_NewSession_Session() {
				para = PARA_SESSION_NEWSESSION; 
			}
		};

		const BYTE PARA_SESSION_IDINUSE = 2;
		struct t_idinuse_Session : t_FL_Session
		{
			DWORD accid;
			DWORD loginTempID;
			WORD wdLoginID;
			char name[MAX_ACCNAMESIZE];
			t_idinuse_Session()
			{
				para = PARA_SESSION_IDINUSE;
				memset(name, 0, sizeof(name));
			}
		};
		//////////////////////////////////////////

	};
};

#pragma pack()
