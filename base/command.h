#pragma once

#include "common.h"
#include "x_nullcmd.h"

#pragma pack(1)

namespace Cmd
{
	//const BYTE CMD_SUPER = 5;

	//const BYTE NULL_USERCMD_PARA = 0;
	struct stNullUserCmd{
		stNullUserCmd(){
			dwTimestamp = 0;
		}
		BYTE byCmd;
		BYTE byParam;
		DWORD dwTimestamp;
	};

	const BYTE PING_USERCMD = 30;
	const BYTE STOCK_BILL_USERCMD = 39;
	const BYTE LOGON_USERCMD = 104;

	//login cmd begin
	struct stLogonUserCmd : public stNullUserCmd{
		stLogonUserCmd(){ byCmd = LOGON_USERCMD; }
	};

	//client login to FLServer
	const BYTE USER_REQUEST_LOGIN_PARA = 2;
	struct stUserRequestLoginCmd : public stLogonUserCmd {
		stUserRequestLoginCmd() {
			byParam = USER_REQUEST_LOGIN_PARA;
		}
		char pstrName[MAX_ACCNAMESIZE];
		char pstrPassword[MAX_PASSWORD];
		WORD game;
		WORD zone;
		char jpegPassport[7];
		char mac_addr[13];
		char uuid[25];
		WORD wdNetType;
		char passpodPwd[9];
	};

	enum {
		LOGIN_RETURN_UNKNOWN = 0,		//unknown error
		LOGIN_RETURN_VERSIONERROR = 1,
		LOGIN_RETURN_UUID = 2,
		LOGIN_RETURN_DB = 3,
		LOGIN_RETURN_PASSWORDERROR = 4,
		LOGIN_RETURN_CHANGEPASSWORD = 5,
		LOGIN_RETURN_IDINUSE = 6,
		LOGIN_RETURN_IDINCLOSE = 7,
		LOGIN_RETURN_GATEWAYNOTAVAILABLE = 8,
		LOGIN_RETURN_USERMAX = 9,
		LOGIN_RETURN_ACCOUNTEXIST = 10,
		LOGIN_RETURN_ACCOUNTSUCCESS = 11,
		LOGIN_RETURN_CHARNAMEREPEAT = 12,
		LOGIN_RETURN_USERDATANOEXIST = 13,
		LOGIN_RETURN_TIMEOUT = 14,
		LOGIN_RETURN_PAYFAILED = 15,
		LOGIN_RETURN_JPED_PASSPORT = 16,
		LOGIN_RETURN_LOCK = 17,
		LOGIN_RETURN_WAITACTIVE = 18,
		LOGIN_RETURN_NEWUSER_OLDZONE = 19,
		LOGIN_RETURN_UUID_ERROR = 20,
		LOGIN_RETURN_USER_TOZONE = 21,
		LOGIN_RETURN_CHANGE_LOGIN = 22,
		LOGIN_RETURN_MATRIX_ERROR = 23,
		LOGIN_RETURN_MATRIX_NEED = 24,
		LOGIN_RETURN_MATRIX_LOCK = 25,
		LOGIN_RETURN_MATRIX_DOWN = 26,
		LOGIN_RETURN_OLDUSER_NEWZONE = 27,
		LOGIN_RETURN_IMG_LOCK = 28,
		LOGIN_RETURN_BUSY = 32,
		LOGIN_RETURN_FORBID = 33,
		LOGIN_RETURN_MAXCHARBASELIMIT = 34,
	};
	const BYTE SERVER_RETURN_LOGIN_FAILED = 3;
	struct stServerReturnLoginFailedCmd : stLogonUserCmd {
		stServerReturnLoginFailedCmd() {
			byParam = SERVER_RETURN_LOGIN_FAILED; 
			byReturnCode = 0;
		}
		BYTE byReturnCode;	//return sub param
	};

	//login success, ret gatewayserver ip,port, key and so on
	const BYTE SERVER_RETURN_LOGIN_OK = 4;
	struct stServerReturnLoginSuccessCmd : public stLogonUserCmd {
		stServerReturnLoginSuccessCmd() {
		   byParam = SERVER_RETURN_LOGIN_OK; 
		}
		DWORD dwUserID;
		DWORD loginTempID;
		DWORD dwpstrIP;
		WORD wdPort;
		union {
			struct {
				BYTE random[58];
				BYTE keyOffset; //offset of the start index in the key
			};
			BYTE key[256];	//keep key, the whole array is filled with random num
		};
	};

	const BYTE PASSWD_LOGON_USERCMD_PARA = 5;
	struct stPasswdLogonUserCmd : stLogonUserCmd 
	{
		stPasswdLogonUserCmd()
		{
			byParam = PASSWD_LOGON_USERCMD_PARA;
		}
		DWORD loginTempID;
		DWORD dwUserID;
		char pstrName[MAX_ACCNAMESIZE];
		char pstrPassword[MAX_PASSWORD];
	};

	const BYTE USER_RELOGIN_PARA = 14;
	struct stUserReLoginCmd : stLogonUserCmd {
		stUserReLoginCmd() {
			byParam = USER_RELOGIN_PARA;
		}
	};

	const BYTE USER_VERIFY_VER_PARA = 120;
	struct stUserVerifyVerCmd : public stLogonUserCmd {
		stUserVerifyVerCmd(){
			byParam = USER_VERIFY_VER_PARA;
			version = 0; }
		DWORD reserve;
		DWORD version;
	};

	struct stPingUserCmd : public stNullUserCmd {
		stPingUserCmd() {
			byCmd = PING_USERCMD;
		}
	};

	struct ping_element {
		DWORD gateway_ip;
		BYTE state;
		ping_element() {
			gateway_ip = 0;
			state = 0;
		}
	};
	const BYTE PING_LIST_PARA = 1;
	struct stPingList : public stPingUserCmd {
		DWORD zone_id;
		struct ping_element ping_list;
		stPingList() {
			byParam = PING_LIST_PARA;
		}
	};

	const BYTE REQUEST_PING_LIST_PARA = 2;
	struct stRequestPingList : public stPingUserCmd {
		DWORD id;	//game zone num
		stRequestPingList() {
			byParam = REQUEST_PING_LIST_PARA; 
		}
	};

	const BYTE LOGIN_PING_PARA = 3;
	struct stLoginPing : public stPingUserCmd {
		stLoginPing() {
			byParam = LOGIN_PING_PARA;
		}
	};

	struct stStockBillUserCmd : public stNullUserCmd
	{
		stStockBillUserCmd()
		{
			byCmd = STOCK_BILL_USERCMD;
		}
	};

	enum {
		STOCK_LOGIN_OK,
		STOCK_LOGIN_NOTLOGIN,
		STOCK_OPEN_OK,
		STOCK_CHANGE_OK,
		STOCK_ERROR,
		STOCK_DIFF,
		STOCK_NONE,
		STOCK_SHORT,
		STOCK_EXIST,
		STOCK_SERVER_WRONG,
		STOCK_GOLDLIST_MAX,
		STOCK_MONEYLIST_MAX,
	};
	const BYTE RETURN_PASSWORD_STOCKPARA = 2;
	struct stReturnPasswordStockUserCmd : stStockBillUserCmd
	{
		stReturnPasswordStockUserCmd()
		{
			byParam = RETURN_PASSWORD_STOCKPARA;
		}
	};

};

#pragma pack()
