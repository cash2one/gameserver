#pragma once

#include "x_nullcmd.h"
#include <functional>
#include "flcmd.h"

#pragma pack(1)

namespace Cmd
{
	namespace Bill
	{
		const BYTE CMD_LOGIN = 1;
		const BYTE CMD_GATE = 2;
		const BYTE CMD_FORWARD = 3;
		const BYTE CMD_REDEEM = 4;
		const BYTE CMD_STOCK = 5;
		/*
		const BYTE CMD_SCENE = 3;
		const BYTE CMD_SESSION = 4;
		const BYTE CMD_SUPER = 5;
		*/

		/////////////////////////////////////////
		// CMD_SESSION
		//////////////////////
		struct t_Bill_Cmd : t_NullCmd
		{
			t_Bill_Cmd()
			{
				cmd = CMD_LOGIN;
			}
		};

		const BYTE PARA_LOGIN = 1;
		struct t_LoginBill : t_Bill_Cmd
		{
			WORD wdServerID;
			WORD wdServerType;
			t_LoginBill()
			{
				para = PARA_LOGIN;
			}
		};

		/////////////////////////////////////////
		// CMD_FORWARD
		//////////////////////
		struct t_Bill_Forward : t_NullCmd {
			t_Bill_Forward(){
				cmd = CMD_FORWARD;
			}
		};

		const BYTE PARA_FORWARD_USER = 1;
		struct t_Bill_ForwardUser : t_Bill_Forward {
			DWORD dwAccid;
			WORD size;
			BYTE data[0];
			t_Bill_ForwardUser(){
				dwAccid = 0;
				size = 0;
			}
		};
		const BYTE PARA_FORWARD_BILL_TO_SCENE = 3;
		struct t_Bill_ForwardBillToScene : t_Bill_Forward{
			DWORD id;
			WORD size;
			BYTE data[0];
			t_Bill_ForwardBillToScene(){
				para = PARA_FORWARD_BILL_TO_SCENE;
				id = 0;
				size = 0;
			}
		};

		struct t_Bill_Gate : t_NullCmd {
			t_Bill_Gate() {
				para = CMD_GATE;
			}
		};

		const BYTE PARA_GATE_NEWSESSION = 1;
		struct t_NewSession_Gateway : t_Bill_Gate {
			t_NewLoginSession session;
			t_NewSession_Gateway() {
				para = PARA_GATE_NEWSESSION;
			}
		};

	};
};

#pragma pack()
