#pragma once

#include "x_nullcmd.h"
#include <functional>

#pragma pack(1)

namespace Cmd
{
	namespace Session
	{
		const BYTE CMD_LOGIN = 1;
		const BYTE CMD_GATE = 2;
		const BYTE CMD_SCENE = 3;
		const BYTE CMD_SUPER = 5;

		/////////////////////////////////////////
		// CMD_LOGIN
		//////////////////////
		struct t_Session_Cmd : t_NullCmd
		{
			t_Session_Cmd()
			{
				cmd = CMD_LOGIN;
			}
		};

		const BYTE PARA_LOGIN = 1;
		struct t_LoginSession : t_Session_Cmd
		{
			WORD wdServerID;
			WORD wdServerType;
			t_LoginSession()
			{
				para = PARA_LOGIN;
			}
		};


		/////////////////////////////////////////
		// CMD_SCENE
		//////////////////////
		struct t_SceneSession : t_NullCmd{
			t_SceneSession(){
				cmd = CMD_SCENE;
			}
		};

		const BYTE PARA_SCENE_SESSION_TEST = 1;
		struct t_SceneSession_Test: t_SceneSession{
			t_SceneSession_Test(){
				para = PARA_SCENE_SESSION_TEST;
			}
		};

		/////////////////////////////////////////
		// CMD_GATE
		//////////////////////
		struct t_GatewaySession : t_NullCmd{
			t_GatewaySession(){
				cmd = CMD_GATE;
			}
		};

		const BYTE PARA_GATE_SESSION_TEST = 1;
		struct t_GatewaySession_Test: t_GatewaySession{
			t_GatewaySession_Test(){
				para = PARA_GATE_SESSION_TEST;
			}
		};
	};
};

#pragma pack()
