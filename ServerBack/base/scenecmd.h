#pragma once

#include "x_nullcmd.h"
#include <functional>

#pragma pack(1)

namespace Cmd
{
	namespace Scene
	{
		const BYTE CMD_LOGIN = 1;
		const BYTE CMD_GATE = 2;
		const BYTE CMD_SCENE = 3;
		const BYTE CMD_SESSION = 4;
		const BYTE CMD_SUPER = 5;

		/////////////////////////////////////////
		// CMD_SESSION
		//////////////////////
		struct t_Scene_Cmd : t_NullCmd
		{
			t_Scene_Cmd()
			{
				cmd = CMD_LOGIN;
			}
		};

		const BYTE PARA_LOGIN = 1;
		struct t_LoginScene : t_Scene_Cmd
		{
			WORD wdServerID;
			WORD wdServerType;
			t_LoginScene()
			{
				para = PARA_LOGIN;
			}
		};

	};
};

#pragma pack()
