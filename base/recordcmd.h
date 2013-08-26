
#pragma once

#include "x_nullcmd.h"
#include <functional>
#include "charbase.h"

#pragma pack(1)

namespace Cmd
{
	namespace Record
	{
		const BYTE CMD_LOGIN = 1;
		const BYTE CMD_GATE = 2;
		const BYTE CMD_SCENE = 3;
		const BYTE CMD_SESSION = 4;
		const BYTE CMD_SUPER = 5;

		/////////////////////////////////////////
		// CMD_SESSION
		//////////////////////
		struct t_Record_Cmd : t_NullCmd
		{
			t_Record_Cmd()
			{
				cmd = CMD_LOGIN;
			}
		};

		const BYTE PARA_LOGIN = 1;
		struct t_LoginRecord : t_Record_Cmd
		{
			WORD wdServerID;
			WORD wdServerType;
			t_LoginRecord()
			{
				para = PARA_LOGIN;
			}
		};

		/////////////////////////////////////////
		// CMD_SCENE
		//////////////////////
		struct t_SceneRecord : t_NullCmd{
			t_SceneRecord(){
				cmd = CMD_SCENE;
			}
		};

		const BYTE PARA_SCENE_USER_READ = 1;
		struct t_ReadUser_SceneRecord : t_SceneRecord{
			DWORD accid;
			DWORD id;
			DWORD dwMapTempID;
			t_ReadUser_SceneRecord(){
				para = PARA_SCENE_USER_READ;
				accid = id = dwMapTempID = 0;
			}
		};

		enum WriteBack_Type{
			TIMETICK_WRITEBACK,
			LOGOUT_WRITEBACK,
			CHANGE_SCENE_WRITEBACK,
			OPERATION_WRITEBACK,
		};
		const BYTE PARA_SCENE_USER_WRITE = 2;
		struct t_WriteUser_SceneRecord: t_SceneRecord{
			DWORD accid;
			DWORD id;
			DWORD dwMapTempID;	//temp map id
			DWORD writeback_type;
			//转区相关
			DWORD to_game_zone;
			DWORD secretkey;
			DWORD type;
			//
			CharBase charbase;
			DWORD dataSize;
			char data[0];
			t_WriteUser_SceneRecord(){
				para = PARA_SCENE_USER_WRITE;
				dataSize = 0;
			}
		};

		const BYTE PARA_SCENE_TEST = 3;
		struct t_Test_SceneRecord:t_SceneRecord{
			t_Test_SceneRecord(){
				para = PARA_SCENE_TEST;
		   	}
		};


		/////////////////////////////////////////
		// CMD_GATE
		//////////////////////
		struct t_GatewayRecord : t_NullCmd{
			t_GatewayRecord(){
				cmd = CMD_GATE;
			}
		};
		const BYTE PARA_GATE_TEST = 3;
		struct t_Test_GatewayRecord:t_GatewayRecord{
			t_Test_GatewayRecord(){
				para = PARA_GATE_TEST;
		   	}
		};
	};
};

#pragma pack()
