#pragma once

#include "type.h"

#pragma pack(1)

namespace Cmd
{
	const BYTE CMD_NULL = 0;
	const BYTE PARA_NULL = 0;

	struct t_NullCmd
	{
		BYTE cmd;
		BYTE para;
		t_NullCmd(const BYTE cmd = CMD_NULL,const BYTE para = PARA_NULL):cmd(cmd),para(para)
		{}
	};
};

#pragma pack()
