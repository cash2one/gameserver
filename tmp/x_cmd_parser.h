#pragma once

#include "common.h"

class x_cmd_parser
{
	public:
		x_cmd_parser(shared_ptr<tcp_client> host)
		{
		}

		virtual bool cmd_parse(const Cmd::t_NullCmd* cmd, const uint32_t len) = 0;

	protected:
		shared_ptr<tcp_client> host_;
};
