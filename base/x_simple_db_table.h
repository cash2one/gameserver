#pragma once

#include "common.h"
#include <boost/utility.hpp>
#include <string>
#include <boost/unordered_map.hpp>
#include <utility>

//for db
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
//end db


class x_simple_db_table
{
	enum 
	{
		FLAG_UNTOUCH = 0x00,	//do nothing
		FLAG_ADD = 0x01,		//insert
		FLAG_MODIFIED = 0x02,	//update
	};
	private:
		boost::shared_ptr<sql::Connection> conn_;
		std::string table_;	//table name
		typedef boost::unordered_map<uint32_t,std::pair<uint8_t, uint32_t> > dbmap;
		boost::unordered_map<uint32_t,std::pair<uint8_t, uint32_t> > id2value_; //value.first: is_new

	public:
		x_simple_db_table(boost::shared_ptr<sql::Connection> conn, const std::string& table);
		~x_simple_db_table();
		bool load();
		bool save();
		uint32_t get(const uint32_t id);
		void set(const uint32_t id, const uint32_t value, const bool save=false);
};

