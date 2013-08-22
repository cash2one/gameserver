#include "x_simple_db_table.h"
/*
//for db
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
//end db
*/
#include <sstream>
#include <memory>

x_simple_db_table::x_simple_db_table(boost::shared_ptr<sql::Connection> conn, const std::string& table)
:conn_(conn),table_(table)
{
	load();
}

x_simple_db_table::~x_simple_db_table()
{
	save();
}

bool x_simple_db_table::load()
{
	id2value_.clear();
	boost::scoped_ptr< sql::Statement > stmt(conn_->createStatement());
	std::ostringstream os;
	os<<"select * from "<<table_;
	boost::scoped_ptr< sql::ResultSet > res(stmt->executeQuery(os.str()));
	while (res->next())
	{
		id2value_[res->getUInt("id")].second = res->getUInt("value");
		id2value_[res->getUInt("id")].first = FLAG_UNTOUCH;
#ifdef _LQ_DEBUG
		Xlogger->trace("(id,flag,value) = (%u,%u,%u)",
				res->getUInt("id"),
				id2value_[res->getUInt("id")].first, 
				id2value_[res->getUInt("id")].second);
#endif
	}
	return true;
}

bool x_simple_db_table::save()
{
	std::ostringstream os;
	std::auto_ptr< sql::Statement > stmt(conn_->createStatement());
	for (dbmap::iterator cit = id2value_.begin();cit!=id2value_.end();++cit)
	{
		if(cit->second.first & FLAG_ADD){
			//insert
			os.str("");
			os << "INSERT INTO "<<table_<<" (id, value) VALUES ('"<< cit->first <<"', '"<<cit->second.second<<"')";
			Xlogger->debug(os.str().c_str());
			stmt->execute(os.str());
		}
		else if (cit->second.first & FLAG_MODIFIED){
			//update
			os.str("");
			os<<"UPDATE "<<table_<<" SET value="<<cit->second.second<<" where id="<<cit->first;
			int affected_rows = stmt->executeUpdate(os.str());
			if (affected_rows!=1)
			{
				os.str("");
				os<< "Expecting one row to be changed, but " << affected_rows << "change(s) reported";
				throw std::runtime_error(os.str());
			}
		}
		cit->second.first = FLAG_UNTOUCH;
	}
	return true;
}

uint32_t x_simple_db_table::get(const uint32_t id)
{
	if (id2value_.find(id) == id2value_.end())
		return 0;
	else
		return id2value_[id].second;
}

void x_simple_db_table::set(const uint32_t id, const uint32_t value, const bool save)
{
	if (id2value_.find(id) == id2value_.end())	//new added
	{
		id2value_[id].first = FLAG_ADD;
	}
	if (id2value_[id].second != value)
	{
		Xlogger->debug("set modified (old,new)=(%u,%u)", id2value_[id].second, value);
		id2value_[id].second = value;
		id2value_[id].first |= FLAG_MODIFIED;
	}
	if (save) {
		std::ostringstream os;
		std::auto_ptr< sql::Statement > stmt(conn_->createStatement());
		if(id2value_[id].first & FLAG_ADD){
			//insert
			os << "INSERT INTO "<<table_<<"(id, value) VALUES (" << id << ", "<< value <<")";
			Xlogger->debug("%s, %s",__PRETTY_FUNCTION__, os.str().c_str());
			stmt->execute(os.str());
		}
		else if(id2value_[id].first & FLAG_MODIFIED) {
			//update
			os<<"UPDATE "<<table_<<" SET value="<<value<<" WHERE id="<<id;
			Xlogger->debug("%s, %s",__PRETTY_FUNCTION__, os.str().c_str());
			int affected_rows = stmt->executeUpdate(os.str());
			if (affected_rows!=1)
			{
				os.str("");
				os<< "Expecting one row to be changed, but " << affected_rows << "change(s) reported";
				throw std::runtime_error(os.str());
			}
		}
		id2value_[id].first = FLAG_UNTOUCH;
	}
}

