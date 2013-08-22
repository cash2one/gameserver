#include "tcp_task.h"
#include "task_state.h"

void state_verify::on_change_state()
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		waiting = true;
		task_->timer_.expires_from_now(boost::posix_time::seconds(5));		//set timer
		task_->timer_.async_wait(bind(&task_state::handle_timeout, shared_from_this(), _1));
		task_->async_read();											//request for read
	}
}

void state_verify::handle_timeout(const boost::system::error_code& error)
{
	bool b = error != boost::asio::error::operation_aborted;
	Xlogger->debug("%s b= %d",__PRETTY_FUNCTION__, b);
	if (error != boost::asio::error::operation_aborted)
		handle_error(error);
}

void state_verify::handle_error(const boost::system::error_code& error)
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		if (waiting)	//stop timer
		{
			waiting = false;
			size_t num = task_->timer_.cancel();
			//assert(num != 0);
			Xlogger->debug("%s cancel num %u ",__PRETTY_FUNCTION__, num);
		}
		task_->set_state(task_->state_closed_);
	}
}

void state_verify::handle_msg(const void* ptr, const uint32_t len)
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		assert(waiting);
		waiting = false;
		size_t num = task_->timer_.cancel();
		assert(num != 0);
		task_->handle_verify(ptr, len);
	}
}

void state_wait_sync::on_change_state()
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		waiting = true;
		task_->timer_.expires_from_now(boost::posix_time::seconds(20));
		task_->timer_.async_wait(bind(&task_state::handle_timeout, shared_from_this(), _1));
		task_->async_read();
	}
}

void state_wait_sync::handle_timeout(const boost::system::error_code& error)
{
	if (error != boost::asio::error::operation_aborted)
		handle_error(error);
}
void state_wait_sync::handle_error(const boost::system::error_code& error)
{
	Xlogger->debug("%s waiting= %u",__PRETTY_FUNCTION__, waiting);
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		if (waiting)	//stop timer
		{
			waiting = false;
			size_t num = task_->timer_.cancel();
			Xlogger->debug("%s cancel num %u ",__PRETTY_FUNCTION__, num);
			//assert(num != 0);
		}
		task_->uniqueRemove();
		task_->set_state(task_->state_closed_);
	}
}
void state_wait_sync::handle_msg(const void* ptr, const uint32_t len)
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		assert(waiting);
		waiting = false;
		size_t num = task_->timer_.cancel();
		assert(num != 0);
		task_->handle_wait_sync(ptr, len);
	}
}

//no need for sync
void state_no_wait_sync::on_change_state()
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		task_->set_state(task_->state_okay_);
	}
}
	
void state_okay::on_change_state()
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		task_->addToContainer();
		task_->async_read();
	}
}

void state_okay::handle_timeout(const boost::system::error_code& error)
{
	handle_error(error);
}
void state_okay::handle_error(const boost::system::error_code& error)
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		task_->removeFromContainer();
		task_->uniqueRemove();
		task_->set_state(task_->state_closed_);
	}
}
void state_okay::handle_msg(const void* ptr, const uint32_t len)
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		task_->handle_msg(ptr, len);
	}
}

void state_closed::on_change_state()
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		task_->close();
	}
}

void state_wait::on_change_state()
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		//just set timer, no read
		task_->timer_.expires_from_now(boost::posix_time::seconds(30));		//set timer
		task_->timer_.async_wait(bind(&task_state::handle_timeout, shared_from_this(), _1));
	}
}

void state_wait::handle_timeout(const boost::system::error_code& error)
{
	Xlogger->debug("%s",__PRETTY_FUNCTION__);
	if (error != boost::asio::error::operation_aborted)
		handle_error(error);
}
void state_wait::handle_error(const boost::system::error_code& error)
{
	if (tcp_task_ptr task_ = task_weak_.lock())
	{
		Xlogger->debug("%s",__PRETTY_FUNCTION__);
		task_->uniqueRemove();
		task_->set_state(task_->state_closed_);
	}
}
