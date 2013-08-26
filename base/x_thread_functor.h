#pragma once
#include <boost/utility.hpp>

class x_thread_functor: boost::noncopyable
{
	public:
		x_thread_functor(){ final_ = false; }
		virtual void operator()() = 0;
		void final(){ final_ = true;}
		bool is_final() const { return final_; }

		virtual ~x_thread_functor(){ final(); }
	protected:
		bool final_;
};
