#ifndef SINGLETON_H
#define SINGLETON_H
#include <cassert>

template<class T>
class Singleton{
private:
	Singleton(const Singleton<T> &);
	Singleton& operator=(const Singleton<T> &);

protected:
	static T* ms_Singleton;
public:
	Singleton(void){
		assert(!ms_Singleton);
		ms_Singleton = static_cast<T*>(this);
	}
	~Singleton(){
		assert(ms_Singleton);
		ms_Singleton = 0;
	}

	static T& getSingleton(){
		assert(ms_Singleton);
		return (*ms_Singleton);
	}
	static T* getSingletonPtr(){
		return ms_Singleton;
	}
};

#endif
