#pragma once
#include "type.h"
#include <utility>
#include <queue>

#include "x_nullcmd.h"

typedef std::pair<uint32_t,BYTE *> CmdPair;
template <int QueueSize=102400>
class MsgQueue {
public:
	MsgQueue() {
		queueRead=0;
		queueWrite=0;
	}
	~MsgQueue() {
		clear();
	}
	typedef std::pair<volatile bool,CmdPair > CmdQueue;
	CmdPair *get() {
		CmdPair *ret=NULL;
		if (cmdQueue[queueRead].first) {
			ret=&cmdQueue[queueRead].second;
		}
		return ret;
	}
	void erase() {
		delete [] (cmdQueue[queueRead].second.second);
		cmdQueue[queueRead].first=false;
		(++queueRead);
		queueRead =queueRead %QueueSize;
	}
	bool put(const void *pNullCmd,const uint32_t cmdLen) {
		BYTE *buf = new BYTE[cmdLen];
		if (buf) {
			memcpy(buf,pNullCmd,cmdLen);
			if (!putQueueToArray() && !cmdQueue[queueWrite].first) {
				cmdQueue[queueWrite].second.first = cmdLen;
				cmdQueue[queueWrite].second.second = buf;
				cmdQueue[queueWrite].first=true;
				(++queueWrite);
				queueWrite =queueWrite  %QueueSize;
				return true;
			}
			else {
				queueCmd.push(std::make_pair(cmdLen,buf));
			}
			return true;
		}
		return false;

	}
private:
	void clear() {
		while(putQueueToArray()) {
			while(get()) {
				erase();
			}
		}
		while(get()) {
			erase();
		}
	}
	bool putQueueToArray()
	{
		bool isLeft=false;
		while(!queueCmd.empty())
		{
			if (!cmdQueue[queueWrite].first)
			{
				cmdQueue[queueWrite].second = queueCmd.front();;
				cmdQueue[queueWrite].first=true;
				(++queueWrite);
				queueWrite =queueWrite  %QueueSize;
				queueCmd.pop();
			}
			else
			{
				isLeft = true; 
				break;
			}
		}
		return isLeft;
	}
	CmdQueue cmdQueue[QueueSize];
	std::queue<CmdPair> queueCmd;
	uint32_t queueWrite;
	uint32_t queueRead;
};

/*
class DoubleQueue{
public:
	DoubleQueue() {
		write_ = 0;
		read_ = 1;
	}
	~DoubleQueue() {
		clear();
	}
	CmdPair *get() {
		CmdPair *ret=NULL;
		if (!queueCmd[read_].empty())
			ret = &queueCmd[read_].top();
		else {
			work_index_ = (++work_index_)%2;
			if (!queueCmd[work_index_].empty())
				ret = &queueCmd[work_index_].top();
		}
		return ret;
	}
	void erase() {
		delete [] (queueCmd[work_index_].top().second);
		queueCmd[work_index_].pop();
	}
	bool put(const void *pNullCmd,const uint32_t cmdLen) {
		BYTE *buf = new BYTE[cmdLen];
		if (buf) {
			memcpy(buf,pNullCmd,cmdLen);
			if (!putQueueToArray() && !cmdQueue[queueWrite].first)
			{
				cmdQueue[queueWrite].second.first = cmdLen;
				cmdQueue[queueWrite].second.second = buf;
				cmdQueue[queueWrite].first=true;
				queueWrite = (++queueWrite)%QueueSize;
				return true;
			}
			else
			{
				queueCmd.push(std::make_pair(cmdLen,buf));
			}
			return true;
		}
		return false;

	}
private:
	void clear()
	{
		while(putQueueToArray())
		{
			while(get())
			{
				erase();
			}
		}
		while(get())
		{
			erase();
		}
	}
	bool putQueueToArray()
	{
		bool isLeft=false;
		while(!queueCmd.empty())
		{
			if (!cmdQueue[queueWrite].first)
			{
				cmdQueue[queueWrite].second = queueCmd.front();;
				cmdQueue[queueWrite].first=true;
				queueWrite = (++queueWrite)%QueueSize;
				queueCmd.pop();
			}
			else
			{
				isLeft = true; 
				break;
			}
		}
		return isLeft;
	}
	std::queue<CmdPair> queueCmd[2];
	int write_;
	int read_;
	boost::thread::mutex mutex_;
};
*/

class MessageQueue
{
protected:
	virtual ~MessageQueue(){};
public:
	bool msgParse(const void *pNullCmd,const uint32_t cmdLen)
	{
		return cmdQueue.put(pNullCmd,cmdLen);
	}
	virtual bool cmdMsgParse(const Cmd::t_NullCmd *,const uint32_t)=0;
	bool doCmd()
	{
		CmdPair *cmd = cmdQueue.get();
		while(cmd)
		{
			cmdMsgParse((const Cmd::t_NullCmd *)cmd->second,cmd->first);
			cmdQueue.erase();
			cmd = cmdQueue.get();
		}
		return true;
	}

private:
	MsgQueue<> cmdQueue;
};
