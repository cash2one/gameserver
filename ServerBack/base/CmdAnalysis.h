/**
* \brief 指令流量分析
*/
struct CmdAnalysis
{
	CmdAnalysis(const char *disc,uint32_t time_secs):_log_timer(time_secs)
	{
		bzero(_disc,sizeof(disc));
		strncpy(_disc,disc,sizeof(_disc)-1);
		bzero(_data,sizeof(_data));
		_switch=false;
	}
	struct
	{
		uint32_t num;
		uint32_t size;
	}_data[256][256] ;
	zMutex _mutex;
	Timer _log_timer;
	char _disc[256];
	bool _switch;//开关
	void add(const BYTE &cmd,const BYTE &para,const uint32_t &size)
	{
		if (!_switch)
		{
			return;
		}
		_mutex.lock(); 
		_data[cmd][para].num++;
		_data[cmd][para].size +=size;
		zRTime ct;
		if (_log_timer(ct))
		{
			for(int i = 0 ; i < 256 ; i ++)
			{
				for(int j = 0 ; j < 256 ; j ++)
				{
					if (_data[i][j].num)
						Xlogger->debug("%s:%d,%d,%d,%d",_disc,i,j,_data[i][j].num,_data[i][j].size);
				}
			}
			bzero(_data,sizeof(_data));
		}
		_mutex.unlock(); 
	}
};
