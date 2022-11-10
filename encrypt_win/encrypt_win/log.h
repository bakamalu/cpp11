#include <string>
#include <stdio.h>
#include <iostream>
#include <time.h>
#include <stdarg.h>
#ifdef __linux
#include <sys/time.h>
#ifdef WIN32
#include <time.h>
#endif
#endif
#ifndef LOG_CPP
#define LOG_CPP

typedef int LOG_LEVEL;
#define J_DEBUG 0
#define J_INFO  1
#define J_WARN  2
#define J_ERROR 3

#define MAX_PATH 1024
#pragma warning( disable : 4996 )
class Log
{
public:
	/*  初始化相关参数
	*   i_log_level       :日志等级，只有等级大于等于该等级的语句才会被记录
	*   i_log_file_name   :日志文件名
	*   i_max_file_size   :日志文件的内存最大值(单位:MB)，超过不再向其中打印日志
	*/
	Log(LOG_LEVEL i_log_level = J_DEBUG, std::string i_log_file_name = "", uint64_t i_max_file_size = 50)
	{
		m_log_file_dir = "";
		m_fp = NULL;
		if (!init(i_log_level, i_log_file_name, i_max_file_size))
		{
			//日志类初始化失败
			printf("ERROR: Log Class init Error!\n");
		}
	}
	/*init:初始化相关参数
	*   i_log_level       :日志等级，小于该等级的语句不打印
	*   i_log_file_name   :日志文件名
	*   i_max_file_size   :日志文件的内存最大值(单位:MB)，超过不再向其中打印日志
	*   return  : 初始化情况，失败返回false
	*/
	bool init(LOG_LEVEL i_log_level, std::string i_log_file_name, uint64_t i_max_file_size,std::string i_log_file_dir="")
	{
		++m_log_index;
		m_log_level = i_log_level;
		m_log_file_name = i_log_file_name;
		m_max_file_size = i_max_file_size;
		m_log_file_dir = i_log_file_dir;

		//日志文件路径
		char log_file_path[MAX_PATH];
		//	./index-time-file_name
		snprintf(log_file_path, sizeof(log_file_path) - 1, "%s%lld-%s-%s", m_log_file_dir.c_str(),m_log_index, get_time().c_str(), m_log_file_name.c_str());
		//std::string log_file_path = m_log_file_dir + m_log_file_name;
		m_fp = fopen(log_file_path, "w");

		//初始化失败
		if (m_fp == NULL)
		{
			return false;
		}

		return true;
	}
	//析构，关闭文件流，
	~Log()
	{
		if (m_fp != NULL)
		{
			if (fclose(m_fp) != 0)
			{
				//文件流关闭失败
			}

		}
	}

	std::string get_time()
	{
		const int ___MAX_PATH = 1024;
		char res_time[___MAX_PATH];

		struct tm *newtime;
		time_t long_time;
		time(&long_time);                /* Get time as long integer. */
		newtime = localtime(&long_time); /* Convert to local time. */

#ifdef __linux
	// 2022 11 10 13:22:45
		snprintf(res_time, sizeof(res_time) - 1, "%4d %02d %02d %02d:%02d:%02d", newtime->tm_year + 1900, newtime->tm_mon + 1, newtime->tm_mday, newtime->tm_hour, newtime->tm_min, newtime->tm_sec);
#elif WIN32
	//作为日志标记，在文件中，遵守文件格式
		snprintf(res_time, sizeof(res_time) - 1, "%4d %02d %02d %02d_%02d_%02d", newtime->tm_year + 1900, newtime->tm_mon + 1, newtime->tm_mday, newtime->tm_hour, newtime->tm_min, newtime->tm_sec);
#endif
		return res_time;
	}

	//记录日志
	void log_mess(int i_log_level, const char*i_Func_line_mess, const char *i_log_format, ...)
	{

		//等级低的语句，不计入
		if (i_log_level < m_log_level)
		{
			return;
		}

		//计入日志的信息
		std::string real_mess = "";

		//标志记录
		switch (i_log_level)
		{
		case J_DEBUG:real_mess = "[DEBUG]:"; break;
		case J_INFO:real_mess = "[INFO] :"; break;
		case J_WARN:real_mess = "[WARN] :"; break;
		case J_ERROR:real_mess = "[ERROR]:"; break;
		default:
			break;
		}
		uint64_t file_size = ftell(m_fp);

		std::string time_mess = get_time() + "_";
		real_mess += time_mess;
		//代码错误位置定位
		real_mess += i_Func_line_mess;
		//信息记录
		va_list vaList;                        //定义一个va_list型的变量
		va_start(vaList, i_log_format);        //va_start初始化vaList
		char mess_str[1024]{ 0 };				//记录的信息
		vsprintf(mess_str, i_log_format, vaList); //配合格式化字符串，输出可变参数
		real_mess += mess_str;
		//换行符号
		real_mess += "\n";

		//日志内存溢出
		file_size += real_mess.size();

		//设定的最大内存
		uint64_t MAX_SIZE = m_max_file_size * 1024 * 1024;

		//日志是否超过设定的最大内存，true则超过
		bool if_overflow = MAX_SIZE < file_size;

		//切换新日志
		if (if_overflow)
		{
			printf("Log file overflow!\n");
			fflush(m_fp);
			//记得修改init 加入时间信息
			init(m_log_level, m_log_file_name, m_max_file_size);
		}

		const int write_count = 1;
		size_t num_write = fwrite(real_mess.c_str(), real_mess.size(), write_count, m_fp);
		//printf("real_mess.size():%d\n",real_mess.size());
		if (num_write != write_count)
		{
			printf("Write log Error!\n");
		}
		//刷新缓冲
		fflush(m_fp);
	}
private:
	//当前日志类的日志等级
	LOG_LEVEL m_log_level = J_DEBUG;
	//当前日志文件的名字
	std::string m_log_file_name = "Log.log";
	//日志文件的内存最大值(单位:MB)
	uint64_t m_max_file_size = 0;
	//日志文件指针
	FILE *m_fp = NULL;
	//日志序数
	uint64_t m_log_index = 0;
	//当前日志文件的目录(设置为当前目录)
	std::string m_log_file_dir;
};

#define LOG_DEBUG(log_class_name,format, ...) {char _func_line[1024]={0};\
        snprintf(_func_line,1024,"%s:%d:	",__FUNCTION__,__LINE__);\
        log_class_name.log_mess(J_DEBUG,_func_line, format, ##__VA_ARGS__);}

#define LOG_INFO(log_class_name,format, ...) {char _func_line[1024]={0};\
        snprintf(_func_line,1024,"%s:%d:	",__FUNCTION__,__LINE__);\
        log_class_name.log_mess(J_INFO,_func_line, format, ##__VA_ARGS__);}

#define LOG_WARN(log_class_name,format, ...) {char _func_line[1024]={0};\
        snprintf(_func_line,1024,"%s:%d:	",__FUNCTION__,__LINE__);\
        log_class_name.log_mess(J_WARN,_func_line, format, ##__VA_ARGS__);}

#define LOG_ERROR(log_class_name,format, ...) {char _func_line[1024]={0};\
        snprintf(_func_line,1024,"%s:%d:	",__FUNCTION__,__LINE__);\
        log_class_name.log_mess(J_ERROR,_func_line, format, ##__VA_ARGS__);}

#endif

/*use example:
#include"log.h"
Log g_log(J_DEBUG, "ext3.log", 50);


int main()
{
	char str[]="hehehehehe";
	LOG_DEBUG(g_log,"hehe %d %s\n",3,str);

	LOG_DEBUG(g_log,"hehe %d %s\n",15,str);
	return 0;
}
*/