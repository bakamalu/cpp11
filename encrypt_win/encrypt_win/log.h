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
	/*  ��ʼ����ز���
	*   i_log_level       :��־�ȼ���ֻ�еȼ����ڵ��ڸõȼ������Żᱻ��¼
	*   i_log_file_name   :��־�ļ���
	*   i_max_file_size   :��־�ļ����ڴ����ֵ(��λ:MB)���������������д�ӡ��־
	*/
	Log(LOG_LEVEL i_log_level = J_DEBUG, std::string i_log_file_name = "", uint64_t i_max_file_size = 50)
	{
		m_log_file_dir = "";
		m_fp = NULL;
		if (!init(i_log_level, i_log_file_name, i_max_file_size))
		{
			//��־���ʼ��ʧ��
			printf("ERROR: Log Class init Error!\n");
		}
	}
	/*init:��ʼ����ز���
	*   i_log_level       :��־�ȼ���С�ڸõȼ�����䲻��ӡ
	*   i_log_file_name   :��־�ļ���
	*   i_max_file_size   :��־�ļ����ڴ����ֵ(��λ:MB)���������������д�ӡ��־
	*   return  : ��ʼ�������ʧ�ܷ���false
	*/
	bool init(LOG_LEVEL i_log_level, std::string i_log_file_name, uint64_t i_max_file_size,std::string i_log_file_dir="")
	{
		++m_log_index;
		m_log_level = i_log_level;
		m_log_file_name = i_log_file_name;
		m_max_file_size = i_max_file_size;
		m_log_file_dir = i_log_file_dir;

		//��־�ļ�·��
		char log_file_path[MAX_PATH];
		//	./index-time-file_name
		snprintf(log_file_path, sizeof(log_file_path) - 1, "%s%lld-%s-%s", m_log_file_dir.c_str(),m_log_index, get_time().c_str(), m_log_file_name.c_str());
		//std::string log_file_path = m_log_file_dir + m_log_file_name;
		m_fp = fopen(log_file_path, "w");

		//��ʼ��ʧ��
		if (m_fp == NULL)
		{
			return false;
		}

		return true;
	}
	//�������ر��ļ�����
	~Log()
	{
		if (m_fp != NULL)
		{
			if (fclose(m_fp) != 0)
			{
				//�ļ����ر�ʧ��
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
	//��Ϊ��־��ǣ����ļ��У������ļ���ʽ
		snprintf(res_time, sizeof(res_time) - 1, "%4d %02d %02d %02d_%02d_%02d", newtime->tm_year + 1900, newtime->tm_mon + 1, newtime->tm_mday, newtime->tm_hour, newtime->tm_min, newtime->tm_sec);
#endif
		return res_time;
	}

	//��¼��־
	void log_mess(int i_log_level, const char*i_Func_line_mess, const char *i_log_format, ...)
	{

		//�ȼ��͵���䣬������
		if (i_log_level < m_log_level)
		{
			return;
		}

		//������־����Ϣ
		std::string real_mess = "";

		//��־��¼
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
		//�������λ�ö�λ
		real_mess += i_Func_line_mess;
		//��Ϣ��¼
		va_list vaList;                        //����һ��va_list�͵ı���
		va_start(vaList, i_log_format);        //va_start��ʼ��vaList
		char mess_str[1024]{ 0 };				//��¼����Ϣ
		vsprintf(mess_str, i_log_format, vaList); //��ϸ�ʽ���ַ���������ɱ����
		real_mess += mess_str;
		//���з���
		real_mess += "\n";

		//��־�ڴ����
		file_size += real_mess.size();

		//�趨������ڴ�
		uint64_t MAX_SIZE = m_max_file_size * 1024 * 1024;

		//��־�Ƿ񳬹��趨������ڴ棬true�򳬹�
		bool if_overflow = MAX_SIZE < file_size;

		//�л�����־
		if (if_overflow)
		{
			printf("Log file overflow!\n");
			fflush(m_fp);
			//�ǵ��޸�init ����ʱ����Ϣ
			init(m_log_level, m_log_file_name, m_max_file_size);
		}

		const int write_count = 1;
		size_t num_write = fwrite(real_mess.c_str(), real_mess.size(), write_count, m_fp);
		//printf("real_mess.size():%d\n",real_mess.size());
		if (num_write != write_count)
		{
			printf("Write log Error!\n");
		}
		//ˢ�»���
		fflush(m_fp);
	}
private:
	//��ǰ��־�����־�ȼ�
	LOG_LEVEL m_log_level = J_DEBUG;
	//��ǰ��־�ļ�������
	std::string m_log_file_name = "Log.log";
	//��־�ļ����ڴ����ֵ(��λ:MB)
	uint64_t m_max_file_size = 0;
	//��־�ļ�ָ��
	FILE *m_fp = NULL;
	//��־����
	uint64_t m_log_index = 0;
	//��ǰ��־�ļ���Ŀ¼(����Ϊ��ǰĿ¼)
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