// header.h: 标准系统包含文件的包含文件，
// 或特定于项目的包含文件
//

#pragma once
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>
// C 运行时头文件
//#include <stdlib.h>
//#include <malloc.h>
//#include <memory.h>
//#include <tchar.h>
/*
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#include <initguid.h>
#include <ole2.h>
#include <mstask.h>
#include <msterr.h>
#include <objidl.h>
//#pragma comment(lib, "comctl32.lib")
//#define SECURITY_WIN32
//#include <Security.h>
//#pragma comment(lib,"Secur32.lib")
//#pragma comment(lib, "Oleacc.lib")
//#pragma comment(lib, "Iphlpapi.lib")
//#include <Powrprof.h>
//#pragma comment(lib, "Powrprof.lib")
//#include <WtsApi32.h>
//#pragma comment(lib, "WtsApi32.lib")
//#include <Userenv.h>
//#pragma comment(lib, "Userenv.lib")
//#include <pdh.h>
//#pragma comment(lib, "pdh.lib")
*/
#include "framework.h"
#ifndef _DEBUG
#ifdef _MSC_VER
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cb) {
	char* p = (char*)pTarget;
	while (cb--)*p++ = (char)value;
	return pTarget;
}
#pragma function(memcpy)
void* __cdecl memcpy(void* pDest, const void* pSrc, size_t cb)
{
	void* pResult = pDest;
	char* bDest = (char*)pDest;
	char* bSrc = (char*)pSrc;
	for (size_t i = 0; i < cb; ++i)
	{
		*bDest++ = *bSrc++;
	}
	return pResult;
}
#endif
#if __cplusplus
extern "C"
#endif
int _fltused = 1;
#endif
#define GET_X_LPARAM(lp)                        ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)                        ((int)(short)HIWORD(lp))