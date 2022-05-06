// TrayS.cpp : 定义应用程序的入口点。
//
#ifdef _WIN64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

#include "framework.h"
#include "TrayS.h"
int DPI(int pixel)
{
	return pixel * iDPI / 96;
}
/*
typedef struct _IP_HEADER {
	BYTE bVerAndHLen;        / *版本信息（前4位）和头长度（后4位）* /
	BYTE bTypeOfService;        //服务类型
	USHORT nTotalLength;        //数据包长度
	USHORT nID;                                //数据包标识
	USHORT nReserved;                //保留字段
	BYTE bTTL;                                //生成时间
	BYTE bProtocol;                        //协议类型
	USHORT nCheckSum;                //校验和
	UINT nSourIp;                        //源IP
	UINT nDestIp;                        //目的IP
}IP_HEADER, * PIP_HEADER;
typedef struct _TCP_HEADER {
	USHORT nSourPort;
	USHORT nDestPort;
	UINT nSequNum;
	UINT nAcknowledgeNum;
	USHORT nHLenAndFlag;
	USHORT nWindowSize;
	USHORT nCheckSum;
	USHORT nrgentPointer;
}TCP_HEADER, * PTCP_HEADER;

typedef struct _UDP_HEADER {
	USHORT nSourPort;
	USHORT nDestPort;
	USHORT nLength;
	USHORT nCheckSum;
}UDP_HEADER, * PUDP_HEADER;


typedef struct _PACK_INFO {
	USHORT nLength;
	USHORT nProtocol;
	UINT nSourIp;
	UINT nDestIp;
	USHORT nSourPort;
	USHORT nDestPort;
}PACK_INFO, * LPPACK_INFO;

void AnalyseTcp(DWORD dwPort, ULONG64 ul64Flow, bool IsRecv)
{
	DWORD dwPid = 0;
	MIB_TCPTABLE_OWNER_PID* stcTcpTable = NULL;
	DWORD szTcpTableSize = 0;
	//获取TCP表大小
	GetExtendedTcpTable(stcTcpTable, &szTcpTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	//分配内存
	stcTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(szTcpTableSize);
	ZeroMemory(stcTcpTable, szTcpTableSize);
	//获取TCP表
	if (NO_ERROR != GetExtendedTcpTable(stcTcpTable, &szTcpTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0))
	{
		free(stcTcpTable);
		return;
	}
	for (DWORD i = 0; i < stcTcpTable->dwNumEntries; i++)
	{
		if (stcTcpTable->table[i].dwLocalPort == dwPort)
			dwPid = stcTcpTable->table[i].dwOwningPid;
	}
	free(stcTcpTable);
}



void AnalyseUdp(DWORD dwPort, ULONG64 ul64Flow, bool IsRecv)
{
	DWORD dwPid = 0;
	MIB_UDPTABLE_OWNER_PID* stcUdpTable = NULL;
	DWORD szUdpTableSize = 0;
	//获取UDP表大小
	GetExtendedUdpTable(stcUdpTable, &szUdpTableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	//分配内存
	stcUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(szUdpTableSize);
	ZeroMemory(stcUdpTable, szUdpTableSize);
	//获取UDP表
	if (NO_ERROR != GetExtendedUdpTable(stcUdpTable, &szUdpTableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0))
	{
		//在实际测试中这个地方确实偶尔是会失败的,不过在频繁的更新中一两次失败无关紧要
		free(stcUdpTable);
		return;
	}
	for (DWORD i = 0; i < stcUdpTable->dwNumEntries; i++)
	{
		if (stcUdpTable->table[i].dwLocalPort == dwPort)
			dwPid = stcUdpTable->table[i].dwOwningPid;
		//此处已经找到进程对应的pid了,同时包的大小和是上传还是下载已经通过参数传进来了。
	}
	free(stcUdpTable);
	//对数据的处理
	//...
}
void Thread()
{
	PACK_INFO        PackInfo = { 0 };
	int nRecvSize = 0;
	char szPackBuf[DEF_BUF_SIZE] = { 0 };

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
		return;

	// 获取本地地址信息
	sockaddr_in LocalAddr;
	char szLocalName[DEF_BUF_SIZE] = { 0 };
	gethostname(szLocalName, DEF_BUF_SIZE);
	hostent* pHost = gethostbyname(szLocalName);
	if (pHost != NULL)
	{
		LocalAddr.sin_family = AF_INET;
		LocalAddr.sin_port = htons(0);
		memcpy(&(LocalAddr.sin_addr.s_addr), pHost->h_addr_list[0], pHost->h_length);
	}
	else
		return;

	// 创建监听套接字
	SOCKET MonSock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (MonSock == INVALID_SOCKET)
		return;

	// 绑定地址信息到套接字
	if (bind(MonSock, (sockaddr*)&LocalAddr, sizeof(sockaddr)) == SOCKET_ERROR)
		return;

	// 设置为混杂模式，收所有IP包
	DWORD dwValue = 1;
	if (ioctlsocket(MonSock, SIO_RCVALL, &dwValue) != 0)
		return;

	while (1)
	{
		// 取得数据包
		nRecvSize = recv(MonSock, szPackBuf, DEF_BUF_SIZE, 0);
		if (nRecvSize > 0)
		{
			// 解析IP包头
			PIP_HEADER pIpHeader = (PIP_HEADER)szPackBuf;
			PackInfo.nLength = nRecvSize;
			PackInfo.nProtocol = (USHORT)pIpHeader->bProtocol;
			PackInfo.nSourIp = pIpHeader->nSourIp;
			PackInfo.nDestIp = pIpHeader->nDestIp;
			UINT nIpHeadLength = (pIpHeader->bVerAndHLen & 0x0F) * sizeof(UINT);                        // IP数据包头长度

			// 只检测TCP和UDP包
			switch (pIpHeader->bProtocol)
			{
			case IPPROTO_TCP:
			{
				// 取得TCP数据包端口号
				PTCP_HEADER pTcpHeader = (PTCP_HEADER)&szPackBuf[nIpHeadLength];
				PackInfo.nSourPort = pTcpHeader->nSourPort;
				PackInfo.nDestPort = pTcpHeader->nDestPort;
				//判断上传还是下载
				if (PackInfo.nSourIp == LocalAddr.sin_addr.S_un.S_addr)
					AnalyseTcp(PackInfo.nSourPort, PackInfo.nLength, FALSE);
				else
					AnalyseTcp(PackInfo.nDestPort, PackInfo.nLength, TRUE);
			}
			break;
			case IPPROTO_UDP:
			{
				// 取得UDP数据包端口号
				PUDP_HEADER pUdpHeader = (PUDP_HEADER)&szPackBuf[nIpHeadLength];
				PackInfo.nSourPort = pUdpHeader->nSourPort;
				PackInfo.nDestPort = pUdpHeader->nDestPort;
				if (PackInfo.nSourIp == LocalAddr.sin_addr.S_un.S_addr)
					AnalyseUdp(PackInfo.nSourPort, PackInfo.nLength, FALSE);
				else
					AnalyseUdp(PackInfo.nDestPort, PackInfo.nLength, TRUE);

			}
			break;
			}
		}

	}
}
*/
BOOL CALLBACK FindWindowFunc(HWND hWnd, LPARAM lpAram)
{
	WCHAR szText[16];
	GetWindowText(hWnd, szText, 16);
	if (lstrcmp(szText, L"_TrayS_") == 0)
	{
		SendMessage(hWnd, WM_TRAYS, 0, 0);
		ExitProcess(0);
		return FALSE;
	}
	return TRUE;
}
BOOL CALLBACK IsZoomedFunc(HWND hWnd, LPARAM lpAram)
{
	if (::IsWindowVisible(hWnd) && IsZoomed(hWnd))
	{
		if (MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST) == (HMONITOR)lpAram)
		{
			BOOL Attribute = FALSE;
			if (pDwmGetWindowAttribute)
				pDwmGetWindowAttribute(hWnd, 14, &Attribute, sizeof(BOOL));
			if (Attribute == FALSE)
			{
				iWindowMode = 1;
				return FALSE;
			}
		}
	}
	return TRUE;
}
/*
BOOL CreateProcessByExplorer(LPCWSTR process, LPCWSTR szDir, LPCWSTR cmd)
{
	BOOL ret = FALSE;

	HANDLE hProcess = 0, hToken = 0, hDuplicatedToken = 0;
	LPVOID lpEnv = NULL;
	do
	{
		HWND hTrayWnd = ::FindWindow(szShellTray, NULL);
		DWORD explorerPid;
		GetWindowThreadProcessId(hTrayWnd, &explorerPid);// 获取explorer进程号，自行实现

		if (explorerPid == NULL)
			break;
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, explorerPid);
		if (INVALID_HANDLE_VALUE == hProcess)
			break;

		if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
			break;

		DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDuplicatedToken);
		CreateEnvironmentBlock(&lpEnv, hDuplicatedToken, FALSE);

		/ *
			WCHAR szDir[MAX_PATH] = L"\"";
		wcscpy_s(&szDir[2], MAX_PATH, process);
		int iLen = wcslen(szDir);
		if (NULL != cmd)
		{
			wcscpy_s(&szDir[iLen], MAX_PATH, L"\" \"");
			iLen = wcslen(szDir);
			wcscpy_s(&szDir[iLen], MAX_PATH, cmd);
		}
		iLen = wcslen(szDir);
		wcscpy_s(&szDir[iLen], MAX_PATH, L"\"");
		* /

			STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = (LPWSTR)L"winsta0\\default";
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		if (!CreateProcessAsUser(hToken, process, NULL / *const_cast<LPWSTR>(szDir) * / , 0, 0, FALSE, CREATE_UNICODE_ENVIRONMENT, lpEnv, NULL, &si, &pi))
			break;
		ret = TRUE;
	} while (0);
	if (INVALID_HANDLE_VALUE != hProcess)
		CloseHandle(hProcess);
	if (INVALID_HANDLE_VALUE != hToken)
		CloseHandle(hToken);
	if (INVALID_HANDLE_VALUE != hDuplicatedToken)
		CloseHandle(hDuplicatedToken);
	if (NULL != lpEnv)
		DestroyEnvironmentBlock(lpEnv);
	return ret;
}

*/
#define CTL_CODE( DeviceType, Function, Method, Access ) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define IOCTL_STORAGE_GET_DEVICE_NUMBER       CTL_CODE(0x0000002d, 0x0420, 0, 0)

typedef struct _STORAGE_DEVICE_NUMBER {
	DWORD		DeviceType;
	DWORD       DeviceNumber;
	DWORD       PartitionNumber;
} STORAGE_DEVICE_NUMBER, * PSTORAGE_DEVICE_NUMBER;
DWORD GetPhysicalDriveFromPartitionLetter(WCHAR letter)
{
	HANDLE hDevice;
	BOOL result;
	DWORD readed;
	STORAGE_DEVICE_NUMBER number;
	WCHAR path[64];
	wsprintf(path, L"\\\\.\\%c:", letter);
	hDevice = CreateFile(path,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
	{
		return DWORD(-1);
	}

	result = DeviceIoControl(hDevice,IOCTL_STORAGE_GET_DEVICE_NUMBER,NULL,0,&number,sizeof(number),&readed,NULL);
	if (!result) // fail
	{
		(void)CloseHandle(hDevice);
		return (DWORD)-1;
	}
	(void)CloseHandle(hDevice);
	return number.DeviceNumber;
}

DWORD iCPU;
/////////////////////////////////////////////////////////////////////////////CPU占用率
FILETIME pre_idleTime;
FILETIME pre_kernelTime;
FILETIME pre_userTime;
__int64 CompareFileTime(FILETIME time1, FILETIME time2)
{
	__int64 a = time1.dwHighDateTime;
	a = a << 32 | time1.dwLowDateTime;
	__int64 b = time2.dwHighDateTime;
	b = b << 32 | time2.dwLowDateTime;
	return (b - a);
}
typedef struct _PDH_RAW_COUNTER {
	volatile DWORD CStatus;
	FILETIME    TimeStamp;
	LONGLONG    FirstValue;
	LONGLONG    SecondValue;
	DWORD       MultiCount;
} PDH_RAW_COUNTER, * PPDH_RAW_COUNTER;
PDH_RAW_COUNTER m_last_rawData;
BOOL m_first_get_CPU_utility=TRUE;
double diskreadbyte=0;
double diskwritebyte=0;
long disktime = 0;

#define PDH_FMT_RAW          ((DWORD) 0x00000010)
#define PDH_FMT_ANSI         ((DWORD) 0x00000020)
#define PDH_FMT_UNICODE      ((DWORD) 0x00000040)
#define PDH_FMT_LONG         ((DWORD) 0x00000100)
#define PDH_FMT_DOUBLE       ((DWORD) 0x00000200)
#define PDH_FMT_LARGE        ((DWORD) 0x00000400)
#define PDH_FMT_NOSCALE      ((DWORD) 0x00001000)
#define PDH_FMT_1000         ((DWORD) 0x00002000)
#define PDH_FMT_NODATA       ((DWORD) 0x00004000)
#define PDH_FMT_NOCAP100     ((DWORD) 0x00008000)
#define PERF_DETAIL_COSTLY   ((DWORD) 0x00010000)
#define PERF_DETAIL_STANDARD ((DWORD) 0x0000FFFF)
typedef HANDLE       PDH_HCOUNTER;
typedef HANDLE       PDH_HQUERY;
typedef HANDLE       PDH_HLOG;

typedef PDH_HCOUNTER HCOUNTER;
typedef PDH_HQUERY   HQUERY;

typedef struct _PDH_FMT_COUNTERVALUE {
	DWORD    CStatus;
	union {
		LONG        longValue;
		double      doubleValue;
		LONGLONG    largeValue;
		LPCSTR      AnsiStringValue;
		LPCWSTR     WideStringValue;
	};
} PDH_FMT_COUNTERVALUE, * PPDH_FMT_COUNTERVALUE;
HQUERY hQuery;
HCOUNTER hCounter;
HCOUNTER hDiskRead;
HCOUNTER hDiskWrite;
HCOUNTER hDiskTime;
DWORD counterType;
PDH_RAW_COUNTER rawData;
typedef ULONG(WINAPI* pfnPdhOpenQuery)(_In_opt_ LPCWSTR szDataSource, _In_ DWORD_PTR dwUserData, _Out_ PDH_HQUERY* phQuery);
typedef ULONG(WINAPI* pfnPdhAddCounter)(_In_ PDH_HQUERY hQuery, _In_ LPCWSTR szFullCounterPath, _In_ DWORD_PTR dwUserData, _Out_ PDH_HCOUNTER* phCounter);
typedef ULONG(WINAPI* pfnPdhCollectQueryData)(PDH_HQUERY hQuery);
typedef ULONG(WINAPI* pfnPdhGetRawCounterValue)(PDH_HCOUNTER hCounter, LPDWORD lpdwType, PPDH_RAW_COUNTER pValue);
typedef ULONG(WINAPI* pfnPdhCalculateCounterFromRawValue)(PDH_HCOUNTER hCounter, DWORD dwFormat, PPDH_RAW_COUNTER rawValue1, PPDH_RAW_COUNTER rawValue2, PPDH_FMT_COUNTERVALUE fmtValue);
typedef ULONG(WINAPI* pfnPdhCloseQuery)(PDH_HQUERY hQuery);
typedef ULONG(WINAPI* pfnPdhGetFormattedCounterValue)(PDH_HCOUNTER hCounter, DWORD dwFormat, LPDWORD lpdwType, PPDH_FMT_COUNTERVALUE pValue);
pfnPdhOpenQuery PdhOpenQuery;
pfnPdhAddCounter PdhAddCounter;
pfnPdhCollectQueryData PdhCollectQueryData;
pfnPdhGetRawCounterValue PdhGetRawCounterValue;
pfnPdhCalculateCounterFromRawValue PdhCalculateCounterFromRawValue;
pfnPdhCloseQuery PdhCloseQuery;
pfnPdhGetFormattedCounterValue PdhGetFormattedCounterValue;
void SwitchPDH(BOOL bOn)
{
	if (bOn)
	{
		if (hPDH == NULL)
			hPDH = LoadLibrary(L"pdh.dll");
		if (hPDH)
		{
			PdhOpenQuery = (pfnPdhOpenQuery)GetProcAddress(hPDH, "PdhOpenQueryW");
			PdhAddCounter = (pfnPdhAddCounter)GetProcAddress(hPDH, "PdhAddCounterW");
			PdhCollectQueryData = (pfnPdhCollectQueryData)GetProcAddress(hPDH, "PdhCollectQueryData");
			PdhGetRawCounterValue = (pfnPdhGetRawCounterValue)GetProcAddress(hPDH, "PdhGetRawCounterValue");
			PdhCalculateCounterFromRawValue = (pfnPdhCalculateCounterFromRawValue)GetProcAddress(hPDH, "PdhCalculateCounterFromRawValue");
			PdhCloseQuery = (pfnPdhCloseQuery)GetProcAddress(hPDH, "PdhCloseQuery");
			PdhGetFormattedCounterValue = (pfnPdhGetFormattedCounterValue)GetProcAddress(hPDH, "PdhGetFormattedCounterValue");
			if (PdhCloseQuery != NULL && PdhAddCounter != NULL && PdhCollectQueryData != NULL && PdhGetRawCounterValue != NULL && PdhCalculateCounterFromRawValue != NULL && PdhCloseQuery != NULL)
			{
				PdhOpenQuery(NULL, 0, &hQuery);//开始查询
				const wchar_t* cpuquery_str{};
				cpuquery_str = L"\\Processor Information(_Total)\\% Processor Utility";
				PdhAddCounter(hQuery, cpuquery_str, NULL, &hCounter);				
				if (TraySave.szDisk == L'\0')
				{
					const wchar_t* diskreadquery_str{};
					const wchar_t* diskwritequery_str{};
					const wchar_t* disktimequery_str{};
					diskreadquery_str = L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec";
					diskwritequery_str = L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec";
					disktimequery_str = L"\\PhysicalDisk(_Total)\\% Disk Time";
					PdhAddCounter(hQuery, diskreadquery_str, NULL, &hDiskRead);
					PdhAddCounter(hQuery, diskwritequery_str, NULL, &hDiskWrite);
					PdhAddCounter(hQuery, disktimequery_str, NULL, &hDiskTime);
				}
				else
				{
					WCHAR sz[256];
					DWORD d = GetPhysicalDriveFromPartitionLetter(TraySave.szDisk);
					wsprintf(sz, L"\\PhysicalDisk(%d %c:)\\Disk Read Bytes/sec", d, TraySave.szDisk);
					PdhAddCounter(hQuery, sz, NULL, &hDiskRead);
					wsprintf(sz, L"\\PhysicalDisk(%d %c:)\\Disk Write Bytes/sec", d, TraySave.szDisk);
					PdhAddCounter(hQuery, sz, NULL, &hDiskWrite);
					wsprintf(sz, L"\\PhysicalDisk(%d %c:)\\%% Disk Time", d, TraySave.szDisk);
					PdhAddCounter(hQuery, sz, NULL, &hDiskTime);
				}			
			}
		}
	}
	else
	{
		PdhCloseQuery(hQuery);//关闭查询
		FreeLibrary(hPDH);
		hPDH = NULL;
	}
}
int GetPDH(BOOL bCPU, BOOL bDisk)
{
	if (hPDH == NULL)
		SwitchPDH(TRUE);
	PdhCollectQueryData(hQuery);
	if (bCPU)
	{		
		PdhGetRawCounterValue(hCounter, &counterType, &rawData);
		PDH_FMT_COUNTERVALUE fmtValue;
		PdhCalculateCounterFromRawValue(hCounter, PDH_FMT_DOUBLE, &rawData, &m_last_rawData, &fmtValue);//计算使用率
		iCPU = (int)fmtValue.doubleValue;//传出数据
		if (iCPU >= 100)
			iCPU = 99;
		m_last_rawData = rawData;//保存上一次数据
	}
	if (bDisk)
	{
		PDH_FMT_COUNTERVALUE pdhValue;
		DWORD dwValue;
		PdhGetFormattedCounterValue(hDiskRead, PDH_FMT_DOUBLE, &dwValue, &pdhValue);
		diskreadbyte = pdhValue.doubleValue;		
		PdhGetFormattedCounterValue(hDiskWrite, PDH_FMT_DOUBLE, &dwValue, &pdhValue);
		diskwritebyte = pdhValue.doubleValue;
		PdhGetFormattedCounterValue(hDiskTime, PDH_FMT_LONG, &dwValue, &pdhValue);
		disktime = pdhValue.longValue;
		if (disktime == 100)
			disktime = 99;
	}
	return iCPU;
}
int GetCPUUseRate()
{
	if (TraySave.bMonitorPDH)
	{
		return GetPDH(TRUE,TraySave.bMonitorDisk);
	}
	else
	{
		if (hPDH)
		{
			SwitchPDH(FALSE);
		}
		int nCPUUseRate = -1;
		FILETIME idleTime;//空闲时间 
		FILETIME kernelTime;//核心态时间 
		FILETIME userTime;//用户态时间 
		GetSystemTimes(&idleTime, &kernelTime, &userTime);

		__int64 idle = CompareFileTime(pre_idleTime, idleTime);
		__int64 kernel = CompareFileTime(pre_kernelTime, kernelTime);
		__int64 user = CompareFileTime(pre_userTime, userTime);
		if (kernel + user != 0)
			nCPUUseRate = (int)((kernel + user - idle) * 100 / (kernel + user));
		pre_idleTime = idleTime;
		pre_kernelTime = kernelTime;
		pre_userTime = userTime;
		if (nCPUUseRate < 1)
			nCPUUseRate = iCPU;
		else if (nCPUUseRate >= 100)
			nCPUUseRate = 99;
		return nCPUUseRate;
	}
}
void ReadReg()//读取设置
{
/*
	if (rovi.dwBuildNumber > 22000)
	{
		TraySave.bAlpha[0] = 188;
		TraySave.bAlpha[1] = 208;
	}
*/
	SetToCurrentPath();
	HANDLE hFile = CreateFile(szTraySave, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (hFile)
	{
		DWORD dwBytes;
		ReadFile(hFile, &TraySave, sizeof TraySave, &dwBytes, NULL);		
		CloseHandle(hFile);
	}
	/*
		HKEY pKey;
		if(IsUserAdmin())
			RegOpenKeyEx(HKEY_LOCAL_MACHINE, szSubKey, NULL, KEY_ALL_ACCESS, &pKey);
		else
			RegOpenKeyEx(HKEY_CURRENT_USER, szSubKey, NULL, KEY_ALL_ACCESS, &pKey);
		if (pKey)
		{
			DWORD dType = REG_BINARY;
			DWORD cbData = sizeof(aMode);
			RegQueryValueEx(pKey, szMode, NULL, &dType, (BYTE*)aMode, &cbData);
			dType = REG_BINARY;
			cbData = sizeof(dAlphaColor);
			RegQueryValueEx(pKey, szAlphaColor, NULL, &dType, (BYTE*)dAlphaColor, &cbData);
			dType = REG_BINARY;
			cbData = sizeof(bAlpha);
			RegQueryValueEx(pKey, szAlpha, NULL, &dType, (BYTE*)bAlpha, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szPos, NULL, &dType, (BYTE*)&iPos, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szUnit, NULL, &dType, (BYTE*)&iUnit, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szTrayIcon, NULL, &dType, (BYTE*)&bTrayIcon, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitor, NULL, &dType, (BYTE*)&bMonitor, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorLeft, NULL, &dType, (BYTE*)&bMonitorLeft, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorFloat, NULL, &dType, (BYTE*)&bMonitorFloat, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorTransparent, NULL, &dType, (BYTE*)&bMonitorTransparent, &cbData);
			dType = REG_BINARY;
			cbData = sizeof(dMonitorPoint);
			RegQueryValueEx(pKey, szMonitorPoint, NULL, &dType, (BYTE*)&dMonitorPoint, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorTraffic, NULL, &dType, (BYTE*)&bMonitorTraffic, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorTemperature, NULL, &dType, (BYTE*)&bMonitorTemperature, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorUsage, NULL, &dType, (BYTE*)&bMonitorUsage, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szSound, NULL, &dType, (BYTE*)&bSound, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorPDH, NULL, &dType, (BYTE*)&bMonitorPDH, &cbData);
			dType = REG_DWORD;
			cbData = sizeof(DWORD);
			RegQueryValueEx(pKey, szMonitorSimple, NULL, &dType, (BYTE*)&bMonitorSimple, &cbData);
			dType = REG_BINARY;
			cbData = sizeof(cMonitorColor);
			RegQueryValueEx(pKey, szMonitorColor, NULL, &dType, (BYTE*)cMonitorColor, &cbData);
			dType = REG_BINARY;
			cbData = sizeof(dNumValues);
			RegQueryValueEx(pKey, szNumValues, NULL, &dType, (BYTE*)dNumValues, &cbData);
			dType = REG_BINARY;
			cbData = 38;
			RegQueryValueEx(pKey, szAdapterName, NULL, &dType, (BYTE*)AdpterName, &cbData);
			RegCloseKey(pKey);
		}
	*/
}
void WriteReg()//写入设置
{
	SetToCurrentPath();
	HANDLE hFile = CreateFile(szTraySave, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (hFile)
	{
		DWORD dwBytes;
		WriteFile(hFile, &TraySave, sizeof TraySave, &dwBytes, NULL);
		CloseHandle(hFile);
	}
	/*
		HKEY pKey;
		if (IsUserAdmin())
		{
			RegCreateKey(HKEY_LOCAL_MACHINE, szSubKey, &pKey);
			RegCloseKey(pKey);
			RegOpenKeyEx(HKEY_LOCAL_MACHINE, szSubKey, NULL, KEY_ALL_ACCESS, &pKey);
		}
		else
		{
			RegCreateKey(HKEY_CURRENT_USER, szSubKey, &pKey);
			RegCloseKey(pKey);
			RegOpenKeyEx(HKEY_CURRENT_USER, szSubKey, NULL, KEY_ALL_ACCESS, &pKey);
		}
		if (pKey)
		{
			RegSetValueEx(pKey, szMode, NULL, REG_BINARY, (BYTE*)aMode, sizeof(aMode));
			RegSetValueEx(pKey, szAlphaColor, NULL, REG_BINARY, (BYTE*)dAlphaColor, sizeof(dAlphaColor));
			RegSetValueEx(pKey, szAlpha, NULL, REG_BINARY, (BYTE*)bAlpha, sizeof(bAlpha));
			RegSetValueEx(pKey, szPos, NULL, REG_DWORD, (BYTE*)&iPos, sizeof(iPos));
			RegSetValueEx(pKey, szUnit, NULL, REG_DWORD, (BYTE*)&iUnit, sizeof(iUnit));
			RegSetValueEx(pKey, szTrayIcon, NULL, REG_DWORD, (BYTE*)&bTrayIcon, sizeof(bTrayIcon));
			RegSetValueEx(pKey, szMonitor, NULL, REG_DWORD, (BYTE*)&bMonitor, sizeof(bMonitor));
			RegSetValueEx(pKey, szMonitorLeft, NULL, REG_DWORD, (BYTE*)&bMonitorLeft, sizeof(bMonitorLeft));
			RegSetValueEx(pKey, szMonitorFloat, NULL, REG_DWORD, (BYTE*)&bMonitorFloat, sizeof(bMonitorFloat));
			RegSetValueEx(pKey, szMonitorTransparent, NULL, REG_DWORD, (BYTE*)&bMonitorTransparent, sizeof(bMonitorTransparent));
			RegSetValueEx(pKey, szMonitorPoint, NULL, REG_BINARY, (BYTE*)&dMonitorPoint, sizeof(dMonitorPoint));
			RegSetValueEx(pKey, szMonitorTraffic, NULL, REG_DWORD, (BYTE*)&bMonitorTraffic, sizeof(bMonitorTraffic));
			RegSetValueEx(pKey, szMonitorTemperature, NULL, REG_DWORD, (BYTE*)&bMonitorTemperature, sizeof(bMonitorTemperature));
			RegSetValueEx(pKey, szMonitorUsage, NULL, REG_DWORD, (BYTE*)&bMonitorUsage, sizeof(bMonitorUsage));
			RegSetValueEx(pKey, szMonitorPDH, NULL, REG_DWORD, (BYTE*)&bMonitorPDH, sizeof(bMonitorPDH));
			RegSetValueEx(pKey, szMonitorSimple, NULL, REG_DWORD, (BYTE*)&bMonitorSimple, sizeof(bMonitorSimple));
			RegSetValueEx(pKey, szSound, NULL, REG_DWORD, (BYTE*)&bSound, sizeof(bSound));
			RegSetValueEx(pKey, szMonitorColor, NULL, REG_BINARY, (BYTE*)cMonitorColor, sizeof(cMonitorColor));
			RegSetValueEx(pKey, szNumValues, NULL, REG_BINARY, (BYTE*)dNumValues, sizeof(dNumValues));
			RegSetValueEx(pKey, szAdapterName, NULL, REG_BINARY, (BYTE*)AdpterName, 38);
			RegCloseKey(pKey);
		}
	*/
}
void GetShellAllWnd()
{
	while (IsWindow(hTray) == FALSE)
	{
		hTray = FindWindow(szShellTray, NULL);
		if (hTray == NULL)
			Sleep(100);
	}
	hReBarWnd = FindWindowEx(hTray, 0, L"ReBarWindow32", NULL);
	hStartWnd = FindWindowEx(hTray, 0, L"Start", NULL);
	hTrayNotifyWnd = FindWindowEx(hTray, 0, L"TrayNotifyWnd", NULL);
	if(hReBarWnd)
		hTaskWnd = FindWindowEx(hReBarWnd, NULL, L"MSTaskSwWClass", NULL);
	if(hTaskWnd)
		hTaskListWnd = FindWindowEx(hTaskWnd, NULL, L"MSTaskListWClass", NULL);
	if(!hTaskListWnd)
		hTaskListWnd = FindWindowEx(hTaskWnd, NULL, L"ToolbarWindow32", NULL);
	hWin11UI = FindWindowEx(hTray, 0, L"Windows.UI.Composition.DesktopWindowContentBridge", NULL);
	if(hTrayNotifyWnd)
		hTrayClockWnd = FindWindowEx(hTrayNotifyWnd, NULL, L"TrayClockWClass", NULL);
/*
	if (hWin11UI)
	{
		if (TraySave.cMonitorColor[0] == 0 && !TraySave.bMonitorFloat)
			TraySave.cMonitorColor[0] = RGB(1, 2, 3);
	}
*/
}
void CloseTaskBar()
{
	if (IsWindow(hTaskBar))
		DestroyWindow(hTaskBar);
	if (IsWindow(hTaskTips))
		DestroyWindow(hTaskTips);
	if(IsWindow(hTime))
		DestroyWindow(hTime);
}
void OpenTimeDlg()
{
	if (!IsWindow(hTime) && TraySave.bSecond)
	{
		
		if (!hWin11UI)
		{
			hTime = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_TIME), NULL, (DLGPROC)TimeProc);
			if (hTrayClockWnd)
				SetParent(hTime, hTrayClockWnd);
		}
		else
		{
			hTime = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_TIME), NULL, (DLGPROC)TimeProc);
			SetWindowLongPtr(hTime, GWL_EXSTYLE, GetWindowLongPtr(hTime, GWL_EXSTYLE) | WS_EX_LAYERED|WS_EX_TRANSPARENT);
/*
			if(bThemeMode&&rovi.dwBuildNumber>22000)
				SetLayeredWindowAttributes(hTime, RGB(254,254,255), 0, LWA_COLORKEY);
			else
*/
				SetLayeredWindowAttributes(hTime, RGB(0, 0, 1), 0, LWA_COLORKEY);
			SetParent(hTime, hTray);
		}
		ShowWindow(hTime, SW_SHOW);
	}
}

void OpenTaskBar()
{
	if (IsWindow(hTaskBar) == FALSE)
	{
		if (TraySave.cMonitorColor[0] == RGB(1, 2, 3))
			TraySave.cMonitorColor[0] = RGB(0,0,1);
		hTaskBar = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_TASKBAR), NULL, (DLGPROC)TaskBarProc);
		if (hTaskBar)
		{
			SetWindowCompositionAttribute(hTaskBar, ACCENT_ENABLE_TRANSPARENT, 0x00111111);
			if (TraySave.bMonitorFloat)
			{
				if (TraySave.cMonitorColor[0] == RGB(1, 2, 3))
					TraySave.cMonitorColor[0] = RGB(0,0,1);
				if (TraySave.cMonitorColor[0] == RGB(0,0,1) || TraySave.cMonitorColor[0] == 0)
				{
					bShadow = TRUE;
				}
				else
					bShadow = FALSE;
			}
			else
			{
//				if (rovi.dwBuildNumber <= 22000||bFullScreen)
				{
					if (TraySave.cMonitorColor[0] == RGB(0, 0, 1) || TraySave.cMonitorColor[0] == 0)
					{
						bShadow = TRUE;
						TraySave.bMonitorFuse = TRUE;
					}
					else
					{
/*
						if (rovi.dwBuildNumber >= 22000)
						{
							SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) | WS_EX_LAYERED);
							SetLayeredWindowAttributes(hTaskBar, RGB(0, 0, 1), 128, LWA_COLORKEY | LWA_ALPHA);
						}
*/
						bShadow = FALSE;
					}
				}
/*
				else
				{
					bShadow = FALSE;
					if (TraySave.cMonitorColor[0] == 0)
						TraySave.cMonitorColor[0] = RGB(0, 0, 1);
					SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) | WS_EX_LAYERED);
					if (bThemeMode)
						SetLayeredWindowAttributes(hTaskBar, RGB(222, 222, 223), 128, LWA_COLORKEY | LWA_ALPHA);
					else
						SetLayeredWindowAttributes(hTaskBar, RGB(0, 0, 1), 128, LWA_COLORKEY | LWA_ALPHA);
				}
*/
				if(!bFullScreen)
					SetParent(hTaskBar, hTray);
			}
			SetWH();
			if (TraySave.bMonitorTransparent)
				SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) | WS_EX_TRANSPARENT);
			ShowWindow(hTaskBar, SW_SHOW);
			SetTimer(hTaskBar, 3, 1000, NULL);
			//			SetTimer(hTaskBar, 6, 100, NULL);
		}
	}
}
////////////////////////////////////////////获取CPU温度
#define MISC_CONTROL_3 0x3+((0x18)<<3)
int GetCpuTemp(DWORD Core)
{
	if (bRing0)
	{
		SetThreadAffinityMask(GetCurrentThread(), Core);
		DWORD eax = 0, ebx, ecx, edx;
		if (!bIntel)
		{
			Cpuid(1, &eax, &ebx, &ecx, &edx);
			int family = ((eax >> 20) & 0xFF) + ((eax >> 8) & 0xF);
			if (family > 0xf)
			{
				//				DWORD pciDevAddr = FindPciDeviceById(0x1022, 0x1203, 0);
				DWORD miscReg;
				ReadPciConfigDwordEx(MISC_CONTROL_3, 0xa4, &miscReg);
				return (miscReg >> 21) >> 3;
			}
			else
			{
				//				DWORD pciDevAddr = FindPciDeviceById(0x1022, 0x1103, 0);
				DWORD miscReg;
				ReadPciConfigDwordEx(MISC_CONTROL_3, 0xe4, &miscReg);
				return ((miscReg & 0xFF0000) >> 16) - 49;
				//				return (miscReg >> 16) & 0xFF;
			}
		}
		else
		{
			DWORD IAcore;
			int Tjunction = 100;
			Rdmsr(0x1A2, &eax, &edx);
			if (eax & 0x20000000)
				Tjunction = 85;
			Rdmsr(0x19C, &eax, &edx);
			IAcore = eax;
			IAcore &= 0xFF0000;
			IAcore = IAcore >> 16;
			return Tjunction - IAcore;
		}
	}
	return 0;
}
//////////////////////////////////////////////////载入温度DLL
void LoadTemperatureDLL()
{
	if (!InitOpenLibSys(&m_hOpenLibSys))
		bRing0 = FALSE;
	else
	{
		bRing0 = TRUE;
		DWORD eax, ebx, ecx, edx;
		Cpuid(0, &eax, &ebx, &ecx, &edx);
		bIntel = TRUE;
		if (ebx == 0x68747541)
		{
			bIntel = FALSE;
		}
	}
#ifdef _WIN64
	hNVDLL = LoadLibrary(L"nvapi64.dll");
#else
	hNVDLL = LoadLibrary(L"nvapi.dll");
#endif
	if (hNVDLL)
	{
		NvAPI_QueryInterface = (NvAPI_QueryInterface_t)GetProcAddress(hNVDLL, "nvapi_QueryInterface");
		if (NvAPI_QueryInterface)
		{
			NvAPI_Initialize_t NvAPI_Initialize = (NvAPI_Initialize_t)NvAPI_QueryInterface(ID_NvAPI_Initialize);
			NvAPI_EnumPhysicalGPUs_t NvAPI_EnumPhysicalGPUs = (NvAPI_EnumPhysicalGPUs_t)NvAPI_QueryInterface(ID_NvAPI_EnumPhysicalGPUs);
			NvAPI_GPU_GetThermalSettings = (NvAPI_GPU_GetThermalSettings_t)NvAPI_QueryInterface(ID_NvAPI_GPU_GetThermalSettings);
			if (NvAPI_Initialize != NULL && NvAPI_EnumPhysicalGPUs != NULL && NvAPI_GPU_GetThermalSettings != NULL)
			{
				if (NvAPI_Initialize() == 0)
				{
					for (NvU32 PhysicalGpuIndex = 0; PhysicalGpuIndex < 4; PhysicalGpuIndex++)
					{
						hPhysicalGpu[PhysicalGpuIndex] = 0;
					}
					int physicalGpuCount;
					NvAPI_EnumPhysicalGPUs(hPhysicalGpu, &physicalGpuCount);
				}
				else
				{
					FreeLibrary(hNVDLL);
					hNVDLL = NULL;
				}
			}
			else
			{
				FreeLibrary(hNVDLL);
				hNVDLL = NULL;
			}
		}
		else
		{
			FreeLibrary(hNVDLL);
			hNVDLL = NULL;
		}
	}
#ifdef _WIN64
	hATIDLL = LoadLibrary(L"atiadlxx.dll");
#else
	hATIDLL = LoadLibrary(L"atiadlxy.dll");
#endif
	if (hATIDLL)
	{
		ADL_Main_Control_Create = (ADL_MAIN_CONTROL_CREATE)GetProcAddress(hATIDLL, "ADL_Main_Control_Create");
		ADL_Main_Control_Destroy = (ADL_MAIN_CONTROL_DESTROY)GetProcAddress(hATIDLL, "ADL_Main_Control_Destroy");
		ADL_Overdrive5_Temperature_Get = (ADL_OVERDRIVE5_TEMPERATURE_GET)GetProcAddress(hATIDLL, "ADL_Overdrive5_Temperature_Get");
		if (NULL != ADL_Main_Control_Create &&
			NULL != ADL_Main_Control_Destroy
			)
		{
			if (ADL_OK != ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1))
			{
				FreeLibrary(hATIDLL);
				hATIDLL = NULL;
			}
		}
		else
		{
			FreeLibrary(hATIDLL);
			hATIDLL = NULL;
		}
	}
}
///////////////////////////////////释放温度DLL
void FreeTemperatureDLL()
{
	if (hATIDLL)
	{
		ADL_Main_Control_Destroy();
		FreeLibrary(hATIDLL);
		hATIDLL = NULL;
	}
	if (hNVDLL)
	{
		FreeLibrary(hNVDLL);
		hNVDLL = NULL;
	}
	if (m_hOpenLibSys)
		DeinitOpenLibSys(&m_hOpenLibSys);
	m_hOpenLibSys = NULL;
}
///////////////////////////////////////////////打开读取设置
void OpenSetting()
{
	if (IsWindow(hSetting))
	{
		SetForegroundWindow(hSetting);
		return;
	}
	hSetting = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_SETTING), NULL, (DLGPROC)SettingProc);
	if (!hSetting)
	{
		return;
	}
	SendMessage(hSetting, WM_SETICON, ICON_BIG, (LPARAM)(HICON)iMain);
	SendMessage(hSetting, WM_SETICON, ICON_SMALL, (LPARAM)(HICON)iMain);
	CheckRadioButton(hSetting, IDC_RADIO_NORMAL, IDC_RADIO_MAXIMIZE, IDC_RADIO_NORMAL);
	iProject = iWindowMode;
	if (iProject == 0)
		CheckRadioButton(hSetting, IDC_RADIO_NORMAL, IDC_RADIO_MAXIMIZE, IDC_RADIO_NORMAL);
	else
		CheckRadioButton(hSetting, IDC_RADIO_NORMAL, IDC_RADIO_MAXIMIZE, IDC_RADIO_MAXIMIZE);
	if (TraySave.aMode[iProject] == ACCENT_DISABLED)
		CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_DEFAULT);
	else if (TraySave.aMode[iProject] == ACCENT_ENABLE_TRANSPARENTGRADIENT)
		CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_TRANSPARENT);
	else if (TraySave.aMode[iProject] == ACCENT_ENABLE_BLURBEHIND)
		CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_BLURBEHIND);
	else if (TraySave.aMode[iProject] == ACCENT_ENABLE_ACRYLICBLURBEHIND)
		CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_ACRYLIC);
	if (TraySave.iPos == 0)
		CheckRadioButton(hSetting, IDC_RADIO_LEFT, IDC_RADIO_RIGHT, IDC_RADIO_LEFT);
	else if (TraySave.iPos == 1)
		CheckRadioButton(hSetting, IDC_RADIO_LEFT, IDC_RADIO_RIGHT, IDC_RADIO_CENTER);
	else if (TraySave.iPos == 2)
		CheckRadioButton(hSetting, IDC_RADIO_LEFT, IDC_RADIO_RIGHT, IDC_RADIO_RIGHT);
	if (hWin11UI)
	{
		EnableWindow(GetDlgItem(hSetting, IDC_RADIO_LEFT), FALSE);
		EnableWindow(GetDlgItem(hSetting, IDC_RADIO_CENTER), FALSE);
		EnableWindow(GetDlgItem(hSetting, IDC_RADIO_RIGHT), FALSE);
//		EnableWindow(GetDlgItem(hSetting, IDC_CHECK_TOPMOST), TRUE);
	}
	if (LOWORD(TraySave.iUnit) == 0)
		CheckRadioButton(hSetting, IDC_RADIO_AUTO, IDC_RADIO_MB, IDC_RADIO_AUTO);
	else if (LOWORD(TraySave.iUnit) == 1)
		CheckRadioButton(hSetting, IDC_RADIO_AUTO, IDC_RADIO_MB, IDC_RADIO_KB);
	else if (LOWORD(TraySave.iUnit) == 2)
		CheckRadioButton(hSetting, IDC_RADIO_AUTO, IDC_RADIO_MB, IDC_RADIO_MB);
	if (HIWORD(TraySave.iUnit) == 0)
		CheckRadioButton(hSetting, IDC_RADIO_BYTE, IDC_RADIO_BIT, IDC_RADIO_BYTE);
	else
		CheckRadioButton(hSetting, IDC_RADIO_BYTE, IDC_RADIO_BIT, IDC_RADIO_BIT);
	CheckDlgButton(hSetting, IDC_CHECK_TRAYICON, TraySave.bTrayIcon);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR, TraySave.bMonitor);
	CheckDlgButton(hSetting, IDC_CHECK_TRAFFIC, TraySave.bMonitorTraffic);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_UPDOWN, TraySave.bMonitorTrafficUpDown);
	CheckDlgButton(hSetting, IDC_CHECK_TEMPERATURE, TraySave.bMonitorTemperature);
	CheckDlgButton(hSetting, IDC_CHECK_USAGE, TraySave.bMonitorUsage);
	CheckDlgButton(hSetting, IDC_CHECK_DISK, TraySave.bMonitorDisk);
	CheckDlgButton(hSetting, IDC_CHECK_SOUND, TraySave.bSound);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_PDH, TraySave.bMonitorPDH);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_SIMPLE, TraySave.iMonitorSimple);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_LEFT, TraySave.bMonitorLeft);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_NEAR, TraySave.bNear);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_FLOAT, TraySave.bMonitorFloat);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_FLOAT_VROW, TraySave.bMonitorFloatVRow);
	CheckDlgButton(hSetting, IDC_CHECK_MONITOR_TIME, TraySave.bMonitorTime);
	CheckDlgButton(hSetting, IDC_CHECK_TIME, TraySave.bSecond);
	CheckDlgButton(hSetting, IDC_CHECK_TRANSPARENT, TraySave.bMonitorTransparent);
	CheckDlgButton(hSetting, IDC_CHECK_TIPS, TraySave.bMonitorTips);
	CheckDlgButton(hSetting, IDC_CHECK_FUSE, TraySave.bMonitorFuse);
	CheckDlgButton(hSetting, IDC_CHECK_TOPMOST, TraySave.bMonitorTopmost);
	SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA, TBM_SETRANGE, 0, MAKELPARAM(0, 255));
	SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA, TBM_SETPOS, TRUE, TraySave.bAlpha[iProject]);
	SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA_B, TBM_SETRANGE, 0, MAKELPARAM(0, 255));
	BYTE bAlphaB = TraySave.dAlphaColor[iProject] >> 24;
	SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA_B, TBM_SETPOS, TRUE, bAlphaB);
	SendDlgItemMessage(hSetting, IDC_CHECK_AUTORUN, BM_SETCHECK, AutoRun(FALSE, FALSE, szAppName), NULL);
	bSettingInit = TRUE;
	SetDlgItemInt(hSetting, IDC_EDIT1, TraySave.dNumValues[0] / 1048576, 0);
	SetDlgItemInt(hSetting, IDC_EDIT2, TraySave.dNumValues[1] / 1048576, 0);
	SetDlgItemInt(hSetting, IDC_EDIT3, TraySave.dNumValues[2], 0);
	SetDlgItemInt(hSetting, IDC_EDIT4, TraySave.dNumValues[3], 0);
	SetDlgItemInt(hSetting, IDC_EDIT5, TraySave.dNumValues[4], 0);
	SetDlgItemInt(hSetting, IDC_EDIT6, TraySave.dNumValues[5], 0);
	SetDlgItemInt(hSetting, IDC_EDIT7, TraySave.dNumValues[6], 0);
	SetDlgItemInt(hSetting, IDC_EDIT8, TraySave.dNumValues[7], 0);
	SetDlgItemInt(hSetting, IDC_EDIT9, TraySave.dNumValues[8] / 1048576, 0);
	SetDlgItemInt(hSetting, IDC_EDIT10, TraySave.dNumValues[9], 0);
	SetDlgItemInt(hSetting, IDC_EDIT11, TraySave.dNumValues[10], 0);
	SetDlgItemInt(hSetting, IDC_EDIT12, TraySave.dNumValues[11], 0);
	SetDlgItemInt(hSetting, IDC_EDIT24, TraySave.dNumValues2[0], 0);
	SetDlgItemInt(hSetting, IDC_EDIT25, TraySave.dNumValues2[1], 0);
	SetDlgItemInt(hSetting, IDC_EDIT26, TraySave.dNumValues2[2], 0);
	SetDlgItemInt(hSetting, IDC_EDIT_TIME, TraySave.FlushTime, 0);
	SetDlgItemText(hSetting, IDC_EDIT14, TraySave.szTrafficOut);
	SetDlgItemText(hSetting, IDC_EDIT15, TraySave.szTrafficIn);
	SetDlgItemText(hSetting, IDC_EDIT16, TraySave.szTemperatureCPU);
	SetDlgItemText(hSetting, IDC_EDIT17, TraySave.szTemperatureGPU);
	SetDlgItemText(hSetting, IDC_EDIT18, TraySave.szTemperatureCPUUnit);
	SetDlgItemText(hSetting, IDC_EDIT19, TraySave.szTemperatureGPUUnit);
	SetDlgItemText(hSetting, IDC_EDIT20, TraySave.szUsageCPU);
	SetDlgItemText(hSetting, IDC_EDIT21, TraySave.szUsageMEM);
	SetDlgItemText(hSetting, IDC_EDIT22, TraySave.szUsageCPUUnit);
	SetDlgItemText(hSetting, IDC_EDIT23, TraySave.szUsageMEMUnit);
	SetDlgItemText(hSetting, IDC_EDIT27, TraySave.szDiskReadSec);
	SetDlgItemText(hSetting, IDC_EDIT28, TraySave.szDiskWriteSec);
	SetDlgItemText(hSetting, IDC_EDIT29, TraySave.szDiskName);
	bSettingInit = FALSE;
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_BACKGROUND), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_TRAFFIC_LOW), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_TRAFFIC_MEDIUM), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_TRAFFIC_HIGH), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_LOW), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_MEDUIM), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_HIGH), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
	ShowWindow(hSetting, SW_SHOW);
	UpdateWindow(hSetting);
	SetForegroundWindow(hSetting);
}
/*
void SetTaskScheduler(BOOL bAdd)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr))
	{
		//  Set general COM security levels.
		hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (SUCCEEDED(hr))
		{
			ITaskService* pService = NULL;
			hr = CoCreateInstance(CLSID_TaskScheduler,
				NULL,
				CLSCTX_INPROC_SERVER,
				IID_ITaskService,
				(void**)&pService);
			if (SUCCEEDED(hr))
			{
				hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
				if (SUCCEEDED(hr))
				{
					ITaskFolder* pRootFolder = NULL;
					hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
					if (SUCCEEDED(hr))
					{
						pRootFolder->DeleteTask(_bstr_t(szAppName), 0);
						if (bAdd)
						{
							ITaskDefinition* pTask = NULL;
							hr = pService->NewTask(0, &pTask);
							//						pService->Release();  // COM clean up.  Pointer is no longer used.
							if (SUCCEEDED(hr))
							{
								if (IsUserAdmin())
								{
									IPrincipal* pPrincipal;
									hr = pTask->get_Principal(&pPrincipal);
									if (SUCCEEDED(hr))
									{
										pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
									}
								}
								IRegistrationInfo* pRegInfo = NULL;
								hr = pTask->get_RegistrationInfo(&pRegInfo);
								if (SUCCEEDED(hr))
								{
									hr = pRegInfo->put_Author(_bstr_t(L"cgbsmy"));
									pRegInfo->Release();
									
									if (SUCCEEDED(hr))
									{
										ITaskSettings* pSettings = NULL;
										hr = pTask->get_Settings(&pSettings);
										if (SUCCEEDED(hr))
										{
											pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
											pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
											pSettings->put_AllowHardTerminate(VARIANT_FALSE);
											pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
											pSettings->put_WakeToRun(VARIANT_TRUE);
											hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
											pSettings->Release();
											if (SUCCEEDED(hr))
											{
												ITriggerCollection* pTriggerCollection = NULL;
												hr = pTask->get_Triggers(&pTriggerCollection);
												if (SUCCEEDED(hr))
												{
													ITrigger* pTrigger = NULL;
													hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
													pTriggerCollection->Release();
													if (SUCCEEDED(hr))
													{
														ILogonTrigger* pLogonTrigger = NULL;
														hr = pTrigger->QueryInterface(
															IID_ILogonTrigger, (void**)&pLogonTrigger);
														pTrigger->Release();
														if (SUCCEEDED(hr))
														{
															hr = pLogonTrigger->put_Id(_bstr_t(L"cgbsmy"));
															if (SUCCEEDED(hr))
															{
//																hr = pBootTrigger->put_StartBoundary(_bstr_t(L"2020-06-11T0:00:00"));
//																hr = pBootTrigger->put_EndBoundary(_bstr_t(L"2222-06-19T08:00:00"));
																// Delay the task to start 30 seconds after system start. 
//																hr = pBootTrigger->put_Delay(_bstr_t(L"PT1S"));
																if (!IsUserAdmin())
																{
																	WCHAR szName[MAX_PATH];
																	DWORD dwLen = MAX_PATH;
																	GetUserName(szName, &dwLen);
																	pLogonTrigger->put_UserId(_bstr_t(szName));
																}
																pLogonTrigger->Release();
																IActionCollection* pActionCollection = NULL;
																hr = pTask->get_Actions(&pActionCollection);
																if (SUCCEEDED(hr))
																{
																	
																	//  Create the action, specifying it as an executable action.
																	IAction* pAction = NULL;
																	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
																	pActionCollection->Release();
																	if (SUCCEEDED(hr))
																	{
																		IExecAction* pExecAction = NULL;
																		//  QI for the executable task pointer.																		
																		hr = pAction->QueryInterface(
																			IID_IExecAction, (void**)&pExecAction);
																		pAction->Release();
																		if (SUCCEEDED(hr))
																		{																																	
																			WCHAR szExe[MAX_PATH];
																			GetModuleFileName(NULL, szExe, MAX_PATH);
																			size_t sLen = wcslen(szExe);
																			hr = pExecAction->put_Path(_bstr_t(szExe));
																			pExecAction->put_Arguments(_bstr_t(L" t"));
																			pExecAction->Release();
																			if (SUCCEEDED(hr))
																			{
																				IRegisteredTask* pRegisteredTask = NULL;
																				VARIANT varID;
																				varID.vt = VT_NULL;
																				VARIANT varPassword;
																				varPassword.vt = VT_NULL;
//																				MessageBox(hSetting, szName, szName, MB_OK);
																				//hr = pRootFolder->RegisterTaskDefinition(_bstr_t(szAppName), pTask, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &pRegisteredTask);
																				//hr = pRootFolder->RegisterTaskDefinition(_bstr_t(szAppName),pTask,TASK_CREATE_OR_UPDATE, _variant_t(),_variant_t(),TASK_LOGON_NONE,_variant_t(L""),&pRegisteredTask);
																				if(IsUserAdmin())
																					hr = pRootFolder->RegisterTaskDefinition(_bstr_t(szAppName), pTask, TASK_CREATE_OR_UPDATE, _variant_t(L"Builtin\\Administrators"), _variant_t(), TASK_LOGON_GROUP, _variant_t(L""), &pRegisteredTask);
																				else
																					hr = pRootFolder->RegisterTaskDefinition(_bstr_t(szAppName), pTask, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &pRegisteredTask);																					
																				if (SUCCEEDED(hr))
																				{
																					IRunningTask* pRunningTask=NULL;
																					VARIANT param;
																					param.vt = VT_EMPTY;
																					hr = pRegisteredTask->Run(param, &pRunningTask);
//																					hr = pRegisteredTask->RunEx(param, TASK_RUN_IGNORE_CONSTRAINTS, NULL, NULL, &pRunningTask);
																					if (SUCCEEDED(hr))
																					{

																					}
																					pRegisteredTask->Release();
																				}
																				
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}

								}
								pTask->Release();
							}
						}
						pRootFolder->Release();
					}
				}
				pService->Release();
			}

		}
		CoUninitialize();
	}

}
	HRESULT hr = S_OK;
	ITaskScheduler* pITS;
	hr = CoInitialize(NULL);
	if (SUCCEEDED(hr))
	{
		hr = CoInitializeSecurity(
			NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			0,
			NULL
		);
		hr = CoCreateInstance(CLSID_CTaskScheduler,
			NULL,
			CLSCTX_INPROC_SERVER,
			IID_ITaskScheduler,
			(void**)&pITS);
		if (SUCCEEDED(hr))
		{
			ITask* pITask;
			IPersistFile* pIPersistFile;
			pITS->Delete(szAppName);
			hr = pITS->NewWorkItem(szAppName,         // Name of task
				CLSID_CTask,          // Class identifier
				IID_ITask,            // Interface identifier
				(IUnknown**)&pITask); // Address of task
			pITS->Release();                               // Release object
			if (hr == S_OK)
			{
				pITask->
				hr = pITask->QueryInterface(IID_IPersistFile,
					(void**)&pIPersistFile);
				pITask->Release();
				if (hr == S_OK)
				{
					hr = pIPersistFile->Save(NULL, TRUE);
					pIPersistFile->Release();
				}
			}
		}
		CoUninitialize();
	}

*/
#ifndef _DEBUG
extern "C" void WinMainCRTStartup() {
	pChangeWindowMessageFilter(WM_TRAYS, MSGFLT_ADD);
	pChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
	pChangeWindowMessageFilter(0x0049, MSGFLT_ADD);
	LPWSTR lpCmdLine = GetCommandLine();
	LPWSTR lpP=NULL;
	int iLen = lstrlen(lpCmdLine);
	int flag = 0;
	for (int i = 0; i < iLen; i++)
	{
		if (lpCmdLine[i] == L'\"')
		{
			++flag;
		}
		else if (flag == 2)
		{
			lpCmdLine = &lpCmdLine[i + 1];
			break;
		}
		else if (lpCmdLine[i] == L' ' && flag == 0)
		{
			lpCmdLine = &lpCmdLine[i + 1];
			if (lpCmdLine[0] == L'o')
			{
				for (int n = 1; n < iLen - i; n++)
				{
					if (lpCmdLine[n] == L' ')
					{
						lpCmdLine[n] = 0;
						lpP = &lpCmdLine[n + 1];
						break;
					}
				}
			}
			break;
		}
	}
	if (lpCmdLine[0] == L'c')////打开控制面板
	{
		CloseHandle(pShellExecute(NULL, L"open", L"control.exe", &lpCmdLine[1], NULL, SW_SHOW));
		ExitProcess(0);
	}
	else if (lpCmdLine[0] == L'o')//用SHELLEXECUTE打开
	{
		CloseHandle(pShellExecute(NULL, L"open", &lpCmdLine[1], lpP, NULL, SW_SHOW));
		ExitProcess(0);
	}
	else if (lpCmdLine[0] == L's')//打开任务计划
	{
		CloseHandle(pShellExecute(NULL, L"open", L"schtasks", &lpCmdLine[1], NULL, SW_HIDE));
		ExitProcess(0);
	}
	if (IsUserAdmin()==3)
	{
		//		lpServiceName = (LPWSTR)szAppName;
		InitService();
		SERVICE_TABLE_ENTRY st[] =
		{
			{ (LPWSTR)szAppName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
			{ NULL, NULL }
		};
		if (lstrcmpi(lpCmdLine, L"/install") == 0)
		{
			InstallService();
			ExitProcess(0);
		}
		else if (lstrcmpi(lpCmdLine, L"/uninstall") == 0)
		{
			UninstallService();
			ExitProcess(0);
		}
		else if (lstrcmpi(lpCmdLine, L"/start") == 0)
		{
			ServiceCtrlStart();
			ExitProcess(0);
		}
		else if (lstrcmpi(lpCmdLine, L"/stop") == 0)
		{
			ServiceCtrlStop();
			ExitProcess(0);
		}
		if (ServiceRunState() != SERVICE_RUNNING)
		{
			if (IsServiceInstalled())
			{
				if (ServiceRunState() == SERVICE_STOPPED)
					ServiceCtrlStart();
				StartServiceCtrlDispatcher(st);
				ExitProcess(0);
			}
		}
		ServiceCtrlStop();
	}
#else
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

/*
	if (lpCmdLine[0] == L'c')////打开控制面板
	{
		CloseHandle(pShellExecute(NULL, L"open", L"control.exe", &lpCmdLine[1], NULL, SW_SHOW));
		return 0;
	}
	else if (lpCmdLine[0] == L'o')//用SHELLEXECUTE打开
	{
		CloseHandle(pShellExecute(NULL, L"open", &lpCmdLine[1], NULL, NULL, SW_SHOW));
		return 0;
	}
	else if (lpCmdLine[0] == L's')//打开任务计划
	{
		CloseHandle(pShellExecute(NULL, L"open", L"schtasks", &lpCmdLine[1], NULL, SW_HIDE));
		return 0;
	}
	if (IsUserAdmin())
	{
		LPWSTR lpServiceName = (LPWSTR)szAppName;
		InitService();
		SERVICE_TABLE_ENTRY st[] =
		{
			{ (LPWSTR)szAppName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
			{ NULL, NULL }
		};
		if (lstrcmpi(lpCmdLine, L"/install") == 0)
		{
			InstallService();
			return 0;
		}
		else if (lstrcmpi(lpCmdLine, L"/uninstall") == 0)
		{
			UninstallService();
			return 0;
		}
		else if (lstrcmpi(lpCmdLine, L"/start") == 0)
		{
			ServiceCtrlStart();
			return 0;
		}
		else if (lstrcmpi(lpCmdLine, L"/stop") == 0)
		{
			ServiceCtrlStop();
			return 0;
		}
		if (ServiceRunState() != SERVICE_RUNNING)
		{
			if (IsServiceInstalled())
			{
				if (ServiceRunState() == SERVICE_STOPPED)
					ServiceCtrlStart();
				StartServiceCtrlDispatcher(st);
				return 0;
			}
		}
		ServiceCtrlStop();
	}
*/
#endif
	GetShellAllWnd();
	hInst = GetModuleHandle(NULL); // 将实例句柄存储在全局变量中
	typedef WINUSERAPI DWORD WINAPI RTLGETVERSION(PRTL_OSVERSIONINFOW  lpVersionInformation);
	rovi.dwOSVersionInfoSize = sizeof(rovi);
	RTLGETVERSION* RtlGetVersion = (RTLGETVERSION*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion)
		RtlGetVersion(&rovi);
	ReadReg();
	if(!TraySave.bMonitorTips||!TraySave.bMonitor||TraySave.bMonitorTransparent)
		EnumWindows((WNDENUMPROC)FindWindowFunc, 0);
	hMutex = CreateMutex(NULL, TRUE, L"_TrayS_");
	if (hMutex != NULL)
	{
		if (ERROR_ALREADY_EXISTS != GetLastError())
		{
			iMain = LoadIcon(hInst, MAKEINTRESOURCE(IDI_TRAYS));
			hDwmapi = LoadLibrary(L"dwmapi.dll");
			if (hDwmapi)
			{
				pDwmGetWindowAttribute = (pfnDwmGetWindowAttribute)GetProcAddress(hDwmapi, "DwmGetWindowAttribute");
			}
			SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
			if (TraySave.bMonitorTemperature)
				LoadTemperatureDLL();
			pProcessTime = NULL;
			EnableDebugPrivilege(TRUE);
			SYSTEM_INFO si;
			GetSystemInfo(&si);
			dNumProcessor = si.dwNumberOfProcessors;
			if (dNumProcessor == 0)
				dNumProcessor = 1;
			ppmu[0] = &pmu[0];
			ppmu[1] = &pmu[1];
			ppmu[2] = &pmu[2];
			ppmu[3] = &pmu[3];
			ppmu[4] = &pmu[4];
			ppcu[0] = &pcu[0];
			ppcu[1] = &pcu[1];
			ppcu[2] = &pcu[2];
			ppcu[3] = &pcu[3];
			ppcu[4] = &pcu[4];
			g_hHeapWindowInfo = HeapCreate(NULL, 0, 0);
			// 执行应用程序初始化:
			if (!InitInstance(hInst, 0))
			{
#ifndef _DEBUG
				ExitProcess(0);
#else
				return 0;
#endif
			}
			MSG msg;
			// 主消息循环:
			while (GetMessage(&msg, nullptr, 0, 0))
			{
				if (!IsDialogMessage(hMain, &msg) && !IsDialogMessage(hSetting, &msg))
				{
					TranslateMessage(&msg);
					DispatchMessage(&msg);
				}
			}
			if (IsWindow(hSetting))
				DestroyWindow(hSetting);
			CloseTaskBar();
			if (IsWindow(hMain))
				DestroyWindow(hMain);
			pShell_NotifyIcon(NIM_DELETE, &nid);
			DestroyIcon(iMain);
			DeleteObject(hFont);
			//free(ipinfo);
			FreeLibrary(hDwmapi);
			if (hIphlpapi)
				FreeLibrary(hIphlpapi);
			if (hOleacc)
				FreeLibrary(hOleacc);
			if (hPDH)
				FreeLibrary(hPDH);
			HeapFree(GetProcessHeap(), 0, mi);
			HeapFree(GetProcessHeap(), 0, piaa);
			HeapFree(GetProcessHeap(), 0, traffic);
			HeapDestroy(g_hHeapWindowInfo);
			if (hMutex)
				CloseHandle(hMutex);
			FreeTemperatureDLL();
			if (bResetRun)
				RunProcess(NULL, NULL);
		}
	}

	// 初始化全局字符串
//   LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
//   LoadStringW(hInstance, IDC_TRAYS, szWindowClass, MAX_LOADSTRING);			
	ExitProcess((UINT)0);
}
//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hMain = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)MainProc);
	if (!hMain)
	{
		return FALSE;
	}
	////////////////////////////////////////////////////////////当前DPI
	HDC hdc = GetDC(hMain);
	iDPI = GetDeviceCaps(hdc, LOGPIXELSY);
	::ReleaseDC(hMain, hdc);
//	EnableNonClientDpiScaling(hMain);
	APPBARDATA abd;
	abd.cbSize = sizeof(abd);
	abd.hWnd = hMain;
	abd.uCallbackMessage = MSG_APPBAR_MSGID;
	SHAppBarMessage(ABM_NEW, &abd);
	bThemeMode = GetSystemUsesLightTheme();
	//////////////////////////////////////////////////////////////////////////////////设置通知栏图标
	nid.cbSize = sizeof NOTIFYICONDATA;
	nid.uID = WM_IAWENTRAY;
	nid.hWnd = hMain;
	nid.hIcon = iMain;
	nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	nid.uCallbackMessage = WM_IAWENTRAY;
	//			nid.dwInfoFlags = NIIF_INFO;
	LoadString(hInst, IDS_TIPS, nid.szTip, 88);
	if (TraySave.bTrayIcon)
		pShell_NotifyIcon(NIM_ADD, &nid);
	MemoryStatusEx.dwLength = sizeof MEMORYSTATUSEX;
	GlobalMemoryStatusEx(&MemoryStatusEx);
	if (TraySave.bMonitor)
	{
		AdjustWindowPos();
	}
	//	if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
	SetTimer(hMain, 3, TraySave.FlushTime, NULL);
	SetTimer(hMain, 6, 1000, NULL);
	SetTimer(hMain, 11, 6000, NULL);
	SetTimer(hMain, 3000, 3000, NULL);
	//   ShowWindow(hMain,SW_SHOW);
	return TRUE;
}
BOOL Find(IAccessible* paccParent, int iRole, IAccessible** paccChild)//查找任务图标UI
{
	HRESULT hr;
	long numChildren;
	unsigned long numFetched;
	VARIANT varChild;
	int indexCount;
	IAccessible* pChild = NULL;
	IEnumVARIANT* pEnum = NULL;
	IDispatch* pDisp = NULL;
	BOOL found = false;
	//Get the IEnumVARIANT interface
	hr = paccParent->QueryInterface(IID_IEnumVARIANT, (PVOID*)&pEnum);
	if (pEnum)
		pEnum->Reset();
	// Get child count
	paccParent->get_accChildCount(&numChildren);
	for (indexCount = 1; indexCount <= numChildren && !found; indexCount++)
	{
		pChild = NULL;
		if (pEnum)
			hr = pEnum->Next(1, &varChild, &numFetched);
		else
		{
			varChild.vt = VT_I4;
			varChild.lVal = indexCount;
		}
		if (varChild.vt == VT_I4)
		{
			pDisp = NULL;
			hr = paccParent->get_accChild(varChild, &pDisp);
		}
		else
			pDisp = varChild.pdispVal;
		if (pDisp)
		{
			hr = pDisp->QueryInterface(IID_IAccessible, (void**)&pChild);
			hr = pDisp->Release();
		}
		if (pChild)
		{
			VariantInit(&varChild);
			varChild.vt = VT_I4;
			varChild.lVal = CHILDID_SELF;
			*paccChild = pChild;
		}
		VARIANT varState;
		pChild->get_accState(varChild, &varState);
		if ((varState.intVal & STATE_SYSTEM_INVISIBLE) == 0)
		{
			VARIANT varRole;
			pChild->get_accRole(varChild, &varRole);
			if (varRole.lVal == iRole)
			{
				paccParent->Release();
				found = true;
				break;
			}
		}
		if (!found && pChild)
		{
			//			found = Find(pCAcc, iRole, paccChild);
			//			if (*paccChild != pCAcc)
			pChild->Release();
		}
	}
	if (pEnum)
		pEnum->Release();
	return found;
}
int oleft=0, otop=0;
int iIconsWidth=0;
void SetTaskBarPos(HWND hTaskListWnd, HWND hTrayWnd, HWND hTaskWnd, HWND hReBarWnd, BOOL bMainTray)//设置任务栏图标位置
{
	if (hOleacc == NULL)
	{
		hOleacc = LoadLibrary(L"oleacc.dll");
		if (hOleacc)
		{
			AccessibleObjectFromWindowT = (pfnAccessibleObjectFromWindow)GetProcAddress(hOleacc, "AccessibleObjectFromWindow");
			AccessibleChildrenT = (pfnAccessibleChildren)GetProcAddress(hOleacc, "AccessibleChildren");
		}
	}
	if (hOleacc == NULL)
		return;
	IAccessible* pAcc = NULL;
	AccessibleObjectFromWindowT(hTaskListWnd, OBJID_WINDOW, IID_IAccessible, (void**)&pAcc);
	IAccessible* paccChlid = NULL;
	if (pAcc)
	{
		if (Find(pAcc, 22, &paccChlid) == FALSE)
		{
			return;
		}
	}
	else
		return;
	long childCount;
	long returnCount;
	LONG left, top, width, height;
	LONG ol = 0, ot = 0;
	int tWidth = 0;
	int tHeight = 0;
	if (paccChlid)
	{
		if (paccChlid->get_accChildCount(&childCount) == S_OK && childCount != 0)
		{
			VARIANT* pArray = (VARIANT*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof VARIANT * childCount);
			if (AccessibleChildrenT(paccChlid, 0L, childCount, pArray, &returnCount) == S_OK)
			{
				for (int x = 0; x < returnCount; x++)
				{
					VARIANT vtChild = pArray[x];
					{

						VARIANT varState;
						paccChlid->get_accState(vtChild, &varState);
						if ((varState.intVal & STATE_SYSTEM_INVISIBLE) == 0)
						{
							VARIANT varRole;
							paccChlid->get_accRole(vtChild, &varRole);
							if (varRole.intVal == 0x2b || varRole.intVal == 0x39)
							{
								paccChlid->accLocation(&left, &top, &width, &height, vtChild);
								if (ol != left)
								{
									tWidth += width;
									ol = left;
								}
								if (ot != top)
								{
									tHeight += height;
									ot = top;
								}
							}
						}
					}
				}
			}
			HeapFree(GetProcessHeap(), 0, pArray);
		}
		paccChlid->Release();
	}
	else
		return;
	iIconsWidth = tWidth;
	RECT lrc, src, trc;
	GetWindowRect(hTaskListWnd, &lrc);
	GetWindowRect(hTrayWnd, &src);
	GetWindowRect(hTaskWnd, &trc);
	BOOL Vertical = FALSE;
	if (src.right - src.left < src.bottom - src.top)
		Vertical = TRUE;
	SendMessage(hReBarWnd, WM_SETREDRAW, TRUE, 0);
	int lr, tb;
	if (Vertical)
	{
		int t = trc.left - src.left;
		int b = src.bottom - trc.bottom;
		if (bMainTray && TraySave.bMonitor && TraySave.bMonitorFloat == FALSE)
		{
			if (TraySave.bMonitorLeft == FALSE)
				b += mHeight;
			else
				t += mHeight;
		}
		if (t > b)
			tb = t;
		else
			tb = b;
	}
	else
	{
		int l = trc.left - src.left;
		int r = src.right - trc.right;
		if (TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE)
		{
			if (TraySave.bMonitorLeft == FALSE)
				r += mWidth;
			else
				l += mWidth;
		}
		if (l > r)
			lr = l;
		else
			lr = r;
	}
	int nleft, ntop;
	if ((TraySave.iPos == 2 || (Vertical == FALSE && tWidth >= trc.right - trc.left - lr) || (Vertical && tHeight >= trc.bottom - trc.top - tb)) && TraySave.iPos != 0)
	{
		if (Vertical)
		{
			ntop = trc.bottom - trc.top - tHeight;
			if (TraySave.bMonitorLeft == FALSE && TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE)
				ntop -= mHeight + 2;
		}
		else
		{
			nleft = trc.right - trc.left - tWidth;
			if (TraySave.bMonitorLeft == FALSE && TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE)
				nleft -= mWidth + 2;
		}
	}
	else if (TraySave.iPos == 0)
	{
		if (TraySave.bMonitorLeft && TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE)
		{
			nleft = mWidth;
			ntop = mHeight;
		}
		else
		{
			nleft = 0;
			ntop = 0;
			if (TraySave.bMonitor == FALSE)
			{
				SetTimer(hMain, 11, 1000, NULL);
			}
		}
	}
	else if (TraySave.iPos == 1)
	{
		if (Vertical)
			ntop = src.top + (src.bottom - src.top) / 2 - trc.top - tHeight / 2;
		else
			nleft = src.left + (src.right - src.left) / 2 - trc.left - tWidth / 2;
		if (bMainTray)
		{
			if (Vertical)
				ntop -= 2;
			else
				nleft -= 2;
		}
	}
	if (Vertical)
	{
		if (bMainTray)
		{
			if (otop == 0)
				lrc.top = ntop;
			else
				lrc.top = otop;
			otop = ntop;
			while (ntop != lrc.top)
			{
				if (ntop > lrc.top)
					++lrc.top;
				else
					--lrc.top;
				SetWindowPos(hTaskListWnd, 0, 0, lrc.top, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
			}
		}
		SetWindowPos(hTaskListWnd, 0, 0, ntop, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
	}
	else
	{
		if (bMainTray)
		{
			if (oleft == 0)
				lrc.left = nleft;
			else
				lrc.left = oleft;
			oleft = nleft;
			while (nleft != lrc.left)
			{
				if (nleft > lrc.left)
					++lrc.left;
				else
					--lrc.left;
				SetWindowPos(hTaskListWnd, 0, lrc.left, 0, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
			}
		}
		SetWindowPos(hTaskListWnd, 0, nleft, 0, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
	}
	if (TraySave.iPos != 0)
		SendMessage(hReBarWnd, WM_SETREDRAW, FALSE, 0);
	ShowWindow(hTaskWnd, SW_SHOWNOACTIVATE);
}
int otleft, ottop;
void SetWH()
{
	mWidth = 0;
	mHeight = 0;
	HDC mdc = GetDC(hMain);
	TraySave.TraybarFont.lfHeight = DPI(TraySave.TraybarFontSize);
	DeleteObject(hFont);
	hFont = CreateFontIndirect(&TraySave.TraybarFont); //创建字体
	HFONT oldFont = (HFONT)SelectObject(mdc, hFont);
	SIZE tSize;
	WCHAR sz[16]=L"8";
	::GetTextExtentPoint(mdc, sz, lstrlen(sz), &tSize);
	int space = tSize.cx/2;
	wHeight = tSize.cy + 1;
	if (TraySave.bMonitorTraffic)
	{
		if (TraySave.iMonitorSimple == 1)
		{
			WCHAR szT[] = L"M↓:8.88";
			::GetTextExtentPoint(mdc, szT, lstrlen(szT), &tSize);
		}
		else if (TraySave.iMonitorSimple == 2)
		{
			WCHAR szT[] = L"M8.88";
			::GetTextExtentPoint(mdc, szT, lstrlen(szT), &tSize);
		}
		else
		{
			wsprintf(sz, L"M%s8.88", TraySave.szTrafficOut);
			::GetTextExtentPoint(mdc, sz, lstrlen(sz), &tSize);
		}
		wTraffic = tSize.cx + space;
		mWidth += wTraffic;
		mHeight += tSize.cy * 2;		
	}
	else
		wTraffic = 0;
	if (TraySave.bMonitorUsage)
	{
		if (TraySave.iMonitorSimple == 1)
			::GetTextExtentPoint(mdc, L"88%", lstrlen(L"88%"), &tSize);
		else if (TraySave.iMonitorSimple == 2)
			::GetTextExtentPoint(mdc, L"88", lstrlen(L"88"), &tSize);
		else
		{
			wsprintf(sz, L"%s88%s", TraySave.szUsageMEM, TraySave.szUsageMEMUnit);
			::GetTextExtentPoint(mdc, sz, lstrlen(sz), &tSize);
		}
		wUsage = tSize.cx + space;
		mWidth += wUsage;
		mHeight += tSize.cy * 2;
	}
	else
		wUsage = 0;
	if (TraySave.bMonitorTemperature)
	{
		if (TraySave.iMonitorSimple == 1)
			::GetTextExtentPoint(mdc, L"88℃", lstrlen(L"88℃"), &tSize);
		else if (TraySave.iMonitorSimple == 2)
			::GetTextExtentPoint(mdc, L"88", lstrlen(L"88"), &tSize);
		else
		{
			wsprintf(sz, L"%s88%s", TraySave.szTemperatureGPU, TraySave.szTemperatureGPUUnit);
			::GetTextExtentPoint(mdc, sz, lstrlen(sz), &tSize);
		}
		wTemperature = tSize.cx + space;
		mWidth += wTemperature;
		if (bRing0)
			mHeight += tSize.cy * 2;
		else
			mHeight += tSize.cy;
	}
	else
		wTemperature = 0;
	if (TraySave.bMonitorDisk)
	{
		if (TraySave.iMonitorSimple == 1)
		{
			WCHAR szT[] = L" MR:8.88";
			::GetTextExtentPoint(mdc, szT, lstrlen(szT), &tSize);
		}
		else if (TraySave.iMonitorSimple == 2)
		{
			WCHAR szT[] = L" M8.88";
			::GetTextExtentPoint(mdc, szT, lstrlen(szT), &tSize);
		}
		else
		{
			wsprintf(sz, L" M%s8.88", TraySave.szDiskReadSec);
			::GetTextExtentPoint(mdc, sz, lstrlen(sz), &tSize);
		}
		wDisk = tSize.cx + space;
		mWidth += wDisk;
		mHeight += tSize.cy * 2;
	}
	else
		wDisk = 0;
	if (TraySave.bMonitorTime)
	{
		::GetTextExtentPoint(mdc, L"88:88:88", lstrlen(L"88:88:88"), &tSize);
		wTime = tSize.cx + space;
		mWidth += wTime;
		mHeight += tSize.cy * 2;
	}
	else
		wTime = 0;
	mWidth += 4;
	mHeight += 4;
	SelectObject(mdc, oldFont);
	ReleaseDC(hMain, mdc);
	ottop = -1;
	otleft = -1;
	AdjustWindowPos();
}
void AdjustWindowPos()//设置信息窗口位置大小
{	
	if (IsWindow(hTray) == FALSE)//任务栏奔溃时重启
	{
		DestroyWindow(hTime);
		DestroyWindow(hTaskBar);
		Sleep(6666);
		bFullScreen = FALSE;
		GetShellAllWnd();
		APPBARDATA abd;
		abd.cbSize = sizeof(abd);
		abd.hWnd = hMain;
		abd.uCallbackMessage = MSG_APPBAR_MSGID;
		SHAppBarMessage(ABM_NEW, &abd);
	}
	int dpi = pGetDpiForWindow(hTray);
	if (dpi != iDPI && dpi != 0)
	{
		bResetRun = TRUE;
		PostQuitMessage(0);
	}
/*
	if (TraySave.bMonitorTopmost&&!TraySave.bMonitorFloat)
	{
		RECT frc;
		HWND fwnd = GetForegroundWindow();
		GetWindowRect(fwnd, &frc);
		RECT ScreenRect;
		GetScreenRect(hTaskBar, &ScreenRect, FALSE);
//		if (GetWindowLongPtr(hTray, GWL_EXSTYLE) & WS_EX_TOPMOST)
		if(EqualRect(&frc,&ScreenRect)==FALSE)
		{
			if (bFullScreen)
			{
				DestroyWindow(hTaskBar);
				bFullScreen = FALSE;
			}
		}
		else
		{
			if (!bFullScreen)
			{
				DestroyWindow(hTaskBar);
				bFullScreen = TRUE;
			}
		}
	}
*/
	if (IsWindow(hTaskBar) == FALSE)
		OpenTaskBar();
	if (TraySave.bSecond && IsWindow(hTime) == FALSE)
		OpenTimeDlg();
	if (TraySave.bMonitorFloat)
	{
		RECT ScreenRect;
		GetScreenRect(hTaskBar, &ScreenRect, FALSE);
		if (TraySave.bMonitorFloatVRow)
		{
			if (wTime || wDisk)
			{
				if (wTime > wDisk)
					wTraffic = wTime;
				else
					wTraffic = wDisk;
			}
			if (TraySave.dMonitorPoint.x + wTraffic > ScreenRect.right)
				TraySave.dMonitorPoint.x = ScreenRect.right - wTraffic;
			if (TraySave.dMonitorPoint.y + mHeight + 8 > ScreenRect.bottom)
				TraySave.dMonitorPoint.y = ScreenRect.bottom - mHeight - 8;
			SetWindowPos(hTaskBar, HWND_TOPMOST, TraySave.dMonitorPoint.x, TraySave.dMonitorPoint.y, wTraffic, mHeight+8, SWP_NOACTIVATE);
			VTray = TRUE;
		}
		else
		{
			if (TraySave.dMonitorPoint.x + mWidth > ScreenRect.right)
				TraySave.dMonitorPoint.x = ScreenRect.right - mWidth;
			if (TraySave.dMonitorPoint.y + wHeight * 2 > ScreenRect.bottom)
				TraySave.dMonitorPoint.y = ScreenRect.bottom - wHeight * 2;
			SetWindowPos(hTaskBar, HWND_TOPMOST, TraySave.dMonitorPoint.x, TraySave.dMonitorPoint.y, mWidth, wHeight * 2, SWP_NOACTIVATE);
			VTray = FALSE;
		}		
	}
	else
	{
		/*
			RECT src,frc;
			if (!TraySave.bMonitorTopmost)
			{
				HWND fwnd = GetForegroundWindow();
				GetWindowRect(fwnd, &frc);
				GetScreenRect(GetForegroundWindow(), &src, FALSE);
				DWORD pid1, pid2;
				GetWindowThreadProcessId(hTray, &pid1);
				GetWindowThreadProcessId(fwnd, &pid2);
				if (EqualRect(&src, &frc) && pid1 != pid2)
				{
					ShowWindow(hTaskBar, SW_HIDE);
					return;
				}
			}
		*/
		RECT trayrc;
		GetWindowRect(hTray, &trayrc);
		if (trayrc.right - trayrc.left > trayrc.bottom - trayrc.top)
			VTray = FALSE;
		else
			VTray = TRUE;
		if (VTray == FALSE)
		{
			int nleft;
			if (hWin11UI)
			{
				RECT startrc, tasklistrc;
				GetWindowRect(hStartWnd, &startrc);
				GetWindowRect(hTaskListWnd, &tasklistrc);
				BOOL bLeft = TraySave.bMonitorLeft;
				if (startrc.left == trayrc.left)
					bLeft = FALSE;
				if (TraySave.bNear)
				{
					if (bLeft)
					{
						nleft = startrc.left - mWidth;
					}
					else
					{
						nleft = tasklistrc.right;
					}
				}
				else
				{
					if (!bLeft)
					{
						RECT tnrc;
						GetWindowRect(hTrayNotifyWnd, &tnrc);
						nleft = tnrc.left - mWidth;
					}
					else
					{
						nleft = trayrc.left;
					}
				}
			}
			else
			{
				if (TraySave.bNear)
				{
					RECT tasklistrc;
					GetWindowRect(hTaskListWnd, &tasklistrc);
					if (TraySave.bMonitorLeft)
						nleft = tasklistrc.left - mWidth;
					else
						nleft = tasklistrc.left + iIconsWidth + 2;
				}
				else
				{
					RECT taskrc;
					GetWindowRect(hTaskWnd, &taskrc);
					if (TraySave.bMonitorLeft)
						nleft = taskrc.left + 2;
					else
						nleft = taskrc.right - mWidth;
				}
			}
			int h = wHeight * 2;
			int ntop;
			if (trayrc.bottom - trayrc.top < h)
			{
				h = trayrc.bottom - trayrc.top - 2;
				ntop = trayrc.top;
			}
			else
				ntop = (trayrc.bottom - trayrc.top - h) / 2 + trayrc.top;
			//		if (!hWin11UI)
			if(!bFullScreen)
				ntop -= trayrc.top;
/*
			if (hWin11UI)
				ntop += 1;
*/
			if (nleft != otleft || ottop != ntop)
			{
				/*
							HDC hdc = GetDC(hTaskBar);
							RECT crc;
							GetClientRect(hTaskBar, &crc);
							HBRUSH hb = CreateSolidBrush(RGB(0, 0, 0));
							FillRect(hdc, &crc, hb);
							DeleteObject(hb);
							ReleaseDC(hTaskBar, hdc);
				*/
				otleft = nleft;
				ottop = ntop;
				//			::InvalidateRect(hTaskBar, NULL, TRUE);
				//			if (!hWin11UI)
				if(bFullScreen)
					SetWindowPos(hTaskBar, HWND_TOPMOST, nleft, ntop, mWidth, h, SWP_NOACTIVATE | SWP_NOREDRAW | SWP_SHOWWINDOW);
				else
					MoveWindow(hTaskBar, nleft, ntop, mWidth, h, TRUE);
				
				//			else
				//				SetWindowPos(hTaskBar, HWND_TOPMOST, nleft, ntop, mWidth, h, SWP_NOACTIVATE | SWP_NOREDRAW | SWP_SHOWWINDOW);
			}
			//		else if(hWin11UI)
			//			SetWindowPos(hTaskBar, HWND_TOPMOST, nleft, ntop, mWidth, h, SWP_NOACTIVATE|SWP_NOREDRAW|SWP_NOSIZE|SWP_NOMOVE|SWP_SHOWWINDOW);
			if(bFullScreen)
				SetWindowPos(hTaskBar, HWND_TOPMOST, nleft, ntop, mWidth, h, SWP_NOACTIVATE | SWP_NOREDRAW | SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
		}
		else
		{
			int ntop;
			RECT taskrc;
			GetWindowRect(hTaskWnd, &taskrc);
			if (TraySave.bMonitorLeft)
				ntop = taskrc.top+2;
			else
				ntop = taskrc.bottom - mHeight;
			int nleft = 1;
			int w = trayrc.right - trayrc.left - 2;
			if (bFullScreen)
				nleft = trayrc.left + 1;
			if (ntop != ottop || otleft != w)
			{
				/*
							HDC hdc = GetDC(hTaskBar);
							RECT crc;
							GetClientRect(hTaskBar, &crc);
							HBRUSH hb = CreateSolidBrush(RGB(0, 0, 0));
							FillRect(hdc, &crc, hb);
							DeleteObject(hb);
							ReleaseDC(hTaskBar, hdc);
				*/
				ottop = ntop;
				otleft = w;
				if (bFullScreen)
					SetWindowPos(hTaskBar, HWND_TOPMOST, nleft, ntop, w, mHeight, SWP_NOACTIVATE | SWP_NOREDRAW | SWP_SHOWWINDOW);
				else
					MoveWindow(hTaskBar, nleft, ntop, w, mHeight, TRUE);
			}
		}
	}
	if (TraySave.bSecond)
	{
		if (!hWin11UI)
		{
			if (GetAncestor(hTime, GA_PARENT) != hTrayClockWnd)
			{
				Sleep(1000);
				DestroyWindow(hTime);
//				SetParent(hTime, hTrayClockWnd);
			}
			else
			{
				if (VTray)
				{
					ShowWindow(hTime, SW_HIDE);
				}
				else
				{
					RECT rc;
					GetWindowRect(hTrayClockWnd, &rc);
					SetWindowPos(hTime, 0, 0, 0, rc.right - rc.left, (rc.bottom - rc.top) / 2, SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOREDRAW);
				}
			}
		}
		else
		{
			if (GetAncestor(hTime, GA_PARENT) != hTray)
			{
				Sleep(1000);
				DestroyWindow(hTime);
//				SetParent(hTime, hTray);
			}
			else
			{
				RECT rc;
				GetWindowRect(hTray, &rc);
				SetWindowPos(hTime, NULL, rc.right - rc.left - ((rc.bottom - rc.top) * 153/100), 1, rc.bottom - rc.top, (rc.bottom - rc.top-2) / 2, SWP_NOACTIVATE | SWP_NOREDRAW);
			}
		}
	}
}

DWORD dwIPSize = 0;
DWORD dwMISize = 0;
INT_PTR CALLBACK TaskTipsProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)//提示信息窗口过程
{
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;
	case WM_MOUSEMOVE:
	{
		POINT pt;
		pt.x = GET_X_LPARAM(lParam);
		pt.y = GET_Y_LPARAM(lParam);
		RECT rc;
		GetClientRect(hDlg, &rc);
		rc.top = nTraffic * wTipsHeight;
		rc.bottom = (nTraffic + 10) * wTipsHeight;
		rc.left = rc.right * 100 / 160;
		rc.right = rc.right * 100 / 148;
		if (PtInRect(&rc, pt))
		{
			inTipsProcessX = TRUE;
			::InvalidateRect(hDlg, NULL, TRUE);
		}
		else
		{
			inTipsProcessX = FALSE;
		}
	}
	break;
	case WM_LBUTTONDOWN:
	{
		POINT pt;
		pt.x = GET_X_LPARAM(lParam);
		pt.y = GET_Y_LPARAM(lParam);
		if (pt.y == 0)
			pt.y = 1;
		if (pt.y < nTraffic * wTipsHeight)
			RunProcess(NULL, szNetCpl);
		else if (pt.y < (nTraffic + 10) * wTipsHeight)
		{
			RECT rc;
			GetClientRect(hDlg, &rc);
			rc.left = rc.right * 100 / 160;
			rc.right = rc.right * 100 / 148;
			if (PtInRect(&rc, pt))
			{

				int x = 0;
				if (wTipsHeight != 0)
					x = (pt.y / wTipsHeight) - nTraffic;
				DWORD pid;
				if (x < 5)
					pid = ppcu[x]->dwProcessID;
				else
					pid = ppmu[x - 5]->dwProcessID;
				HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
				if (hProc)
				{
					TerminateProcess(hProc, 0);
					CloseHandle(hProc);
					inTipsProcessX = FALSE;
					GetCursorPos(&pt);
					SetCursorPos(pt.x + 88, pt.y);
				}
			}
			else
			{
				if((pt.y / wTipsHeight) - nTraffic<5)
					RunProcess(NULL, szTaskmgr);
				else
					RunProcess(NULL, szPerfmon);
			}
		}
		else
		{
			RECT rc;
			GetClientRect(hDlg, &rc);
			if (pt.x < rc.right * 8 / 100)
			{
				bSetting = TRUE;
				SendMessage(hMain, WM_TRAYS, 0, 0);				
			}
			else if (pt.x > rc.right * 92 / 100)
				SendMessage(hMain, WM_CLOSE, 0, 0);
			else
			{
				if (pt.y < (nTraffic + 11) * wTipsHeight)
				{
					WCHAR wDrive[MAX_PATH];
					DWORD dwLen = GetLogicalDriveStrings(MAX_PATH, wDrive);
					if (dwLen != 0)
					{
						DWORD driver_number = dwLen / 4;
						DWORD x = pt.x / ((rc.right - rc.right * 8 / 100) / driver_number);
						if (x < driver_number)
						{
							WCHAR sz[24];
							memset(sz, 0, 48);
							wsprintf(sz, L"o%s", &wDrive[x * 4]);
							RunProcess(NULL, sz);
						}
					}
				}
				else
				{
					if(pt.x<rc.right/2)
						RunProcess(NULL, szCompmgmt);
					else
						RunProcess(NULL, szPowerCpl);
				}
			}
		}
		return TRUE;
	}
	break;
	case WM_MOUSELEAVE:
	{
		POINT pt;
		GetCursorPos(&pt);
		if (WindowFromPoint(pt) != hTaskBar)
		{
			if (pProcessTime != NULL)
			{
				HeapFree(GetProcessHeap(), 0, pProcessTime);
				pProcessTime = NULL;
			}
			DestroyWindow(hTaskTips);
			SetTimer(hMain, 11, 1000, NULL);
		}
	}
	break;
	case WM_ERASEBKGND:
		HDC hdc = (HDC)wParam;//BeginPaint(hDlg, &ps);
		RECT rc, crc;
		GetClientRect(hDlg, &rc);
		crc = rc;
		HDC mdc = CreateCompatibleDC(hdc);
		HBITMAP hMemBmp = CreateCompatibleBitmap(hdc, rc.right - rc.left, rc.bottom - rc.top);
		HBITMAP oldBmp = (HBITMAP)SelectObject(mdc, hMemBmp);
		//		if (bErasebkgnd)
		{
			TraySave.TipsFont.lfHeight = TraySave.TipsFontSize;
			HFONT hTipsFont = CreateFontIndirect(&TraySave.TipsFont); //创建字体
			HFONT oldFont = (HFONT)SelectObject(mdc, hTipsFont);
			WCHAR sz[64];
			SetBkMode(mdc, TRANSPARENT);
			COLORREF rgb;
			rgb = RGB(192, 192, 192);
			SetTextColor(mdc, rgb);
			rc.bottom = wTipsHeight;
			HBRUSH hb = CreateSolidBrush(RGB(24, 24, 24));
			for (int i = 0; i < nTraffic / 2 + 6; i++)
			{
				FillRect(mdc, &rc, hb);
				OffsetRect(&rc, 0, wTipsHeight * 2);
			}
			DeleteObject(hb);
			HPEN hp = CreatePen(PS_DOT, 1, RGB(98, 98, 98));
			HPEN oldpen = (HPEN)SelectObject(mdc, hp);
			MoveToEx(mdc, crc.right * 10 / 23, 0, NULL);
			LineTo(mdc, crc.right * 10 / 23, wTipsHeight * nTraffic);
			MoveToEx(mdc, crc.right * 7 / 10, 0, NULL);
			LineTo(mdc, crc.right * 7 / 10, wTipsHeight * nTraffic);
			MoveToEx(mdc, crc.right * 85 / 100, 0, NULL);
			LineTo(mdc, crc.right * 85 / 100, wTipsHeight * nTraffic);

			MoveToEx(mdc, crc.right * 100 / 124, wTipsHeight * nTraffic, NULL);
			LineTo(mdc, crc.right * 100 / 124, wTipsHeight * (nTraffic + 10));
			MoveToEx(mdc, crc.right * 100 / 148, wTipsHeight * nTraffic, NULL);
			LineTo(mdc, crc.right * 100 / 148, wTipsHeight * (nTraffic + 10));
			MoveToEx(mdc, crc.right * 100 / 160, wTipsHeight * nTraffic, NULL);
			LineTo(mdc, crc.right * 100 / 160, wTipsHeight * (nTraffic + 10));

			MoveToEx(mdc, 0, wTipsHeight * nTraffic, NULL);
			LineTo(mdc, crc.right, wTipsHeight * nTraffic);
			MoveToEx(mdc, 0, wTipsHeight * (nTraffic + 5), NULL);
			LineTo(mdc, crc.right, wTipsHeight * (nTraffic + 5));
			MoveToEx(mdc, 0, wTipsHeight * (nTraffic + 10), NULL);
			LineTo(mdc, crc.right, wTipsHeight * (nTraffic + 10));
			MoveToEx(mdc, crc.right * 8 / 100, wTipsHeight * (nTraffic + 10), NULL);
			LineTo(mdc, crc.right * 8 / 100, wTipsHeight * (nTraffic + 10 + 2));
			MoveToEx(mdc, crc.right * 92 / 100, wTipsHeight * (nTraffic + 10), NULL);
			LineTo(mdc, crc.right * 92 / 100, wTipsHeight * (nTraffic + 10 + 2));

/*
			DeleteObject(hp);
			rc.bottom = wTipsHeight*nTraffic;
			rc.top = 1;
			rc.left = 5;
			rc.right = crc.right-5;
			DWORD max = 0;
			for (int in=0;in<rNum;in++)
			{
				if (max < s_in_bytes[in])
					max = s_in_bytes[in];
			}
			for (int out = 0; out < rNum; out++)
			{
				if (max < s_out_bytes[out])
					max = s_out_bytes[out];
			}
			if (max == 0)
				max = 100;
			hp = CreatePen(PS_DOT, 1, RGB(128, 255, 0));
			oldpen = (HPEN)SelectObject(mdc, hp);
			MoveToEx(mdc, rc.left, rc.bottom, NULL);
			for (int e=1;e<= rNum;e++)
			{
				int x = iBytes + e-1;
				if (x >= rNum)
					x -= rNum;
				LineTo(mdc, rc.left + (rc.right - rc.left) * e / rNum, rc.bottom - double((rc.bottom - rc.top) * s_out_bytes[x] / max ));
			}
			SelectObject(mdc, oldpen);
			DeleteObject(hp);

			hp = CreatePen(PS_SOLID, 1, RGB(255, 128, 0));
			oldpen = (HPEN)SelectObject(mdc, hp);
			MoveToEx(mdc, rc.left, rc.bottom, NULL);
			for (int e = 1; e <= rNum; e++)
			{
				int x = iBytes + e - 1;
				if (x >= rNum)
					x -= rNum;
				LineTo(mdc, rc.left + (rc.right - rc.left) *e / rNum, rc.bottom - double((rc.bottom - rc.top) * s_in_bytes[x] / max ));
			}
*/

			SelectObject(mdc, oldpen);
			DeleteObject(hp);
			rc.top = 0;
/*
			int cx;
			if (wTipsHeight < 24)
				cx = 16;
			else if (wTipsHeight < 32)
				cx = 24;
			else if (wTipsHeight < 48)
				cx = 32;
			else if (wTipsHeight < 64)
				cx = 48;
			else if (wTipsHeight < 128)
				cx = 64;
			else
				cx = 128;
*/
			//			OffsetRect(&rc, 0, DPI(16)*3);
						//PIP_ADAPTER_INFO pai = &ipinfo[0];
			//			PIP_ADAPTER_ADDRESSES paa = &piaa[0];
			rc.bottom = wTipsHeight;
			for (int i = 0; i < nTraffic; i++)
			{
				rc.left = 5;// +wTipsHeight;
				DrawText(mdc, traffic[i].FriendlyName, lstrlen(traffic[i].FriendlyName), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
				/*
								HICON hIcon = GetIconForCSIDL(CSIDL_CONNECTIONS);

								UINT size = MAKELPARAM(cx, cx);
								WCHAR szGuid[64];// = L":::";
								MultiByteToWideChar(CP_ACP, 0, traffic[i].AdapterName, 64, szGuid , 64);
								SHFILEINFO shfi;
								SHGetFileInfo(szGuid, 0, &shfi, sizeof(shfi), SHGFI_ICON | SHGFI_USEFILEATTRIBUTES);
								hIcon = shfi.hIcon;

								if (wTipsHeight >= 16)
									DrawIconEx(mdc, 2, rc.top + (rc.bottom - rc.top - cx) / 2, hIcon, cx, cx, 0, NULL, DI_NORMAL);
								else
									DrawIconEx(mdc, 1, rc.top + 1, hIcon, wTipsHeight - 2, wTipsHeight - 2, 0, NULL, DI_NORMAL);
								DestroyIcon(hIcon);
				*/
				rc.left = crc.right * 10 / 23;
				rc.right = crc.right * 7 / 10;
				DrawText(mdc, traffic[i].IP4, lstrlen(traffic[i].IP4), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				int f_in_byte = traffic[i].in_byte;
				if (traffic[i].in_byte < 1000)
					wsprintf(sz, L"↓:%db", traffic[i].in_byte);
				else if (traffic[i].in_byte < 1000000)
				{
					int k_in_byte = f_in_byte / 1000;
					if (k_in_byte >= 100)
						wsprintf(sz, L"↓:%dk", k_in_byte);
					else if (k_in_byte >= 10)
						wsprintf(sz, L"↓:%d.%dk", k_in_byte, f_in_byte / 100 - k_in_byte * 10);
					else
						wsprintf(sz, L"↓:%d.%dk", k_in_byte, f_in_byte / 10 - k_in_byte * 100);
				}
				else if (traffic[i].in_byte < 1000000000)
				{
					int m_in_byte = f_in_byte / 1000000;
					if (m_in_byte >= 100)
						wsprintf(sz, L"↓:%dm", m_in_byte);
					else if (m_in_byte >= 10)
						wsprintf(sz, L"↓:%d.%dm", m_in_byte, f_in_byte / 100000 - m_in_byte * 10);
					else
						wsprintf(sz, L"↓:%d.%dm", m_in_byte, f_in_byte / 10000 - m_in_byte * 100);
				}
				else
				{
					int g_in_byte = f_in_byte / 1000000000;
					if (g_in_byte >= 100)
						wsprintf(sz, L"↓:%dG", g_in_byte);
					else if (g_in_byte >= 10)
						wsprintf(sz, L"↓:%d.%dG", g_in_byte, f_in_byte / 100000000 - g_in_byte * 10);
					else
						wsprintf(sz, L"↓:%d.%dG", g_in_byte, f_in_byte / 10000000 - g_in_byte * 100);
				}
				rc.left = crc.right * 7 / 10 + 2;
				rc.right += crc.right;
				DrawText(mdc, sz, lstrlen(sz), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
				int f_out_byte = traffic[i].out_byte;
				if (traffic[i].out_byte < 1000)
					wsprintf(sz, L"↑:%db", traffic[i].out_byte);
				else if (traffic[i].out_byte < 1000000)
				{
					int k_out_byte = f_out_byte / 1000;
					if (k_out_byte >= 100)
						wsprintf(sz, L"↑:%dk", k_out_byte);
					else if (k_out_byte >= 10)
						wsprintf(sz, L"↑:%d.%dk", k_out_byte, f_out_byte / 100 - k_out_byte * 10);
					else
						wsprintf(sz, L"↑:%d.%dk", k_out_byte, f_out_byte / 10 - k_out_byte * 100);
				}
				else if (traffic[i].out_byte < 1000000000)
				{
					int m_out_byte = f_out_byte / 1000000;
					if (m_out_byte >= 100)
						wsprintf(sz, L"↑:%dm", m_out_byte);
					else if (m_out_byte >= 10)
						wsprintf(sz, L"↑:%d.%dm", m_out_byte, f_out_byte / 100000 - m_out_byte * 10);
					else
						wsprintf(sz, L"↑:%d.%dm", m_out_byte, f_out_byte / 10000 - m_out_byte * 100);
				}
				else
				{
					int g_out_byte = f_out_byte / 1000000000;
					if (g_out_byte >= 100)
						wsprintf(sz, L"↑:%dg", g_out_byte);
					else if (g_out_byte >= 10)
						wsprintf(sz, L"↑:%d.%dg", g_out_byte, f_out_byte / 100000000 - g_out_byte * 10);
					else
						wsprintf(sz, L"↑:%d.%dg", g_out_byte, f_out_byte / 10000000 - g_out_byte * 100);
				}
				rc.left = crc.right * 85 / 100 + 2;
				DrawText(mdc, sz, lstrlen(sz), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
				OffsetRect(&rc, 0, wTipsHeight);
			}
			rc.left = 5;// +wTipsHeight;
			rc.right = crc.right - 5;
			POINT pt;
			GetCursorPos(&pt);
			ScreenToClient(hDlg, &pt);
			for (int i = 0; i < 5; i++)
			{
				SetTextColor(mdc, RGB(192, 192, 0));
				DrawText(mdc, ppcu[i]->szExe, lstrlen(ppcu[i]->szExe), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
				/*
								HICON hIcon = OpenProcessIcon(ppcu[i]->dwProcessID,cx);
								if(wTipsHeight>=16)
									DrawIconEx(mdc, 2, rc.top + (rc.bottom - rc.top - cx) / 2, hIcon, cx, cx, 0, NULL, DI_NORMAL);
								else
									DrawIconEx(mdc, 1, rc.top+1, hIcon, wTipsHeight-2, wTipsHeight-2, 0, NULL, DI_NORMAL);
								DestroyIcon(hIcon);
				*/
				int iCpuUsage = int(ppcu[i]->fCpuUsage * 100);
				wsprintf(sz, L"%d.%.2d%%", iCpuUsage / 100, iCpuUsage % 100);
				DrawText(mdc, sz, lstrlen(sz), &rc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
				RECT cr = rc;
				cr.left = crc.right * 100 / 148;
				cr.right = crc.right * 8 / 10;
				wsprintf(sz, L"%d", ppcu[i]->dwProcessID);
				DrawText(mdc, sz, lstrlen(sz), &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				cr.left = crc.right * 100 / 160;
				cr.right = crc.right * 100 / 148;
				if (PtInRect(&cr, pt))
					SetTextColor(mdc, RGB(255, 255, 255));
				DrawText(mdc, L"X", 1, &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				OffsetRect(&rc, 0, wTipsHeight);
			}
			for (int i = 0; i < 5; i++)
			{
				SetTextColor(mdc, RGB(0, 192, 192));
				DrawText(mdc, ppmu[i]->szExe, lstrlen(ppmu[i]->szExe), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
				/*
								HICON hIcon = OpenProcessIcon(ppmu[i]->dwProcessID,cx);
								if(wTipsHeight>=16)
									DrawIconEx(mdc, 2, rc.top+(rc.bottom-rc.top-cx)/2, hIcon, cx, cx, 0, NULL, DI_NORMAL);
								else
									DrawIconEx(mdc, 1, rc.top+1, hIcon, wTipsHeight-2, wTipsHeight-2, 0, NULL, DI_NORMAL);
								DestroyIcon(hIcon);
				*/
				if (ppmu[i]->dwMemUsage >= 1048576000)
				{
					SIZE_T iMemUsage = (ppmu[i]->dwMemUsage * 100 / 1073741824);
					wsprintf(sz, L"%d.%.2dGB", iMemUsage / 100, iMemUsage % 100);
				}
				else
				{
					SIZE_T iMemUsage = (ppmu[i]->dwMemUsage * 100 / 1048576);
					wsprintf(sz, L"%d.%.2dMB", iMemUsage / 100, iMemUsage % 100);
				}
				DrawText(mdc, sz, lstrlen(sz), &rc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
				RECT cr = rc;
				cr.left = crc.right * 100 / 148;
				cr.right = crc.right * 8 / 10;
				wsprintf(sz, L"%d", ppmu[i]->dwProcessID);
				DrawText(mdc, sz, lstrlen(sz), &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				cr.left = crc.right * 100 / 160;
				cr.right = crc.right * 100 / 148;
				if (PtInRect(&cr, pt))
					SetTextColor(mdc, RGB(255, 255, 255));
				DrawText(mdc, L"X", 1, &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				OffsetRect(&rc, 0, wTipsHeight);
			}

			HBRUSH hb1, hb2, hb3, hb4;
			hb1 = CreateSolidBrush(RGB(168, 168, 168));
			hb2 = CreateSolidBrush(RGB(128, 0, 0));
			hb3 = CreateSolidBrush(RGB(0, 128, 198));
			hb4 = CreateSolidBrush(RGB(0, 148, 0));
			SetTextColor(mdc, RGB(255, 255, 255));
			/*
						HBRUSH hb;
						hb=CreateSolidBrush(RGB(0,38,0));
						FillRect(mdc, &rc, hb);
						DeleteObject(hb);
			*/
			WCHAR wDrive[MAX_PATH];
			DWORD dwLen = GetLogicalDriveStrings(MAX_PATH, wDrive);
			if (dwLen != 0)
			{
				DWORD driver_number = dwLen / 4;
				rc.left = crc.right * 8 / 100 + 3;
				int dw = crc.right * 84 / 100 / driver_number - 2;
				rc.right = rc.left + dw;
				rc.top += 3;
				rc.bottom -= 1;
				for (DWORD nIndex = 0; nIndex < driver_number; nIndex++)
				{
					LPWSTR dName = wDrive + nIndex * 4;
					UINT64 lpFreeBytesAvailable = 0;
					UINT64 lpTotalNumberOfBytes = 0;
					UINT64 lpTotalNumberOfFreeBytes = 0;
					if (GetDriveType(dName) != DRIVE_CDROM&&dName[0]!=L'A')
					{
						if (GetDiskFreeSpaceEx(dName, (PULARGE_INTEGER)&lpFreeBytesAvailable, (PULARGE_INTEGER)&lpTotalNumberOfBytes, (PULARGE_INTEGER)&lpTotalNumberOfFreeBytes))
						{
							RECT frc = rc;
							if (nIndex + 1 == driver_number)
								rc.right = crc.right * 92 / 100 - 2;
							frc.right = frc.left + (rc.right - rc.left) * (lpTotalNumberOfBytes - lpTotalNumberOfFreeBytes) / lpTotalNumberOfBytes;
							FillRect(mdc, &rc, hb1);
							if (lpTotalNumberOfFreeBytes < lpTotalNumberOfBytes * 1 / 10)
								FillRect(mdc, &frc, hb2);
							else
								FillRect(mdc, &frc, hb3);
						}
						dName[2] = 0;
					}
					DrawText(mdc, dName, lstrlen(dName), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
					OffsetRect(&rc, dw + 2, 0);
					if (rc.right - 3 > crc.right * 92 / 100)
						break;
				}
			}
			rc.top -= 2;
			rc.bottom -= 2;
			OffsetRect(&rc, 0, wTipsHeight);
			rc.left = crc.right * 50 / 100 + 1;
			rc.right = crc.right * 92 / 100 - 2;
			FillRect(mdc, &rc, hb1);

			rc.left = crc.right * 8 / 100 + 3;
			rc.right = crc.right * 50 / 100 - 1;
			FillRect(mdc, &rc, hb1);
			/*
						PROCESSOR_POWER_INFORMATION* pi = (PROCESSOR_POWER_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof PROCESSOR_POWER_INFORMATION*dNumProcessor);
						if (pCallNtPowerInformation(ProcessorInformation, NULL, 0, &pi[0], sizeof PROCESSOR_POWER_INFORMATION * dNumProcessor) == 0)
						{
							int iCGhz = pi[0].CurrentMhz / 10;
							int iMGhz = pi[0].MaxMhz / 10;
							wsprintf(sz,  L"%d个逻辑处理器 当前频率%d.%.2dGHz 最大频率%d.%.2dGHz", dNumProcessor, iCGhz/100,iCGhz%100, iMGhz / 100, iMGhz % 100);
						}
						HeapFree(GetProcessHeap(), 0,pi);
						DrawText(mdc, sz, lstrlen(sz), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			*/

			DWORDLONG iaPage = MemoryStatusEx.ullAvailPageFile * 100 / 1073741824;
			DWORDLONG itPage = MemoryStatusEx.ullTotalPageFile * 100 / 1073741824;
			DWORDLONG ia = MemoryStatusEx.ullAvailPhys * 100 / 1073741824;
			DWORDLONG it = MemoryStatusEx.ullTotalPhys * 100 / 1073741824;

			RECT frc = rc;
			frc.right = frc.left + (rc.right - rc.left) * (itPage - iaPage) / itPage;
			if (iaPage < itPage * 2 / 10)
				FillRect(mdc, &frc, hb2);
			else
				FillRect(mdc, &frc, hb4);
			wsprintf(sz, L"虚拟内存:%d.%.2d/%d.%.2dGB", iaPage / 100, iaPage % 100, itPage / 100, itPage % 100);
			DrawText(mdc, sz, lstrlen(sz), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
			rc.left = crc.right * 50 / 100 + 1;
			rc.right = crc.right * 92 / 100 - 2;
			frc = rc;
			frc.right = frc.left + (rc.right - rc.left) * (it - ia) / it;
			if (ia < it * 2 / 10)
				FillRect(mdc, &frc, hb2);
			else
				FillRect(mdc, &frc, hb4);
			DeleteObject(hb1);
			DeleteObject(hb2);
			DeleteObject(hb3);
			DeleteObject(hb4);
			wsprintf(sz, L"物理内存:%d.%.2d/%d.%.2dGB", ia / 100, ia % 100, it / 100, it % 100);
			DrawText(mdc, sz, lstrlen(sz), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

			WCHAR set[] = L"设置";
			WCHAR sexit[] = L"退出";
			rc.top -= wTipsHeight;
			rc.right = crc.right * 8 / 100;
			rc.left = 0;
			DrawText(mdc, set, lstrlen(set), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			rc.right = crc.right;
			rc.left = crc.right * 92 / 100;
			DrawText(mdc, sexit, lstrlen(sexit), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			DeleteObject(hTipsFont);
			SelectObject(mdc, oldFont);
		}
		GetClientRect(hDlg, &rc);
		BitBlt(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mdc, 0, 0, SRCCOPY);
		SelectObject(mdc, oldBmp);
		DeleteObject(hMemBmp);
		DeleteDC(mdc);
		return TRUE;
		break;
	}
	return (INT_PTR)FALSE;
}
void GetProcessCpuUsage()//获取进程CPU占用前五
{
	if (!inTipsProcessX)
	{
		ppcu[0] = &pcu[0];
		ppcu[1] = &pcu[1];
		ppcu[2] = &pcu[2];
		ppcu[3] = &pcu[3];
		ppcu[4] = &pcu[4];
		memset(pcu, 0, sizeof pcu);
		pcu[0].fCpuUsage = 0;
		pcu[1].fCpuUsage = 0;
		pcu[2].fCpuUsage = 0;
		pcu[3].fCpuUsage = 0;
		pcu[4].fCpuUsage = 0;
	}
	DWORD dCurID = GetCurrentProcessId();
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hs != INVALID_HANDLE_VALUE)
	{
		BOOL ret = Process32First(hs, &pe);
		while (ret)
		{
			if (pe.th32ProcessID != dCurID)
			{
				HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
				if (hProc)
				{
					int n = -1;
					for (int i = 0; i < nProcess + 31; i++)
					{
						if (pProcessTime[i].dwProcessID == pe.th32ProcessID)
						{
							n = i;
							break;
						}
						else if (n == -1 && pProcessTime[i].dwProcessID == NULL)
							n = i;
					}
					FILETIME CreateTime, ExitTime, KernelTime, UserTime;
					if (GetProcessTimes(hProc, &CreateTime, &ExitTime, &KernelTime, &UserTime))
					{
						float nProcCpuPercent = 0;
						BOOL bRetCode = FALSE;
						FILETIME CreateTime, ExitTime, KernelTime, UserTime;
						LARGE_INTEGER lgKernelTime;
						LARGE_INTEGER lgUserTime;
						LARGE_INTEGER lgCurTime;

						bRetCode = GetProcessTimes(hProc, &CreateTime, &ExitTime, &KernelTime, &UserTime);
						if (bRetCode)
						{
							lgKernelTime.HighPart = KernelTime.dwHighDateTime;
							lgKernelTime.LowPart = KernelTime.dwLowDateTime;

							lgUserTime.HighPart = UserTime.dwHighDateTime;
							lgUserTime.LowPart = UserTime.dwLowDateTime;

							lgCurTime.QuadPart = (lgKernelTime.QuadPart + lgUserTime.QuadPart) / 10000;
							if (pProcessTime[n].g_slgProcessTimeOld.QuadPart == 0)
								nProcCpuPercent = 0;
							else
								nProcCpuPercent = (float)((lgCurTime.QuadPart - pProcessTime[n].g_slgProcessTimeOld.QuadPart) * 100 / 1000);
							pProcessTime[n].g_slgProcessTimeOld = lgCurTime;
							pProcessTime[n].dwProcessID = pe.th32ProcessID;
							nProcCpuPercent = nProcCpuPercent / dNumProcessor;
						}
						else
						{
							nProcCpuPercent = 0;
						}
						if (nProcCpuPercent > 100)
							nProcCpuPercent = 0;
						if (!inTipsProcessX)
						{
							PROCESSCPUUSAGE* ppc;
							if (ppcu[0]->fCpuUsage <= nProcCpuPercent)
							{
								ppc = ppcu[4];
								ppcu[4] = ppcu[3];
								ppcu[3] = ppcu[2];
								ppcu[2] = ppcu[1];
								ppcu[1] = ppcu[0];
								ppcu[0] = ppc;
								ppcu[0]->dwProcessID = pe.th32ProcessID;
								ppcu[0]->fCpuUsage = nProcCpuPercent;
								lstrcpyn(ppcu[0]->szExe, pe.szExeFile, 24);
							}
							else if (ppcu[1]->fCpuUsage <= nProcCpuPercent)
							{
								ppc = ppcu[4];
								ppcu[4] = ppcu[3];
								ppcu[3] = ppcu[2];
								ppcu[2] = ppcu[1];
								ppcu[1] = ppc;
								ppcu[1]->dwProcessID = pe.th32ProcessID;
								ppcu[1]->fCpuUsage = nProcCpuPercent;
								lstrcpyn(ppcu[1]->szExe, pe.szExeFile, 24);
							}
							else if (ppcu[2]->fCpuUsage <= nProcCpuPercent)
							{
								ppc = ppcu[4];
								ppcu[4] = ppcu[3];
								ppcu[3] = ppcu[2];
								ppcu[2] = ppc;
								ppcu[2]->dwProcessID = pe.th32ProcessID;
								ppcu[2]->fCpuUsage = nProcCpuPercent;
								lstrcpyn(ppcu[2]->szExe, pe.szExeFile, 24);
							}
							else if (ppcu[3]->fCpuUsage <= nProcCpuPercent)
							{
								ppc = ppcu[4];
								ppcu[4] = ppcu[3];
								ppcu[3] = ppc;
								ppcu[3]->dwProcessID = pe.th32ProcessID;
								ppcu[3]->fCpuUsage = nProcCpuPercent;
								lstrcpyn(ppcu[3]->szExe, pe.szExeFile, 24);
							}
							else if (ppcu[4]->fCpuUsage <= nProcCpuPercent)
							{
								ppcu[4]->dwProcessID = pe.th32ProcessID;
								ppcu[4]->fCpuUsage = nProcCpuPercent;
								lstrcpyn(ppcu[4]->szExe, pe.szExeFile, 24);
							}
						}
					}
					CloseHandle(hProc);
				}
			}
			ret = Process32Next(hs, &pe);
		}
		CloseHandle(hs);
	}
}
int GetProcessMemUsage()//获取进程内存占用前五
{
	if (!inTipsProcessX)
	{
		ppmu[0] = &pmu[0];
		ppmu[1] = &pmu[1];
		ppmu[2] = &pmu[2];
		ppmu[3] = &pmu[3];
		ppmu[4] = &pmu[4];
		memset(pmu, 0, sizeof pmu);
		pmu[0].dwMemUsage = 0;
		pmu[1].dwMemUsage = 0;
		pmu[2].dwMemUsage = 0;
		pmu[3].dwMemUsage = 0;
		pmu[4].dwMemUsage = 0;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	int n = 0;
	HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hs != INVALID_HANDLE_VALUE)
	{
		BOOL ret = Process32First(hs, &pe);
		while (ret)
		{
			++n;
			if (lstrcmp(pe.szExeFile, L"Memory Compression") != 0 && !inTipsProcessX)
			{
				HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
				if (hProc)
				{
					PROCESS_MEMORY_COUNTERS_EX pmc;
					if (GetProcessMemoryInfo(hProc, (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc)))
					{
						//QueryWorkingSet()
						PROCESSMEMORYUSAGE* ppm;
						if (ppmu[0]->dwMemUsage <= pmc.WorkingSetSize)
						{
							ppm = ppmu[4];
							ppmu[4] = ppmu[3];
							ppmu[3] = ppmu[2];
							ppmu[2] = ppmu[1];
							ppmu[1] = ppmu[0];
							ppmu[0] = ppm;
							ppmu[0]->dwProcessID = pe.th32ProcessID;
							ppmu[0]->dwMemUsage = pmc.WorkingSetSize;
							lstrcpyn(ppmu[0]->szExe, pe.szExeFile, 24);

						}
						else if (ppmu[1]->dwMemUsage <= pmc.WorkingSetSize)
						{
							ppm = ppmu[4];
							ppmu[4] = ppmu[3];
							ppmu[3] = ppmu[2];
							ppmu[2] = ppmu[1];
							ppmu[1] = ppm;
							ppmu[1]->dwProcessID = pe.th32ProcessID;
							ppmu[1]->dwMemUsage = pmc.WorkingSetSize;
							lstrcpyn(ppmu[1]->szExe, pe.szExeFile, 24);

						}
						else if (ppmu[2]->dwMemUsage <= pmc.WorkingSetSize)
						{
							ppm = ppmu[4];
							ppmu[4] = ppmu[3];
							ppmu[3] = ppmu[2];
							ppmu[2] = ppm;
							ppmu[2]->dwProcessID = pe.th32ProcessID;
							ppmu[2]->dwMemUsage = pmc.WorkingSetSize;
							lstrcpyn(ppmu[2]->szExe, pe.szExeFile, 24);

						}
						else if (ppmu[3]->dwMemUsage <= pmc.WorkingSetSize)
						{
							ppm = ppmu[4];
							ppmu[4] = ppmu[3];
							ppmu[3] = ppm;
							ppmu[3]->dwProcessID = pe.th32ProcessID;
							ppmu[3]->dwMemUsage = pmc.WorkingSetSize;
							lstrcpyn(ppmu[3]->szExe, pe.szExeFile, 24);
						}
						else if (ppmu[4]->dwMemUsage <= pmc.WorkingSetSize)
						{
							ppmu[4]->dwProcessID = pe.th32ProcessID;
							ppmu[4]->dwMemUsage = pmc.WorkingSetSize;
							lstrcpyn(ppmu[4]->szExe, pe.szExeFile, 24);
						}
					}
					CloseHandle(hProc);
				}
			}
			ret = Process32Next(hs, &pe);
		}
		CloseHandle(hs);
	}
	return n;
}
void DrawDisk(HDC mdc, LPRECT lpRect, double dwByte,BOOL bReadWrite)
{
	WCHAR szWriteS[] = L"X:";
	WCHAR szWriteS2[] = L"";
	WCHAR szReadS[] = L"R:";
	WCHAR szReadS2[] = L"";
	WCHAR* szT;
	if (bReadWrite)
	{
		if (TraySave.iMonitorSimple == 1)
			szT = szWriteS;
		else if (TraySave.iMonitorSimple == 2)
			szT = szWriteS2;
		else
			szT = TraySave.szDiskWriteSec;
	}
	else
	{
		if (TraySave.iMonitorSimple == 1)
			szT = szReadS;
		else if (TraySave.iMonitorSimple == 2)
			szT = szReadS2;
		else
			szT = TraySave.szDiskReadSec;
	}
	WCHAR sz[24];
	COLORREF rgb;
	if (dwByte/1024/1024 < TraySave.dNumValues2[0])
		rgb = TraySave.cMonitorColor[1];
	else if (dwByte/1024/1024 < TraySave.dNumValues2[1])
		rgb = TraySave.cMonitorColor[2];
	else
		rgb = TraySave.cMonitorColor[3];
	SetTextColor(mdc, rgb);
	float f_byte = (float)dwByte;
	if (dwByte < 1048576000)
	{		
		f_byte /= 1048576;
		int m_byte = int(f_byte * 100);
		if (f_byte >= 100)
			wsprintf(sz, L"%s%dM", szT, m_byte / 100);
		else if (f_byte >= 10)
			wsprintf(sz, L"%s%d.%.1dM", szT, m_byte / 100, (m_byte / 10) % 10);
		else
			wsprintf(sz, L"%s%d.%.2dM", szT, m_byte / 100, m_byte % 100);
	}
	else
	{
		f_byte /= 1073741824;
		int g_byte = int(f_byte * 100);
		if (f_byte >= 100)
			wsprintf(sz, L"%s%dG", szT, g_byte / 100);
		else if (f_byte >= 10)
			wsprintf(sz, L"%s%d.%.1dG", szT, g_byte / 100, (g_byte / 10) % 10);
		else
			wsprintf(sz, L"%s%d.%.2dG", szT, g_byte / 100, g_byte % 100);
	}
	if (VTray && (TraySave.bMonitorFloat == FALSE || TraySave.bMonitorFloatVRow))
		DrawShadowText(mdc, sz, lstrlen(sz), lpRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
	else
		DrawShadowText(mdc, sz, lstrlen(sz), lpRect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
}
void DrawTraffic(HDC mdc, LPRECT lpRect, DWORD dwByte, BOOL bInOut)
{
	WCHAR szInS[] = L"↓:";
	WCHAR szInS2[] = L"";
	WCHAR szOutS[] = L"↑:";
	WCHAR szOutS2[] = L"";
	WCHAR* szT;
	if (bInOut)
	{
		if (TraySave.iMonitorSimple == 1)
			szT = szInS;
		else if (TraySave.iMonitorSimple == 2)
			szT = szInS2;
		else
			szT = TraySave.szTrafficIn;
	}
	else
	{
		if (TraySave.iMonitorSimple == 1)
			szT = szOutS;
		else if (TraySave.iMonitorSimple == 2)
			szT = szOutS2;
		else
			szT = TraySave.szTrafficOut;
	}
	WCHAR sz[24];
	COLORREF rgb;
	if (dwByte < TraySave.dNumValues[0])
		rgb = TraySave.cMonitorColor[1];
	else if (dwByte < TraySave.dNumValues[1])
		rgb = TraySave.cMonitorColor[2];
	else
		rgb = TraySave.cMonitorColor[3];
	SetTextColor(mdc, rgb);
	if (HIWORD(TraySave.iUnit))
		dwByte *= 8;
	float f_byte = (float)dwByte;
	if (dwByte < 1000 && LOWORD(TraySave.iUnit) == 0)
		wsprintf(sz, L"%s%dB", szT, dwByte);
	else if ((dwByte < 1024000 || (dwByte < 1000000 && HIWORD(TraySave.iUnit))) && LOWORD(TraySave.iUnit) != 2)
	{
		if (HIWORD(TraySave.iUnit))
			f_byte /= 1000;
		else
			f_byte /= 1024;
		int k_byte = int(f_byte * 100);
		if (f_byte >= 100)
			wsprintf(sz, L"%s%dK", szT, k_byte / 100);
		else if (f_byte >= 10)
			wsprintf(sz, L"%s%d.%.1dK", szT, k_byte / 100, (k_byte / 10) % 10);
		else
			wsprintf(sz, L"%s%d.%.2dK", szT, k_byte / 100, k_byte % 100);
	}
	else if (dwByte < 1048576000 || (dwByte < 1000000000 && HIWORD(TraySave.iUnit)))
	{
		if (HIWORD(TraySave.iUnit))
			f_byte /= 1000000;
		else
			f_byte /= 1048576;
		int m_byte = int(f_byte * 100);
		if (f_byte >= 100)
			wsprintf(sz, L"%s%dM", szT, m_byte / 100);
		else if (f_byte >= 10)
			wsprintf(sz, L"%s%d.%.1dM", szT, m_byte / 100, (m_byte / 10) % 10);
		else
			wsprintf(sz, L"%s%d.%.2dM", szT, m_byte / 100, m_byte % 100);
	}
	else
	{
		if (HIWORD(TraySave.iUnit))
			f_byte /= 1000000000;
		else
			f_byte /= 1073741824;
		int g_byte = int(f_byte * 100);
		if (f_byte >= 100)
			wsprintf(sz, L"%s%dG", szT, g_byte / 100);
		else if (f_byte >= 10)
			wsprintf(sz, L"%s%d.%.1dG", szT, g_byte / 100, (g_byte / 10) % 10);
		else
			wsprintf(sz, L"%s%d.%.2dG", szT, g_byte / 100, g_byte % 100);
	}
	if (HIWORD(TraySave.iUnit))
		lstrlwr(sz, 16);
	if (VTray && (TraySave.bMonitorFloat == FALSE||TraySave.bMonitorFloatVRow))
		DrawShadowText(mdc, sz, lstrlen(sz), lpRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
	else
		DrawShadowText(mdc, sz, lstrlen(sz), lpRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
}
BOOL bEvent = FALSE;//
BOOL SetTrackMouseEvent(HWND hWnd, DWORD dwFlags)
{
	TRACKMOUSEEVENT csTME;
	csTME.cbSize = sizeof(csTME);
	csTME.dwFlags = dwFlags;
	csTME.hwndTrack = hWnd;// 指定要 追踪 的窗口
	csTME.dwHoverTime = 300;  // 鼠标在按钮上停留超过 300ms ，才认为状态为 HOVER
	return TrackMouseEvent(&csTME);
}
INT_PTR CALLBACK TimeProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)//任务栏信息窗口过程
{
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;
	case WM_ERASEBKGND:
	{
		//		PAINTSTRUCT ps;
		HDC hdc = (HDC)wParam;//BeginPaint(hDlg, &ps);		
		RECT rc;
		GetClientRect(hDlg, &rc);
		HDC mdc = CreateCompatibleDC(hdc);
		HBITMAP hMemBmp = CreateCompatibleBitmap(hdc, rc.right - rc.left, rc.bottom - rc.top);
		HBITMAP oldBmp = (HBITMAP)SelectObject(mdc, hMemBmp);

		COLORREF rgb(RGB(255, 255, 255));
		COLORREF cBack = RGB(0, 0, 1);
		if (bThemeMode != 0)
		{
			rgb = RGB(8, 8, 8);
//			if(rovi.dwBuildNumber>22000)
//				cBack = RGB(254, 254, 255);
		}
		if (hWin11UI)
		{
			HBRUSH hb = CreateSolidBrush(cBack);
			FillRect(mdc, &rc, hb);
			DeleteObject(hb);
		}
		SYSTEMTIME systm;
		GetLocalTime(&systm);
		WCHAR sz[16];
		TCHAR szWeek[7][2] = { L"日",L"一",L"二",L"三",L"四",L"五",L"六" };
		
		int fsize;
		if (hWin11UI)
		{
			fsize = DPI(-11);
			wsprintf(sz, L"%.2d'%s", systm.wSecond, szWeek[systm.wDayOfWeek]);
		}
		else
		{
			fsize = DPI(-12);
			wsprintf(sz, L"%s%.2d:%.2d:%.2d", szWeek[systm.wDayOfWeek], systm.wHour,systm.wMinute,systm.wSecond );
		}
		HFONT hFont=CreateFont(fsize, 0, 0, 0, 0, false, false, false,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
			CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
			DEFAULT_PITCH, L"微软雅黑");
		HFONT oldFont = (HFONT)SelectObject(mdc, hFont);
		SetBkMode(mdc, TRANSPARENT);
		SetTextColor(mdc, rgb);
		if(!hWin11UI)
			DrawText(mdc, sz, lstrlen(sz), &rc, DT_CENTER | DT_SINGLELINE|DT_VCENTER);
		else
			DrawText(mdc, sz, 4, &rc, DT_LEFT | DT_SINGLELINE | DT_BOTTOM);
		SelectObject(mdc, oldFont);
		DeleteObject(hFont);

		if (!hWin11UI)
		{
			BYTE* lpvBits = NULL;
			BITMAPINFO binfo;
			memset(&binfo, 0, sizeof(BITMAPINFO));
			binfo.bmiHeader.biBitCount = 32;     //每个像素多少位，也可直接写24(RGB)或者32(RGBA)
			binfo.bmiHeader.biCompression = 0;
			binfo.bmiHeader.biHeight = rc.bottom - rc.top;
			binfo.bmiHeader.biPlanes = 1;
			binfo.bmiHeader.biSizeImage = (rc.bottom - rc.top) * (rc.right - rc.left) * 4;
			binfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
			binfo.bmiHeader.biWidth = rc.right - rc.left;
			lpvBits = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, binfo.bmiHeader.biSizeImage);
			//		GetDIBits(mdc, hMemBmp, 0, rc.bottom - rc.top, lpvBits, &bmpInfo, DIB_RGB_COLORS);

			GetDIBits(mdc, hMemBmp, 0, rc.bottom - rc.top, lpvBits, &binfo, DIB_RGB_COLORS);
			for (DWORD i = 0; i < binfo.bmiHeader.biSizeImage - 4; i += 4)
			{
				if (lpvBits[i] > 3 || lpvBits[i + 1] != 0 || lpvBits[i + 2] != 0)
					lpvBits[i + 3] = 0x80;
			}
			SetDIBits(mdc, hMemBmp, 0, rc.bottom - rc.top, lpvBits, &binfo, DIB_RGB_COLORS);
			HeapFree(GetProcessHeap(), 0, lpvBits);
		}
		BitBlt(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mdc, 0, 0, SRCCOPY);
		SelectObject(mdc, oldBmp);
		DeleteObject(hMemBmp);
		DeleteDC(mdc);
		return TRUE;
	}
	break;
	}
	return FALSE;
}
int iGetAddressTime=10;//10秒一次获取网卡信息
INT_PTR CALLBACK TaskBarProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)//任务栏信息窗口过程
{
	switch (message)
	{
	case WM_INITDIALOG:		
		return (INT_PTR)TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) >= IDC_SELECT_ALL && LOWORD(wParam) <= IDC_SELECT_ALL + 99)
		{
			if (LOWORD(wParam) == IDC_SELECT_ALL)
				TraySave.AdpterName[0] = L'\0';
			else
			{
				int x = LOWORD(wParam) - IDC_SELECT_ALL;
				PIP_ADAPTER_ADDRESSES paa;
				paa = &piaa[0];
				int n = 1;
				while (paa)
				{
					if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL)
					{
						if (n == x)
						{
							lstrcpyA(TraySave.AdpterName, paa->AdapterName);
							break;
						}
						n++;
					}
					paa = paa->Next;
				}
			}
			WriteReg();
			m_last_in_bytes = 0;
			m_last_out_bytes = 0;
			s_in_byte = 0;
			s_out_byte = 0;
		}
		else if (LOWORD(wParam) >= IDC_DISK_ALL && LOWORD(wParam) <= IDC_DISK_ALL + 99)
		{
			if (LOWORD(wParam) == IDC_DISK_ALL)
				TraySave.szDisk = L'\0';
			else
			{
				TraySave.szDisk = LOWORD(wParam) - IDC_DISK_ALL;
			}
			WriteReg();
			SwitchPDH(FALSE);
			SwitchPDH(TRUE);
			diskreadbyte = 0;
			diskwritebyte = 0;
			disktime = 0;
		}
		break;
	case WM_MOUSEMOVE:
		if (bEvent == FALSE && TraySave.bMonitorTips)
		{
			SetTrackMouseEvent(hTaskBar, TME_LEAVE | TME_HOVER);
			bEvent = TRUE;
		}
		break;
	case WM_MOUSEHOVER:
	{
		if (!IsWindowVisible(hTaskTips)&&TraySave.bMonitorTips)
		{
/*
			if (s_in_byte == 0)
				return FALSE;
*/
			if (!IsWindow(hTaskTips))
			{
				hTaskTips = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_TIPS), NULL, (DLGPROC)TaskTipsProc);
				SetLayeredWindowAttributes(hTaskTips, 0, 255, LWA_ALPHA);
			}
			nProcess = GetProcessMemUsage();
			if (pProcessTime == NULL)
			{
				pProcessTime = (PROCESSTIME*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof PROCESSTIME * (nProcess + 32));
				memset(pProcessTime, 0, sizeof(PROCESSTIME) * (nProcess + 32));
			}
			GetProcessCpuUsage();
			HDC mdc = GetDC(hMain);
			TraySave.TipsFont.lfHeight = DPI(TraySave.TipsFontSize);
			HFONT hTipsFont = CreateFontIndirect(&TraySave.TipsFont); //创建字体
			HFONT oldFont = (HFONT)SelectObject(mdc, hTipsFont);
			SIZE tSize;
			::GetTextExtentPoint(mdc, L"虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存", 32, &tSize);
			SelectObject(mdc, oldFont);
			DeleteObject(hTipsFont);
			::ReleaseDC(hMain, mdc);
			int x, y, w, h;
			w = tSize.cx;
			wTipsHeight = tSize.cy;
			h = wTipsHeight * (nTraffic + 12);
			RECT wrc, src;
			GetWindowRect(hDlg, &wrc);
			GetScreenRect(hDlg, &src, TRUE);
			if (wrc.bottom + h > src.bottom)
				y = wrc.top - h;
			else
				y = wrc.bottom;
			if (wrc.right - (wrc.right - wrc.left) / 2 + w / 2 > src.right)
				x = src.right - w;
			else if (wrc.right - (wrc.right - wrc.left) / 2 - w / 2 < src.left)
				x = src.left;
			else
				x = wrc.right - (wrc.right - wrc.left) / 2 - w / 2;
			SetWindowPos(hTaskTips, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
			HRGN hRgn = CreateRoundRectRgn(0, 0, w + 1, h + 1, 11, 11);
			SetWindowRgn(hTaskTips, hRgn, FALSE);
//			SetCursorPos(2498, 1398);
//			mouse_event(MOUSEEVENTF_MOVE, 2380, 1398, 0, 0);
//			mouse_event(MOUSEEVENTF_LEFTDOWN, 2500, 1398, 0, 0);
//			mouse_event(MOUSEEVENTF_LEFTUP, 2500, 1398, 0, 0);
		}
	}
	break;
	case WM_MOUSELEAVE:
		Sleep(100);
		POINT pt;
		GetCursorPos(&pt);
		if (WindowFromPoint(pt) != hTaskTips)
		{
			if (pProcessTime != NULL)
			{
				HeapFree(GetProcessHeap(), 0, pProcessTime);
				pProcessTime = NULL;
			}
			DestroyWindow(hTaskTips);
			//			ShowWindow(hTaskTips, SW_HIDE);
			SetTimer(hMain, 11, 1000, NULL);
		}
		else
			SetTrackMouseEvent(hTaskTips, TME_LEAVE);
		bEvent = FALSE;
		break;
	case  WM_RBUTTONDOWN:
	{
		POINT pt;
		GetCursorPos(&pt);
		ScreenToClient(hDlg, &pt);
		if (TraySave.bMonitorTraffic && pt.x < wTraffic && pt.y < wHeight * 2)
		{

			HMENU hMenu = LoadMenu(hInst, MAKEINTRESOURCEW(IDR_MENU));
			HMENU subMenu = GetSubMenu(hMenu, 0);
			PIP_ADAPTER_ADDRESSES paa;
			paa = &piaa[0];
			int n = 1;
			CheckMenuRadioItem(subMenu, IDC_SELECT_ALL, IDC_SELECT_ALL + 99, IDC_SELECT_ALL, MF_BYCOMMAND);
			while (paa)
			{
				if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL)
				{
					AppendMenu(subMenu, MF_BYCOMMAND, IDC_SELECT_ALL + n, paa->FriendlyName);
					if (lstrcmpA(paa->AdapterName, TraySave.AdpterName) == 0)
						CheckMenuRadioItem(subMenu, IDC_SELECT_ALL, IDC_SELECT_ALL + 99, IDC_SELECT_ALL + n, MF_BYCOMMAND);
					n++;
				}
				paa = paa->Next;
			}
			POINT point;
			GetCursorPos(&point);
			SetTimer(hDlg, 5, 1200, NULL);
			TrackPopupMenu(subMenu, TPM_LEFTALIGN, point.x, point.y, NULL, hDlg, NULL);
			DestroyMenu(hMenu);
		}
		else if (TraySave.bMonitorTime && (pt.x > mWidth - wTime || pt.y > mHeight - wHeight * 2))
			RunProcess(NULL, szTimeDateCpl);
		else
		{
			int l = wTraffic + wUsage + wTemperature;
			int b = mHeight-wHeight*2;
			if (TraySave.bMonitorTime)
				b -= wHeight * 2;
			if (TraySave.bMonitorDisk && (pt.x > l || pt.y > b))
			{
				HMENU hMenu = LoadMenu(hInst, MAKEINTRESOURCEW(IDR_MENU));
				HMENU subMenu = GetSubMenu(hMenu, 1);
				CheckMenuRadioItem(subMenu, IDC_DISK_ALL, IDC_DISK_ALL + 99, IDC_DISK_ALL, MF_BYCOMMAND);
				WCHAR wDrive[MAX_PATH];
				DWORD dwLen = GetLogicalDriveStrings(MAX_PATH, wDrive);
				DWORD driver_number = dwLen / 4;
				for (DWORD nIndex = 0; nIndex < driver_number; nIndex++)
				{
					LPWSTR dName = wDrive + nIndex * 4;
					if (GetDriveType(dName) != DRIVE_CDROM)
					{
						if (GetPhysicalDriveFromPartitionLetter(dName[0]) != -1)
						{
							dName[2] = 0;
							AppendMenu(subMenu, MF_BYCOMMAND, IDC_DISK_ALL + dName[0], dName);
							if (TraySave.szDisk == dName[0])
								CheckMenuRadioItem(subMenu, IDC_DISK_ALL, IDC_DISK_ALL + 99, IDC_DISK_ALL + dName[0], MF_BYCOMMAND);
						}
					}
				}
				POINT point;
				GetCursorPos(&point);
				SetTimer(hDlg, 5, 1200, NULL);
				TrackPopupMenu(subMenu, TPM_LEFTALIGN, point.x, point.y, NULL, hDlg, NULL);
				DestroyMenu(hMenu);
			}
			else
				OpenSetting();
		}
		return TRUE;
	}
	break;
	case WM_LBUTTONDOWN:
	{
		if (TraySave.bMonitorFloat)
		{
			bTaskBarMoveing = TRUE;
			PostMessage(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, lParam);
			SetTimer(hDlg, 11, 1000, NULL);
		}
		return TRUE;
		/*
				else
					RunProcess(szNetCpl);
		*/
	}
	break;
	case WM_LBUTTONUP:
		if (!TraySave.bMonitorFloat)
		{
/*
			ShowWindow(hDlg, SW_HIDE);
			Sleep(100);
			POINT pt;
			GetCursorPos(&pt);
			mouse_event(MOUSEEVENTF_LEFTDOWN, pt.x, pt.y, 0, 0);
			mouse_event(MOUSEEVENTF_LEFTUP, pt.x, pt.y, 0, 0);
			SetTimer(hDlg, 9, 3000, NULL);
			ShowWindow(hTaskTips,SW_HIDE);
			return TRUE;
*/
		}
		break;
	case WM_TIMER:
		if (wParam == 11)
		{
			if (!KEYDOWN(VK_LBUTTON))
			{
				if (TraySave.bMonitorFloat && bTaskBarMoveing)
				{
					RECT wrc;
					GetWindowRect(hDlg, &wrc);
					TraySave.dMonitorPoint.x = wrc.left;
					TraySave.dMonitorPoint.y = wrc.top;
					WriteReg();
					bTaskBarMoveing = FALSE;
					KillTimer(hDlg, wParam);
				}
			}
		}
		else if (wParam == 9)
		{
			KillTimer(hDlg, wParam);
			ShowWindow(hDlg, SW_SHOWNOACTIVATE);
		}
		else if (wParam == 5)////////////////////////////////////////////////光标移出弹出式菜单自动隐藏菜单
		{

			HWND hMenu = FindWindow(L"#32768", NULL);
			POINT pt;
			GetCursorPos(&pt);
			if (WindowFromPoint(pt) != hMenu)
			{
				KillTimer(hDlg, wParam);
				PostMessage(hMenu, WM_CLOSE, NULL, NULL);
			}
		}
		else if (wParam == 3)
		{
			if (IsWindowVisible(hTaskTips))
			{
				nProcess = GetProcessMemUsage();
				GetProcessCpuUsage();
			}
			GlobalMemoryStatusEx(&MemoryStatusEx);
			if (TraySave.bMonitorDisk)
			{
				TraySave.bMonitorPDH = TRUE;
				if (TraySave.bMonitorUsage == FALSE)
					GetPDH(FALSE, TRUE);
			}
			if (TraySave.bMonitorUsage)
			{
				iCPU = GetCPUUseRate();
			}
			if (TraySave.bMonitorTemperature)
			{
				if (bRing0)
				{
					iTemperature1 = GetCpuTemp(1);
					iTemperature2 = GetCpuTemp(dNumProcessor);
				}
				int iATITemperature = 0;
				int iNVTemperature = 0;
				if (hNVDLL)
				{
					NV_GPU_THERMAL_SETTINGS currentTemp;//获取温度的数据结构
					currentTemp.version = NV_GPU_THERMAL_SETTINGS_VER;//一定要设置，不然调用获取温度函数时候会出错
					for (int GpuIndex = 0; GpuIndex < 4; GpuIndex++)
					{
						if (NvAPI_GPU_GetThermalSettings(hPhysicalGpu[GpuIndex], 15, &currentTemp) == 0)
						{
							iNVTemperature = currentTemp.sensor[0].currentTemp;
							break;
						}
					}
				}
				if (hATIDLL)
				{
					adlTemperature.iSize = sizeof(ADLTemperature);
					ADL_Overdrive5_Temperature_Get(0, 0, &adlTemperature);
					iATITemperature = adlTemperature.iTemperature / 1000;
				}
				if (iATITemperature != 0 || iNVTemperature != 0)
				{
					if (iATITemperature > iNVTemperature)
						iTemperature2 = iATITemperature;
					else
						iTemperature2 = iNVTemperature;
				}
			}
			if (TraySave.bMonitorTraffic)
			{
				if (hIphlpapi == NULL)
				{
					hIphlpapi = LoadLibrary(L"iphlpapi.dll");
					if (hIphlpapi)
					{
						GetAdaptersAddressesT = (pfnGetAdaptersAddresses)GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
						GetIfTableT = (pfnGetIfTable)GetProcAddress(hIphlpapi, "GetIfTable");
					}
				}
				if (hIphlpapi)
				{
					PIP_ADAPTER_ADDRESSES paa;
					if (iGetAddressTime == 10)
					{
						//				DWORD odwIPSize = dwIPSize;
						dwIPSize = 0;
						if (GetAdaptersAddressesT(AF_INET, 0, 0, piaa, &dwIPSize) == ERROR_BUFFER_OVERFLOW)
						{
							//					if (dwIPSize != odwIPSize)
							{

								HeapFree(GetProcessHeap(), 0, piaa);
								int n = 0;
								piaa = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwIPSize);
								if (GetAdaptersAddressesT(AF_INET, 0, 0, piaa, &dwIPSize) == ERROR_SUCCESS)
								{
									paa = &piaa[0];
									while (paa)
									{
										if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL)
										{
											++n;
										}
										paa = paa->Next;
									}
									if (n != nTraffic)
									{
										HeapFree(GetProcessHeap(), 0, traffic);
										nTraffic = n;
										traffic = (TRAFFIC*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nTraffic * sizeof TRAFFIC);
									}
								}
							}
						}
						iGetAddressTime = 0;
					}
					else
						iGetAddressTime++;
					/*
								PIP_ADAPTER_INFO pai;
								if (GetAdaptersInfo(ipinfo, &dwIPSize) == ERROR_BUFFER_OVERFLOW)
								{
									free(ipinfo);
									ipinfo = (PIP_ADAPTER_INFO)malloc(dwIPSize);
									GetAdaptersInfo(ipinfo, &dwIPSize);
									pai = &ipinfo[0];
									nTraffic = 0;
									while (pai)
									{
										++nTraffic;
										pai = pai->Next;
									}
									free(traffic);
									traffic = (TRAFFIC*)malloc(nTraffic * sizeof TRAFFIC);
								}
					*/
					if (nTraffic != 0)
					{
						if (GetIfTableT(mi, &dwMISize, FALSE) == ERROR_INSUFFICIENT_BUFFER)
						{
							dwMISize += sizeof MIB_IFROW * 2;
							HeapFree(GetProcessHeap(), 0, mi);
							mi = (MIB_IFTABLE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwMISize);
							GetIfTableT(mi, &dwMISize, FALSE);
						}
						DWORD m_in_bytes = 0;
						DWORD m_out_bytes = 0;
						for (DWORD i = 0; i < mi->dwNumEntries; i++)
						{
							int l = 0;
							paa = &piaa[0];
							while (paa)
							{
								if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL)
								{
									if (paa->IfIndex == mi->table[i].dwIndex)
									{
										traffic[l].in_byte = (mi->table[i].dwInOctets - traffic[l].in_bytes) * 8;
										traffic[l].out_byte = (mi->table[i].dwOutOctets - traffic[l].out_bytes) * 8;
										traffic[l].in_bytes = mi->table[i].dwInOctets;
										traffic[l].out_bytes = mi->table[i].dwOutOctets;

										PIP_ADAPTER_UNICAST_ADDRESS pUnicast = paa->FirstUnicastAddress;
										//							char IP[130];
										while (pUnicast)
										{
											if (AF_INET == pUnicast->Address.lpSockaddr->sa_family)// IPV4 地址，使用 IPV4 转换
											{
												void* pAddr = &((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr;
												byte* bp = (byte*)pAddr;
												wsprintf(traffic[l].IP4, L"%d.%d.%d.%d", bp[0], bp[1], bp[2], bp[3]);
												break;
											}
											//								else if (AF_INET6 == pUnicast->Address.lpSockaddr->sa_family)// IPV6 地址，使用 IPV6 转换
											//									inet_ntop(PF_INET6, &((sockaddr_in6*)pUnicast->Address.lpSockaddr)->sin6_addr, IP, sizeof(IP));
											pUnicast = pUnicast->Next;
										}
										//							MultiByteToWideChar(CP_ACP, 0, IP, 15, traffic[l].IP4, 15);
										traffic[l].FriendlyName = paa->FriendlyName;
										traffic[l].AdapterName = paa->AdapterName;
										if (lstrlen(paa->FriendlyName) > 19)
										{
											paa->FriendlyName[16] = L'.';
											paa->FriendlyName[17] = L'.';
											paa->FriendlyName[18] = L'.';
											paa->FriendlyName[19] = L'\0';
										}
										//							wcsncpy_s(traffic[l].FriendlyName, 24, paa->FriendlyName,24);
										if (TraySave.AdpterName[0] == L'\0' || lstrcmpA(paa->AdapterName, TraySave.AdpterName) == 0)
										{
											m_in_bytes += mi->table[i].dwInOctets;
											m_out_bytes += mi->table[i].dwOutOctets;
										}
									}
									++l;
								}
								paa = paa->Next;
							}
						}
						if (m_last_in_bytes != 0)
						{
							s_in_byte = m_in_bytes - m_last_in_bytes;
							s_out_byte = m_out_bytes - m_last_out_bytes;
/*
							s_in_bytes[iBytes] = s_in_byte / 1024;
							s_out_bytes[iBytes] = s_out_byte / 1024;
							if (iBytes == rNum-1)
								iBytes = 0;
							else
								++iBytes;
*/
						}
						m_last_out_bytes = m_out_bytes;
						m_last_in_bytes = m_in_bytes;
					}
				}
			}
			else
			{
				if (hIphlpapi)
				{
					FreeLibrary(hIphlpapi);
					hIphlpapi = NULL;
				}
			}
			if (TraySave.bSound)
			{
				if (TraySave.bMonitorTraffic)
					if (TraySave.dNumValues[8] != 0 && (s_in_byte > TraySave.dNumValues[8] || s_out_byte > TraySave.dNumValues[8]))
						MessageBeep(MB_ICONHAND);
				if (TraySave.bMonitorTemperature)
					if (TraySave.dNumValues[9] != 0 && ((DWORD)iTemperature1 > TraySave.dNumValues[9] || (DWORD)iTemperature2 > TraySave.dNumValues[9]))
						MessageBeep(MB_ICONHAND);
				if (TraySave.bMonitorUsage)
					if ((TraySave.dNumValues[10] != 0 && (DWORD)iCPU > TraySave.dNumValues[10]) || (TraySave.dNumValues[11] != 0 && MemoryStatusEx.dwMemoryLoad > TraySave.dNumValues[11]))
						MessageBeep(MB_ICONHAND);
				if (TraySave.bMonitorDisk)
					if (TraySave.dNumValues2[2] != 0 && (diskreadbyte / 1024 / 1024 > TraySave.dNumValues2[2] || diskwritebyte / 1024 / 1024 > TraySave.dNumValues2[2]))
						MessageBeep(MB_ICONHAND);
			}
			if (TraySave.bSecond)
			{
				if (IsWindow(hTime))
					::InvalidateRect(hTime, NULL, TRUE);
			}
			if (IsWindow(hTaskBar))
				::InvalidateRect(hTaskBar, NULL, TRUE);
			if (rovi.dwBuildNumber >= 22000)//&&TraySave.cMonitorColor[0]==RGB(0,0,1))
			{
/*
				RECT src,frc;
				DWORD pid1, pid2;
				HWND fwnd = GetForegroundWindow();
				GetWindowThreadProcessId(fwnd, &pid1);
				GetWindowThreadProcessId(hTray, &pid2);
				GetScreenRect(hDlg, &src, FALSE);
				GetWindowRect(fwnd, &frc);
				if (EqualRect(&src, &frc) == 0 || pid1 == pid2)
*/
				if(!bFullScreen)
				{
					POINT pt;
					GetCursorPos(&pt);
					RECT brc;
					GetWindowRect(hTaskBar, &brc);
					if (PtInRect(&brc, pt))
					{
						if (!KEYDOWN(VK_LBUTTON))
							SendMessage(hTaskBar, WM_MOUSEHOVER, 0, 0);
					}
					else if (WindowFromPoint(pt) != hTaskTips)
					{
						if (IsWindow(hTaskTips))
							SendMessage(hTaskBar, WM_MOUSELEAVE, 0, 0);
					}
				}
			}
		}
	case WM_ERASEBKGND:
	{
		//		PAINTSTRUCT ps;
		HDC hdc = (HDC)wParam;//BeginPaint(hDlg, &ps);		
		RECT rc;
		GetClientRect(hDlg, &rc);
		HDC mdc = CreateCompatibleDC(hdc);
		HBITMAP hMemBmp = CreateCompatibleBitmap(hdc, rc.right - rc.left, rc.bottom - rc.top);
		HBITMAP oldBmp = (HBITMAP)SelectObject(mdc, hMemBmp);
//		if (TraySave.cMonitorColor[0] != 0)
		{
			HBRUSH hb;
			if(TraySave.cMonitorColor[0] != RGB(0, 0, 1))
				hb = CreateSolidBrush(TraySave.cMonitorColor[0]);
			else
			{

/*
				if(bThemeMode&&!TraySave.bMonitorFloat&&rovi.dwBuildNumber>22000)
					hb=CreateSolidBrush(RGB(222,222,223));
				else
*/
					hb = CreateSolidBrush(RGB(0, 0,1));
			}
			FillRect(mdc, &rc, hb);
			DeleteObject(hb);
		}
		//		if (bErasebkgnd)
		{
			InflateRect(&rc, -1, -1);
			HFONT oldFont = (HFONT)SelectObject(mdc, hFont);
			WCHAR sz[16];
			SetBkMode(mdc, TRANSPARENT);
			COLORREF rgb;
			if (TraySave.bMonitorTraffic)
			{
				RECT crc = rc;				
				if (VTray && (TraySave.bMonitorFloat == FALSE|| TraySave.bMonitorFloatVRow))
				{
					crc.bottom = wHeight;
					if(TraySave.bMonitorTrafficUpDown)
						DrawTraffic(mdc, &crc, s_out_byte, FALSE);
					else
						DrawTraffic(mdc, &crc, s_in_byte, TRUE);
					OffsetRect(&crc, 0, wHeight);
					if (TraySave.bMonitorTrafficUpDown)
						DrawTraffic(mdc, &crc, s_in_byte, TRUE);
					else
						DrawTraffic(mdc, &crc, s_out_byte, FALSE);
				}
				else
				{
					crc.right = crc.left + wTraffic;
					crc.bottom /= 2;
					if (TraySave.bMonitorTrafficUpDown)
						DrawTraffic(mdc, &crc, s_out_byte, FALSE);
					else
						DrawTraffic(mdc, &crc, s_in_byte, TRUE);
					OffsetRect(&crc, 0, crc.bottom);
					if (TraySave.bMonitorTrafficUpDown)
						DrawTraffic(mdc, &crc, s_in_byte, TRUE);
					else
						DrawTraffic(mdc, &crc, s_out_byte, FALSE);
				}
			}
			if (TraySave.bMonitorUsage)
			{
				if (iCPU <= TraySave.dNumValues[4])
					rgb = TraySave.cMonitorColor[4];
				else if (iCPU <= TraySave.dNumValues[5])
					rgb = TraySave.cMonitorColor[5];
				else
					rgb = TraySave.cMonitorColor[6];
				SetTextColor(mdc, rgb);
				/*
							if(bRing0)
								swprintf_s(sz, 16, L"%.2d%%", iCPU);
							else
				*/
				if (TraySave.iMonitorSimple == 1)
					wsprintf(sz, L"%.2d%%", iCPU);
				else if (TraySave.iMonitorSimple == 2)
					wsprintf(sz, L"%.2d", iCPU);
				else
					wsprintf(sz, L"%s%.2d%s", TraySave.szUsageCPU, iCPU, TraySave.szUsageCPUUnit);

				int sLen = lstrlen(sz);
				RECT crc = rc;
				if (VTray && (TraySave.bMonitorFloat == FALSE || TraySave.bMonitorFloatVRow))
				{
					if (TraySave.bMonitorTraffic)
						crc.top = wHeight * 2;
					crc.bottom = crc.top + wHeight;
					DrawShadowText(mdc, sz, sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				else
				{
					crc.left = crc.left + wTraffic;
					crc.right = crc.left + wUsage;
					crc.bottom /= 2;
					DrawShadowText(mdc, sz, sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				/*
							if(bRing0)
								swprintf_s(sz, 16, L"%.2d%%", MemoryStatusEx.dwMemoryLoad);
							else
				*/
				if (TraySave.iMonitorSimple == 1)
					wsprintf(sz, L"%.2d%%", MemoryStatusEx.dwMemoryLoad);
				else if (TraySave.iMonitorSimple == 2)
					wsprintf(sz, L"%.2d", MemoryStatusEx.dwMemoryLoad);
				else
					wsprintf(sz, L"%s%.2d%s", TraySave.szUsageMEM, MemoryStatusEx.dwMemoryLoad, TraySave.szUsageMEMUnit);
				sLen = lstrlen(sz);
				if (MemoryStatusEx.dwMemoryLoad <= TraySave.dNumValues[6])
					rgb = TraySave.cMonitorColor[4];
				else if (MemoryStatusEx.dwMemoryLoad <= TraySave.dNumValues[7])
					rgb = TraySave.cMonitorColor[5];
				else
					rgb = TraySave.cMonitorColor[6];
				SetTextColor(mdc, rgb);
				if (VTray && (TraySave.bMonitorFloat == FALSE || TraySave.bMonitorFloatVRow))
				{
					OffsetRect(&crc, 0, wHeight);
					DrawShadowText(mdc, sz, (int)sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				else
				{
					OffsetRect(&crc, 0, crc.bottom);
					DrawShadowText(mdc, sz, (int)sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
			}
			if (TraySave.bMonitorTemperature)
			{
				RECT crc = rc;
				if (VTray && (TraySave.bMonitorFloat == FALSE|| TraySave.bMonitorFloatVRow))
				{
					if (TraySave.bMonitorTraffic)
						crc.top = wHeight * 2;
					if (TraySave.bMonitorUsage)
						crc.top += wHeight * 2;
					crc.bottom = crc.top + wHeight;
				}
				else
				{
					crc.left += wTraffic + wUsage;
					crc.right = crc.left  + wTemperature;
					crc.bottom /= 2;
				}
				if (bRing0)
				{
					if ((hATIDLL != NULL || hNVDLL != NULL||iTemperature1==0)&&TraySave.bMonitorDisk)
						iTemperature1 = disktime;
					if (iTemperature1 <= TraySave.dNumValues[2])
						rgb = TraySave.cMonitorColor[4];
					else if (iTemperature1 <= TraySave.dNumValues[3])
						rgb = TraySave.cMonitorColor[5];
					else
						rgb = TraySave.cMonitorColor[6];
					SetTextColor(mdc, rgb);
					if ((hATIDLL != NULL || hNVDLL != NULL) && TraySave.bMonitorDisk)
					{
						if (TraySave.iMonitorSimple == 0)
							wsprintf(sz, L"%s%.2d%s", TraySave.szDiskName,iTemperature1, TraySave.szUsageMEMUnit);
						else if (TraySave.iMonitorSimple == 1)
							wsprintf(sz, L"%.2d%%", iTemperature1);
						else
							wsprintf(sz, L"%.2d", iTemperature1);
					}
					else
					{
						if (TraySave.iMonitorSimple == 1)
							wsprintf(sz, L"%.2d℃", iTemperature1);
						else if (TraySave.iMonitorSimple == 2)
							wsprintf(sz, L"%.2d", iTemperature1);
						else
							wsprintf(sz, L"%s%.2d%s", TraySave.szTemperatureCPU, iTemperature1, TraySave.szTemperatureCPUUnit);
					}
					if (VTray && (TraySave.bMonitorFloat == FALSE|| TraySave.bMonitorFloatVRow))
						DrawShadowText(mdc, sz, lstrlen(sz), &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
					else
						DrawShadowText(mdc, sz, lstrlen(sz), &crc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				if (bRing0)
				{
					if (VTray && (TraySave.bMonitorFloat == FALSE|| TraySave.bMonitorFloatVRow))
						OffsetRect(&crc, 0, wHeight);
					else
						OffsetRect(&crc, 0, crc.bottom);
				}
				else
				{
					if (VTray && (TraySave.bMonitorFloat == FALSE|| TraySave.bMonitorFloatVRow))
					{
						//						crc.bottom += wHeight;
					}
					else
						crc.bottom += (crc.bottom - crc.top);
				}
				if (hATIDLL == NULL && hNVDLL == NULL&&TraySave.bMonitorDisk)//如果没有独立显卡则显示磁盘使用率
					iTemperature2 = disktime;
				if (iTemperature2 <= TraySave.dNumValues[2])
					rgb = TraySave.cMonitorColor[4];
				else if (iTemperature2 <= TraySave.dNumValues[3])
					rgb = TraySave.cMonitorColor[5];
				else
					rgb = TraySave.cMonitorColor[6];
				SetTextColor(mdc, rgb);
				if (hATIDLL == NULL && hNVDLL == NULL && TraySave.bMonitorDisk)
				{
					if (TraySave.iMonitorSimple == 0)
						wsprintf(sz, L"%s%.2d%s", TraySave.szDiskName, iTemperature2, TraySave.szUsageMEMUnit);
					else if (TraySave.iMonitorSimple == 1)
						wsprintf(sz, L"%.2d%%", iTemperature2);
					else
						wsprintf(sz, L"%.2d", iTemperature2);
				}
				else
				{
					if (TraySave.iMonitorSimple == 0)
						wsprintf(sz, L"%s%.2d%s", TraySave.szTemperatureGPU, iTemperature2, TraySave.szTemperatureGPUUnit);
					else if (TraySave.iMonitorSimple == 1)
						wsprintf(sz, L"%.2d℃", iTemperature2);
					else
						wsprintf(sz, L"%.2d", iTemperature2);
				}
				if (VTray && (TraySave.bMonitorFloat == FALSE|| TraySave.bMonitorFloatVRow))
					DrawShadowText(mdc, sz, lstrlen(sz), &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				else
					DrawShadowText(mdc, sz, lstrlen(sz), &crc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);

			}
			if (TraySave.bMonitorDisk)
			{
				RECT crc = rc;
				if (VTray && (TraySave.bMonitorFloat == FALSE || TraySave.bMonitorFloatVRow))
				{
					if (TraySave.bMonitorTraffic)
						crc.top = wHeight * 2;
					if (TraySave.bMonitorTemperature)
					{
						crc.top += wHeight;
						if (bRing0)
							crc.top += wHeight;
					}
					if (TraySave.bMonitorUsage)
						crc.top += wHeight * 2;
					crc.bottom = crc.top + wHeight;
					if (TraySave.bMonitorTrafficUpDown)
						DrawDisk(mdc, &crc, diskreadbyte, FALSE);
					else
						DrawDisk(mdc, &crc, diskwritebyte, TRUE);
					OffsetRect(&crc, 0, wHeight);
					if (TraySave.bMonitorTrafficUpDown)
						DrawDisk(mdc, &crc, diskwritebyte, TRUE);
					else
						DrawDisk(mdc, &crc, diskreadbyte, FALSE);
				}
				else
				{
					crc.left = crc.left + wTraffic + wTemperature + wUsage;
					crc.right = crc.left + wDisk;
					crc.bottom /= 2;
					if (TraySave.bMonitorTrafficUpDown)
						DrawDisk(mdc, &crc, diskreadbyte, FALSE);
					else
						DrawDisk(mdc, &crc, diskwritebyte, TRUE);
					OffsetRect(&crc, 0, crc.bottom);
					if (TraySave.bMonitorTrafficUpDown)
						DrawDisk(mdc, &crc, diskwritebyte, TRUE);
					else
						DrawDisk(mdc, &crc, diskreadbyte, FALSE);
				}
			}
			if(TraySave.bMonitorTime)
			{
				SetTextColor(mdc, TraySave.cMonitorColor[1]);
				SYSTEMTIME systm;
				GetLocalTime(&systm);
				RECT crc = rc;
				crc.bottom /= 2;
				TCHAR szWeek[7][2] = { L"日",L"一",L"二",L"三",L"四",L"五",L"六" };
				wsprintf(sz, L"%.2d/%.2d'%s",systm.wMonth,systm.wDay,szWeek[systm.wDayOfWeek]);
				int sLen = lstrlen(sz);
				if (VTray && (TraySave.bMonitorFloat == FALSE || TraySave.bMonitorFloatVRow))
				{
					if (TraySave.bMonitorTraffic)
						crc.top = wHeight * 2;
					if (TraySave.bMonitorTemperature)
					{
						crc.top += wHeight;
						if (bRing0)
							crc.top += wHeight;
					}
					if(TraySave.bMonitorUsage)
						crc.top += wHeight*2;
					if (TraySave.bMonitorDisk)
						crc.top += wHeight * 2;
					crc.bottom = crc.top + wHeight;
					DrawShadowText(mdc, sz, sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				else
					DrawShadowText(mdc, sz, sLen, &crc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				wsprintf(sz, L"%.2d:%.2d:%.2d", systm.wHour, systm.wMinute, systm.wSecond);
				sLen = lstrlen(sz);
				if (VTray && (TraySave.bMonitorFloat == FALSE || TraySave.bMonitorFloatVRow))
				{
					OffsetRect(&crc, 0, wHeight);
					DrawShadowText(mdc, sz, (int)sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				else
				{
					OffsetRect(&crc, 0, crc.bottom);
					DrawShadowText(mdc, sz, (int)sLen, &crc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE, bColor, bShadow);
				}
				
				
			}
			SelectObject(mdc, oldFont);
		}
		//		GetClientRect(hDlg, &rc);
		InflateRect(&rc, 1, 1);
		/*
				BLENDFUNCTION bf1;
				bf1.BlendOp = AC_SRC_OVER;
				bf1.BlendFlags = 0;
				bf1.SourceConstantAlpha = 88;
				bf1.AlphaFormat = AC_SRC_ALPHA;
				::AlphaBlend(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, bf1);
		*/
//		if (TraySave.bMonitorFuse)/////////////////背景融合
		{
			BYTE* lpvBits = NULL;

			BITMAPINFO binfo;
			memset(&binfo, 0, sizeof(BITMAPINFO));
			binfo.bmiHeader.biBitCount = 32;     //每个像素多少位，也可直接写24(RGB)或者32(RGBA)
			binfo.bmiHeader.biCompression = 0;
			binfo.bmiHeader.biHeight = rc.bottom - rc.top;
			binfo.bmiHeader.biPlanes = 1;
			binfo.bmiHeader.biSizeImage = (rc.bottom - rc.top) * (rc.right - rc.left) * 4;
			binfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
			binfo.bmiHeader.biWidth = rc.right - rc.left;
			lpvBits = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, binfo.bmiHeader.biSizeImage);
			//		GetDIBits(mdc, hMemBmp, 0, rc.bottom - rc.top, lpvBits, &bmpInfo, DIB_RGB_COLORS);

			GetDIBits(mdc, hMemBmp, 0, rc.bottom - rc.top, lpvBits, &binfo, DIB_RGB_COLORS);
			for (DWORD i = 0; i < binfo.bmiHeader.biSizeImage - 4; i += 4)
			{
				if (lpvBits[i] > 3 || lpvBits[i + 1] > 3 || lpvBits[i + 2] > 3)
				{
					if(TraySave.bMonitorFuse)
						lpvBits[i + 3] = 0x80;
					else if(TraySave.bMonitorFloat)
						lpvBits[i + 3] = 0xff;
				}
			}
			SetDIBits(mdc, hMemBmp, 0, rc.bottom - rc.top, lpvBits, &binfo, DIB_RGB_COLORS);
			HeapFree(GetProcessHeap(), 0, lpvBits);
		}
		BitBlt(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mdc, 0, 0, SRCCOPY);
		SelectObject(mdc, oldBmp);
		DeleteObject(hMemBmp);
		DeleteDC(mdc);
		//		EndPaint(hDlg, &ps);

		return TRUE;
	}
	break;
	}
	return FALSE;
}

INT_PTR CALLBACK MainProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)//主窗口过程
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case MSG_APPBAR_MSGID:
		if (wParam == ABN_FULLSCREENAPP)
		{
			if (TraySave.bMonitorTopmost && !TraySave.bMonitorFloat)
			{
				if (lParam == FALSE)
				{
					if (bFullScreen)
					{
						DestroyWindow(hTaskBar);
					}
				}
				else
				{
					if (!bFullScreen)
					{
						DestroyWindow(hTaskBar);
					}
				}
			}
			bFullScreen = lParam;
		}
		break;
	case WM_INITDIALOG:
		SetTimer(hDlg, 88, 8888,NULL);
		return (INT_PTR)TRUE;
		/*
			case WM_ENDSESSION:
				if (lParam == ENDSESSION_LOGOFF)
				{
					DestroyWindow(hTray);
					RunProcess(NULL);
					return TRUE;
				}
				break;
		*/
	case WM_TRAYS:
		if(bSetting)
			OpenSetting();
		break;
	case 0x02e0://WM_DPICHANGED:
//	case WM_DPICHANGED_AFTERPARENT:
//	case WM_DPICHANGED_BEFOREPARENT:
	{
		iDPI = LOWORD(wParam);
		bResetRun = TRUE;
		PostQuitMessage(0);
//		SetTimer(hDlg, 8, 1000, NULL);
	}
	break;
	case WM_CLOSE:
	{
		KillTimer(hDlg, 6);
		KillTimer(hDlg, 3);
		SendMessage(hReBarWnd, WM_SETREDRAW, TRUE, 0);
		HWND hSecondaryTray;
		hSecondaryTray = FindWindow(szSecondaryTray, NULL);
		while (hSecondaryTray)
		{
			HWND hSReBarWnd = FindWindowEx(hSecondaryTray, 0, L"WorkerW", NULL);
			SendMessage(hSReBarWnd, WM_SETREDRAW, TRUE, 0);
			ShowWindow(hSReBarWnd, SW_SHOWNOACTIVATE);
			hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
		}
		ShowWindow(hTaskListWnd, SW_SHOW);
		PostQuitMessage(0);
	}
	break;
	case WM_TIMER:
	{
		if(wParam==88)
		{
			KillTimer(hDlg,wParam);
			bSetting = TRUE;
		}
		else if (wParam == 8)//DPI重置
		{
			KillTimer(hDlg, wParam);
			DestroyWindow(hTime);
			SetWH();			
//			OpenTimeDlg();
		}
		else if(wParam==3000)
			GetShellAllWnd();
		else if (wParam == 11)//释放内存
		{
			KillTimer(hDlg, wParam);
			SetTimer(hDlg, wParam, 60000, NULL);
			HANDLE hProcess = GetCurrentProcess();
			SetProcessWorkingSetSize(hProcess, -1, -1);
			EmptyWorkingSet(hProcess);
		}
		else if (wParam == 6)//处理任务栏图标与信息窗口
		{
			if (TraySave.bMonitor)
			{
				//				if (!bTaskBarMoveing)
				//					AdjustWindowPos();
				if (IsWindowVisible(hTaskTips))
					::InvalidateRect(hTaskTips, NULL, TRUE);
				DWORD dm = GetSystemUsesLightTheme();
				if (dm != bThemeMode)
				{
					DestroyWindow(hTime);
					DestroyWindow(hTaskBar);
					bThemeMode = dm;
				}

			}
			if ((TraySave.iPos != 0 || TraySave.bMonitor) && hWin11UI == NULL&&rovi.dwBuildNumber<22000)
			{
				//				if (TraySave.bTaskIcon == FALSE)
				{					
					SetTaskBarPos(hTaskListWnd, hTray, hTaskWnd, hReBarWnd, TRUE);
				}
				HWND hSecondaryTray;
				hSecondaryTray = FindWindow(szSecondaryTray, NULL);
				while (hSecondaryTray)
				{
					HWND hSReBarWnd = FindWindowEx(hSecondaryTray, 0, L"WorkerW", NULL);
					if (hSReBarWnd)
					{
						HWND hSTaskListWnd = FindWindowEx(hSReBarWnd, NULL, L"MSTaskListWClass", NULL);
						if (hSTaskListWnd)
						{
							SetTaskBarPos(hSTaskListWnd, hSecondaryTray, hSReBarWnd, hSReBarWnd, FALSE);
						}
					}
					hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
				}
			}
		}
		else if (wParam == 3)//处理任务栏风格
		{
			if (TraySave.bMonitor)
			{
				if (!bTaskBarMoveing)
				{
					AdjustWindowPos();
				}
			}
			//			if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
			{
				int oldWindowMode = iWindowMode;
				if (hTray)
				{
					if (iProject == 0)
						iWindowMode = 0;
					else if (iProject == 1)
						iWindowMode = 1;
					else
					{
						iWindowMode = 0;
						EnumWindows(IsZoomedFunc, (LPARAM)MonitorFromWindow(hTray, MONITOR_DEFAULTTONEAREST));
					}
					if (TraySave.aMode[iWindowMode] != ACCENT_DISABLED || oldWindowMode != iWindowMode)
					{
						SetWindowCompositionAttribute(hTray, TraySave.aMode[iWindowMode], TraySave.dAlphaColor[iWindowMode]);
//						HWND hTray11=FindWindowEx(hTray, 0, L"Windows.UI.Composition.DesktopWindowContentBridge",NULL);
//						SetWindowCompositionAttribute(hTray11, TraySave.aMode[iWindowMode], TraySave.dAlphaColor[iWindowMode]);
					}
					LONG_PTR exStyle = GetWindowLongPtr(hTray, GWL_EXSTYLE);
					exStyle |= WS_EX_LAYERED;
					SetWindowLongPtr(hTray, GWL_EXSTYLE, exStyle);
					SetLayeredWindowAttributes(hTray, 0, (BYTE)TraySave.bAlpha[iWindowMode], LWA_ALPHA);
				}
				HWND hSecondaryTray = FindWindow(szSecondaryTray, NULL);
				while (hSecondaryTray)
				{
					if (iProject == 0)
						iWindowMode = 0;
					else if (iProject == 1)
						iWindowMode = 1;
					else
					{
						iWindowMode = 0;
						EnumWindows(IsZoomedFunc, (LPARAM)MonitorFromWindow(hSecondaryTray, MONITOR_DEFAULTTONEAREST));
					}
					if (TraySave.aMode[iWindowMode] != ACCENT_DISABLED || oldWindowMode != iWindowMode)
						SetWindowCompositionAttribute(hSecondaryTray, TraySave.aMode[iWindowMode], TraySave.dAlphaColor[iWindowMode]);
					LONG_PTR exStyle = GetWindowLongPtr(hSecondaryTray, GWL_EXSTYLE);
					exStyle |= WS_EX_LAYERED;
					SetWindowLongPtr(hSecondaryTray, GWL_EXSTYLE, exStyle);
					SetLayeredWindowAttributes(hSecondaryTray, 0, (BYTE)TraySave.bAlpha[iWindowMode], LWA_ALPHA);
					hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
				}
			}
			//			if (TraySave.aMode[0] == ACCENT_DISABLED && TraySave.aMode[1] == ACCENT_DISABLED)//默认则关闭定时器
			//				KillTimer(hDlg, 3);
		}
	}
	break;
	case WM_IAWENTRAY://////////////////////////////////////////////////////////////////////////////////通知栏左右键处理
	{
		if (wParam == WM_IAWENTRAY)
		{
			if (lParam == WM_LBUTTONDOWN || lParam == WM_RBUTTONDOWN)
			{
				OpenSetting();
			}
		}
		break;
	}
	break;
	}
	return FALSE;
}
INT_PTR CALLBACK SettingProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)//设置窗口过程
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;
	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->code)
		{
		case NM_CLICK:
		case NM_RETURN:
		{
			HWND g_hLink = GetDlgItem(hDlg, IDC_SYSLINK);
			PNMLINK pNMLink = (PNMLINK)lParam;
			LITEM item = pNMLink->item;
			if ((((LPNMHDR)lParam)->hwndFrom == g_hLink) && (item.iLink == 0))
			{
				CloseHandle(pShellExecute(NULL, L"open", L"http://810619.xyz:888/index.php?share/folder&user=1&sid=ZS4yPCWN", NULL, NULL, SW_SHOW));
				//CloseHandle(pShellExecute(NULL, L"open", L"https://gitee.com/cgbsmy/TrayS", NULL, NULL, SW_SHOW));
				//mailto:cgbsmy@live.com?subject=TrayS
			}
			else
			{
				CloseHandle(pShellExecute(NULL, L"open", L"https://www.52pojie.cn/thread-1182669-1-1.html", NULL, NULL, SW_SHOW));
			}
			break;
		}
		}
		break;
	case WM_HSCROLL://////////////////////////////////////////////////////////////////////////////////透明度处理
	{
		HWND hSlider = GetDlgItem(hDlg, IDC_SLIDER_ALPHA);
		HWND hSliderB = GetDlgItem(hDlg, IDC_SLIDER_ALPHA_B);
		if (hSlider == (HWND)lParam)
		{
			TraySave.bAlpha[iProject] = (int)SendDlgItemMessage(hDlg, IDC_SLIDER_ALPHA, TBM_GETPOS, 0, 0);
		}
		else if (hSliderB == (HWND)lParam)
		{
			DWORD bAlphaB = (int)SendDlgItemMessage(hDlg, IDC_SLIDER_ALPHA_B, TBM_GETPOS, 0, 0);
			bAlphaB = bAlphaB << 24;
			TraySave.dAlphaColor[iProject] = bAlphaB + (TraySave.dAlphaColor[iProject] & 0xffffff);
		}
		SetTimer(hDlg, 3, 500, NULL);
		break;
	}
	case WM_TIMER:
		if (wParam == 3)
		{
			KillTimer(hDlg, wParam);
			WriteReg();
		}
		break;
	case WM_COMMAND:
		if (HIWORD(wParam) == EN_CHANGE && !bSettingInit)
		{
			if (LOWORD(wParam) >= IDC_EDIT1 && LOWORD(wParam) <= IDC_EDIT12)
			{
				int index = LOWORD(wParam) - IDC_EDIT1;
				TraySave.dNumValues[index] = GetDlgItemInt(hDlg, LOWORD(wParam), NULL, 0);
				if (index == 0 || index == 1 || index == 8)
					TraySave.dNumValues[index] *= 1048576;
				SetTimer(hDlg, 3, 500, NULL);
			}
			else if (LOWORD(wParam) >= IDC_EDIT24 && LOWORD(wParam) <= IDC_EDIT26)
			{
				int index = LOWORD(wParam) - IDC_EDIT24;
				TraySave.dNumValues2[index] = GetDlgItemInt(hDlg, LOWORD(wParam), NULL, 0);
				SetTimer(hDlg, 3, 500, NULL);
			}
			else if (LOWORD(wParam) == IDC_EDIT_TIME)
			{
				TraySave.FlushTime = GetDlgItemInt(hDlg, LOWORD(wParam), NULL, 0);
				if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
					SetTimer(hMain, 3, TraySave.FlushTime, NULL);
				SetTimer(hDlg, 3, 500, NULL);
			}
			else if ((LOWORD(wParam) >= IDC_EDIT14 && LOWORD(wParam) <= IDC_EDIT23)||LOWORD(wParam)==IDC_EDIT27|| LOWORD(wParam) == IDC_EDIT29)
			{
				GetDlgItemText(hDlg, IDC_EDIT14, TraySave.szTrafficOut, 8);
				GetDlgItemText(hDlg, IDC_EDIT15, TraySave.szTrafficIn, 8);
				GetDlgItemText(hDlg, IDC_EDIT16, TraySave.szTemperatureCPU, 8);
				GetDlgItemText(hDlg, IDC_EDIT17, TraySave.szTemperatureGPU, 8);
				GetDlgItemText(hDlg, IDC_EDIT18, TraySave.szTemperatureCPUUnit, 4);
				GetDlgItemText(hDlg, IDC_EDIT19, TraySave.szTemperatureGPUUnit, 4);
				GetDlgItemText(hDlg, IDC_EDIT20, TraySave.szUsageCPU, 8);
				GetDlgItemText(hDlg, IDC_EDIT21, TraySave.szUsageMEM, 8);
				GetDlgItemText(hDlg, IDC_EDIT22, TraySave.szUsageCPUUnit, 4);
				GetDlgItemText(hDlg, IDC_EDIT23, TraySave.szUsageMEMUnit, 4);
				GetDlgItemText(hDlg, IDC_EDIT27, TraySave.szDiskReadSec, 8);
				GetDlgItemText(hDlg, IDC_EDIT28, TraySave.szDiskWriteSec, 8);
				GetDlgItemText(hDlg, IDC_EDIT29, TraySave.szDiskName, 8);
				SetTimer(hDlg, 3, 1500, NULL);
				if (TraySave.iMonitorSimple == 0)
					SetWH();
			}			
		}
		else if (LOWORD(wParam) >= IDC_RADIO_DEFAULT && LOWORD(wParam) <= IDC_RADIO_ACRYLIC)
		{
			iWindowMode = !iWindowMode;
			if (IsDlgButtonChecked(hDlg, IDC_RADIO_DEFAULT))
				TraySave.aMode[iProject] = ACCENT_DISABLED;
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_TRANSPARENT))
				TraySave.aMode[iProject] = ACCENT_ENABLE_TRANSPARENTGRADIENT;
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_BLURBEHIND))
				TraySave.aMode[iProject] = ACCENT_ENABLE_BLURBEHIND;
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_ACRYLIC))
				TraySave.aMode[iProject] = ACCENT_ENABLE_ACRYLICBLURBEHIND;
			WriteReg();
			if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
				SetTimer(hMain, 3, TraySave.FlushTime, NULL);
			//			else
			//				KillTimer(hMain, 3);

		}
		else if (LOWORD(wParam) >= IDC_RADIO_LEFT && LOWORD(wParam) <= IDC_RADIO_RIGHT)
		{
			if (IsDlgButtonChecked(hDlg, IDC_RADIO_LEFT))
			{
				TraySave.iPos = 0;
			}
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_CENTER))
			{
				TraySave.iPos = 1;
			}
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_RIGHT))
			{
				TraySave.iPos = 2;
			}
			WriteReg();
		}
		else if (LOWORD(wParam) >= IDC_RADIO_BYTE && LOWORD(wParam) <= IDC_RADIO_MB)
		{
			if (IsDlgButtonChecked(hDlg, IDC_RADIO_AUTO))
				TraySave.iUnit = 0;
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_KB))
				TraySave.iUnit = 1;
			else if (IsDlgButtonChecked(hDlg, IDC_RADIO_MB))
				TraySave.iUnit = 2;
			if (IsDlgButtonChecked(hDlg, IDC_RADIO_BIT))
				TraySave.iUnit |= 0x10000;
			WriteReg();
		}
		if (LOWORD(wParam) == IDC_RADIO_NORMAL || LOWORD(wParam) == IDC_RADIO_MAXIMIZE)
		{
			if (IsDlgButtonChecked(hDlg, IDC_RADIO_NORMAL))
				iProject = 0;
			else
				iProject = 1;
			if (TraySave.aMode[iProject] == ACCENT_DISABLED)
				CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_DEFAULT);
			else if (TraySave.aMode[iProject] == ACCENT_ENABLE_TRANSPARENTGRADIENT)
				CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_TRANSPARENT);
			else if (TraySave.aMode[iProject] == ACCENT_ENABLE_BLURBEHIND)
				CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_BLURBEHIND);
			else if (TraySave.aMode[iProject] == ACCENT_ENABLE_ACRYLICBLURBEHIND)
				CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_ACRYLIC);
			SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA, TBM_SETPOS, TRUE, TraySave.bAlpha[iProject]);
			BYTE bAlphaB = TraySave.dAlphaColor[iProject] >> 24;
			SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA_B, TBM_SETPOS, TRUE, bAlphaB);
			::InvalidateRect(GetDlgItem(hSetting, IDC_BUTTON_COLOR), NULL, FALSE);
		}
		else if (LOWORD(wParam) == IDC_CHECK_SOUND)
		{
			TraySave.bSound = IsDlgButtonChecked(hDlg, IDC_CHECK_SOUND);
			WriteReg();
		}
		else if (LOWORD(wParam) == IDC_CHECK_TIPS)
		{
			TraySave.bMonitorTips = IsDlgButtonChecked(hDlg, IDC_CHECK_TIPS);
			WriteReg();
		}
		else if (LOWORD(wParam) == IDC_CHECK_FUSE)
		{
			TraySave.bMonitorFuse = IsDlgButtonChecked(hDlg, IDC_CHECK_FUSE);
			WriteReg();
		}
		else if (LOWORD(wParam) == IDC_CHECK_TRAYICON)
		{
			TraySave.bTrayIcon = IsDlgButtonChecked(hDlg, IDC_CHECK_TRAYICON);
			WriteReg();
			CloseTaskBar();
			if (TraySave.bTrayIcon)
				pShell_NotifyIcon(NIM_ADD, &nid);
			else
				pShell_NotifyIcon(NIM_DELETE, &nid);
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR)
		{
			TraySave.bMonitor = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR);
			WriteReg();
			if (!TraySave.bMonitor)
			{
				CloseTaskBar();
			}
		}
		else if (LOWORD(wParam) == IDC_CHECK_TRAFFIC)
		{
			TraySave.bMonitorTraffic = IsDlgButtonChecked(hDlg, IDC_CHECK_TRAFFIC);
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_UPDOWN)
		{
			TraySave.bMonitorTrafficUpDown = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_UPDOWN);
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_TEMPERATURE)
		{
			TraySave.bMonitorTemperature = IsDlgButtonChecked(hDlg, IDC_CHECK_TEMPERATURE);
			if (TraySave.bMonitorTemperature)
				LoadTemperatureDLL();
			else
				FreeTemperatureDLL();
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_SIMPLE)
		{
			TraySave.iMonitorSimple = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_SIMPLE);
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_USAGE)
		{
			TraySave.bMonitorUsage = IsDlgButtonChecked(hDlg, IDC_CHECK_USAGE);
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_DISK)
		{
			TraySave.bMonitorDisk = IsDlgButtonChecked(hDlg, IDC_CHECK_DISK);
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_PDH)
		{
			TraySave.bMonitorPDH = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_PDH);
			WriteReg();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_LEFT)
		{
			TraySave.bMonitorLeft = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_LEFT);
			WriteReg();
			AdjustWindowPos();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_NEAR)
		{
			TraySave.bNear = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_NEAR);
			WriteReg();
			AdjustWindowPos();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_FLOAT)
		{
			TraySave.bMonitorFloat = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_FLOAT);
			WriteReg();
			CloseTaskBar();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_FLOAT_VROW)
		{
			TraySave.bMonitorFloatVRow = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_FLOAT_VROW);
			WriteReg();
			CloseTaskBar();
		}
		else if (LOWORD(wParam) == IDC_CHECK_MONITOR_TIME)
		{
			TraySave.bMonitorTime = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_TIME);
			WriteReg();
			SetWH();
		}
		else if (LOWORD(wParam) == IDC_CHECK_TIME)
		{
			TraySave.bSecond = IsDlgButtonChecked(hDlg, IDC_CHECK_TIME);
			WriteReg();
			if(TraySave.bSecond)
				OpenTimeDlg();
			else
				DestroyWindow(hTime);
		}
		else if (LOWORD(wParam) == IDC_CHECK_TRANSPARENT)
		{
			TraySave.bMonitorTransparent = IsDlgButtonChecked(hDlg, IDC_CHECK_TRANSPARENT);
			if (TraySave.bMonitorTransparent)
				SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) | WS_EX_TRANSPARENT | WS_EX_LAYERED);
			else
				SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) & ~WS_EX_TRANSPARENT);
			WriteReg();
		}
		else if (LOWORD(wParam) == IDC_CHECK_TOPMOST)
		{
			TraySave.bMonitorTopmost = IsDlgButtonChecked(hDlg, IDC_CHECK_TOPMOST);
			WriteReg();
		}
		else if (LOWORD(wParam) == IDC_CHECK_AUTORUN)
		{
			if (IsDlgButtonChecked(hDlg, IDC_CHECK_AUTORUN))
				AutoRun(TRUE, TRUE, szAppName);
			else
				AutoRun(TRUE, FALSE, szAppName);
		}
		else if (LOWORD(wParam) == IDC_RESTORE_DEFAULT)
		{
			DeleteFile(szTraySave);
			//			RegDeleteKey(HKEY_CURRENT_USER, szSubKey);
			SendMessage(hDlg, WM_COMMAND, IDCANCEL, 0);
		}
		else if (LOWORD(wParam) == IDCANCEL)
		{
			/*
						SendMessage(hMain, WM_TIMER, 11, 1000);
						DestroyWindow(hDlg);
						return (INT_PTR)TRUE;
			*/
			//			SendMessage(hReBarWnd, WM_SETREDRAW, TRUE, 0);
			bResetRun = TRUE;
			SendMessage(hMain, WM_CLOSE, NULL, NULL);
			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_CLOSE)
		{
			SendMessage(hMain, WM_CLOSE, NULL, NULL);
		}
		else if (LOWORD(wParam) == IDC_BUTTON_FONT || LOWORD(wParam) == IDC_BUTTON_TIPS_FONT)
		{
			typedef UINT_PTR(CALLBACK* LPCFHOOKPROC) (HWND, UINT, WPARAM, LPARAM);
			typedef struct tagCHOOSEFONTW {
				DWORD           lStructSize;
				HWND            hwndOwner;          // caller's window handle
				HDC             hDC;                // printer DC/IC or NULL
				LPLOGFONTW      lpLogFont;          // ptr. to a LOGFONT struct
				INT             iPointSize;         // 10 * size in points of selected font
				DWORD           Flags;              // enum. type flags
				COLORREF        rgbColors;          // returned text color
				LPARAM          lCustData;          // data passed to hook fn.
				LPCFHOOKPROC    lpfnHook;           // ptr. to hook function
				LPCWSTR         lpTemplateName;     // custom template name
				HINSTANCE       hInstance;          // instance handle of.EXE that
													//   contains cust. dlg. template
				LPWSTR          lpszStyle;          // return the style field here
													// must be LF_FACESIZE or bigger
				WORD            nFontType;          // same value reported to the EnumFonts
													//   call back with the extra FONTTYPE_
													//   bits added
				WORD            ___MISSING_ALIGNMENT__;
				INT             nSizeMin;           // minimum pt size allowed &
				INT             nSizeMax;           // max pt size allowed if
													//   CF_LIMITSIZE is used
			} CHOOSEFONT;
			TraySave.TraybarFont.lfHeight = TraySave.TraybarFontSize;
			TraySave.TipsFont.lfHeight = TraySave.TipsFontSize;
			CHOOSEFONT cf;
			cf.lStructSize = sizeof cf;
			cf.hwndOwner = hDlg;
			cf.hDC = NULL;
			if (LOWORD(wParam) == IDC_BUTTON_FONT)
				cf.lpLogFont = &TraySave.TraybarFont;
			else
				cf.lpLogFont = &TraySave.TipsFont;
			cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT | CF_EFFECTS;
			cf.nFontType = SCREEN_FONTTYPE;
			cf.rgbColors = RGB(0, 0, 0);
			typedef BOOL(WINAPI* pfnChooseFont)(CHOOSEFONT* lpcf);
			HMODULE hComdlg32 = LoadLibrary(L"comdlg32.dll");
			if (hComdlg32)
			{
				pfnChooseFont ChooseFont = (pfnChooseFont)GetProcAddress(hComdlg32, "ChooseFontW");
				if (ChooseFont)
				{
					if (ChooseFont(&cf))
					{
						if (LOWORD(wParam) == IDC_BUTTON_FONT)
						{
							TraySave.TraybarFontSize = TraySave.TraybarFont.lfHeight;
							otleft = -1;
							SetWH();
						}
						else
							TraySave.TipsFontSize = TraySave.TipsFont.lfHeight;
						WriteReg();
					}
				}
				FreeLibrary(hComdlg32);
			}
		}
		else if (LOWORD(wParam) == IDC_BUTTON_COLOR || (LOWORD(wParam) >= IDC_BUTTON_COLOR_BACKGROUND && LOWORD(wParam) <= IDC_BUTTON_COLOR_HIGH))
		{
			CHOOSECOLOR stChooseColor;
			stChooseColor.lStructSize = sizeof(CHOOSECOLOR);
			stChooseColor.hwndOwner = hDlg;
			if (LOWORD(wParam) == IDC_BUTTON_COLOR)
			{
				stChooseColor.rgbResult = TraySave.dAlphaColor[iProject];
				stChooseColor.lpCustColors = (LPDWORD)&TraySave.dAlphaColor[iProject];
			}
			else
			{
				stChooseColor.rgbResult = TraySave.cMonitorColor[LOWORD(wParam) - IDC_BUTTON_COLOR_BACKGROUND];
				stChooseColor.lpCustColors = TraySave.cMonitorColor;
			}
			stChooseColor.Flags = CC_RGBINIT | CC_FULLOPEN;
			stChooseColor.lCustData = 0;
			stChooseColor.lpfnHook = NULL;
			stChooseColor.lpTemplateName = NULL;
			typedef BOOL(WINAPI* pfnChooseColor)(LPCHOOSECOLOR lpcc);
			HMODULE hComdlg32 = LoadLibrary(L"comdlg32.dll");
			if (hComdlg32)
			{
				pfnChooseColor ChooseColor = (pfnChooseColor)GetProcAddress(hComdlg32, "ChooseColorW");
				if (ChooseColor)
				{
					if (ChooseColor(&stChooseColor))
					{
						if (LOWORD(wParam) == IDC_BUTTON_COLOR)
						{
							TraySave.dAlphaColor[iProject] = stChooseColor.rgbResult;
							DWORD bAlphaB = (int)SendDlgItemMessage(hDlg, IDC_SLIDER_ALPHA_B, TBM_GETPOS, 0, 0);
							bAlphaB = bAlphaB << 24;
							TraySave.dAlphaColor[iProject] = bAlphaB + (TraySave.dAlphaColor[iProject] & 0xffffff);
						}
						else
						{

							TraySave.cMonitorColor[LOWORD(wParam - IDC_BUTTON_COLOR_BACKGROUND)] = stChooseColor.rgbResult;
							if (TraySave.cMonitorColor[0] == 0 || TraySave.cMonitorColor[0] == RGB(0, 0, 1))
							{
								TraySave.cMonitorColor[0] = RGB(0, 0, 1);
//								if (TraySave.bMonitorFloat||rovi.dwBuildNumber<=22000)
								{
									bShadow = TRUE;
									TraySave.bMonitorFuse = TRUE;
								}
							}
							else
								bShadow = FALSE;
						}
						::InvalidateRect(GetDlgItem(hMain, LOWORD(wParam)), NULL, FALSE);
					}
				}
				FreeLibrary(hComdlg32);
			}
			WriteReg();
			//			SendMessage(hMain, WM_TRAYS, NULL, NULL);
		}
		break;
	}
	return (INT_PTR)FALSE;
}
INT_PTR CALLBACK ColorButtonProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)//颜色按钮控件过程
{
	switch (message)
	{
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		RECT rc;
		GetClientRect(hWnd, &rc);
		HBRUSH hb;
		int id = GetDlgCtrlID(hWnd);
		if (id >= IDC_BUTTON_COLOR_BACKGROUND && id <= IDC_BUTTON_COLOR_HIGH)
		{
			hb = CreateSolidBrush(TraySave.cMonitorColor[id - IDC_BUTTON_COLOR_BACKGROUND]);
		}
		else
			hb = CreateSolidBrush(TraySave.dAlphaColor[iProject] & 0xffffff);
		FillRect(hdc, &rc, hb);
		DeleteObject(hb);
		EndPaint(hWnd, &ps);
		return TRUE;
	}
	}
	return CallWindowProc(oldColorButtonPoroc, hWnd, message, wParam, lParam);
}