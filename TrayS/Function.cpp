#include "Function.h"
////////////////////////////////////////////////////动态运行函数
HRESULT pSHLoadIndirectString(LPCWSTR pszSource, LPWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved)
{
	HRESULT ret = NULL;
	typedef UINT(WINAPI* pfnSHLoadIndirectString)(LPCWSTR pszSource, LPWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved);
	HMODULE hShell32 = LoadLibrary(L"Shlwapi.dll");
	if (hShell32)
	{
		pfnSHLoadIndirectString pSHLoadIndirectStringW = (pfnSHLoadIndirectString)GetProcAddress(hShell32, "SHLoadIndirectString");
		if (pSHLoadIndirectStringW)
		{
			ret = pSHLoadIndirectStringW(pszSource, pszOutBuf, cchOutBuf, ppvReserved);
		}
		FreeLibrary(hShell32);
	}
	return ret;
}
UINT  pDragQueryFile(HDROP hDrop, UINT iFile, LPTSTR lpszFile, UINT cch)
{
	UINT ret = NULL;
	typedef UINT(WINAPI* pfnDragQueryFile)(HDROP hDrop, UINT iFile, LPTSTR lpszFile, UINT cch);
	HMODULE hShell32 = LoadLibrary(L"shell32.dll");
	if (hShell32)
	{
		pfnDragQueryFile pDragQueryFileW = (pfnDragQueryFile)GetProcAddress(hShell32, "DragQueryFileW");
		if (pDragQueryFileW)
		{
			ret = pDragQueryFileW(hDrop, iFile, lpszFile, cch);
		}
		FreeLibrary(hShell32);
	}
	return ret;
}
HICON  pExtractIcon(HINSTANCE hInst, LPCTSTR lpszExeFileName, UINT nIconIndex)
{
	//IExtractIcon
	HICON ret = NULL;
	typedef HICON(WINAPI* pfnExtractIcon)(HINSTANCE hInst, LPCTSTR lpszExeFileName, UINT nIconIndex);
	HMODULE hShell32 = LoadLibrary(L"shell32.dll");
	if (hShell32)
	{
		pfnExtractIcon pExtractIconW = (pfnExtractIcon)GetProcAddress(hShell32, "ExtractIconW");
		if (pExtractIconW)
		{
			ret = pExtractIconW(hInst, lpszExeFileName, nIconIndex);
		}
		FreeLibrary(hShell32);
	}
	return ret;
}
DWORD pSHGetFileInfo(LPCTSTR pszPath, DWORD dwFileAttributes, SHFILEINFO FAR* psfi, UINT cbFileInfo, UINT uFlags)
{
	//IExtractIcon
	DWORD ret = NULL;
	typedef DWORD(WINAPI* pfnSHGetFileInfo)(LPCTSTR pszPath, DWORD dwFileAttributes, SHFILEINFO FAR* psfi, UINT cbFileInfo, UINT uFlags);
	HMODULE hShell32 = LoadLibrary(L"shell32.dll");
	if (hShell32)
	{
		pfnSHGetFileInfo pSHGetFileInfoW = (pfnSHGetFileInfo)GetProcAddress(hShell32, "SHGetFileInfoW");
		if (pSHGetFileInfoW)
		{
			ret = pSHGetFileInfoW(pszPath, dwFileAttributes, psfi, cbFileInfo, uFlags);

		}
		FreeLibrary(hShell32);
	}
	return ret;
}
HRESULT  pSHDefExtractIcon(LPCWSTR pszIconFile,int iIndex,UINT uFlags,HICON* phiconLarge,HICON* phiconSmall,UINT nIconSize)
{
	//IExtractIcon
	HRESULT ret = NULL;
	typedef HRESULT(WINAPI* pfnSHDefExtractIcon)(LPCWSTR pszIconFile, int iIndex, UINT uFlags, HICON* phiconLarge, HICON* phiconSmall, UINT nIconSize);
	HMODULE hShell32 = LoadLibrary(L"shell32.dll");
	if (hShell32)
	{
		pfnSHDefExtractIcon SHDefExtractIconW = (pfnSHDefExtractIcon)GetProcAddress(hShell32, "SHDefExtractIconW");
		if (SHDefExtractIconW)
		{
			ret = SHDefExtractIconW(pszIconFile, iIndex, uFlags, phiconLarge, phiconSmall, nIconSize);
		}
		FreeLibrary(hShell32);
	}
	return ret;
}
HINSTANCE pShellExecute(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpOperation, _In_ LPCWSTR lpFile, _In_opt_ LPCWSTR lpParameters, _In_opt_ LPCWSTR lpDirectory, _In_ INT nShowCmd)
{
	HINSTANCE hInstance = NULL;
	typedef HINSTANCE(WINAPI* pfnShellExecute)(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpOperation, _In_ LPCWSTR lpFile, _In_opt_ LPCWSTR lpParameters, _In_opt_ LPCWSTR lpDirectory, _In_ INT nShowCmd);
	HMODULE hShell32 = LoadLibrary(L"shell32.dll");
	if (hShell32)
	{
		pfnShellExecute pShellExecuteW = (pfnShellExecute)GetProcAddress(hShell32, "ShellExecuteW");
		if (pShellExecuteW)
			hInstance = pShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
		FreeLibrary(hShell32);
	}
	return hInstance;
}
BOOL pShell_NotifyIcon(DWORD dwMessage, _In_ PNOTIFYICONDATAW lpData)
{
	typedef BOOL(WINAPI* pfnShell_NotifyIcon)(DWORD dwMessage, _In_ PNOTIFYICONDATAW lpData);
	HMODULE hShell32 = LoadLibrary(L"shell32.dll");
	BOOL ret = FALSE;
	if (hShell32)
	{
		pfnShell_NotifyIcon pShell_NotifyIconW = (pfnShell_NotifyIcon)GetProcAddress(hShell32, "Shell_NotifyIconW");
		if (pShell_NotifyIconW)
			ret = pShell_NotifyIconW(dwMessage, lpData);
		FreeLibrary(hShell32);
	}
	return ret;
}
BOOL pWTSQueryUserToken(ULONG SessionId, PHANDLE phToken)
{
	BOOL ret = FALSE;
	typedef BOOL(WINAPI* pfnWTSQueryUserToken)(ULONG SessionId, PHANDLE phToken);
	HMODULE hWTSAPI32 = LoadLibrary(L"wtsapi32.dll");
	if (hWTSAPI32)
	{
		pfnWTSQueryUserToken WTSQueryUserToken = (pfnWTSQueryUserToken)GetProcAddress(hWTSAPI32, "WTSQueryUserToken");
		if (WTSQueryUserToken)
			ret = WTSQueryUserToken(SessionId, phToken);
		FreeLibrary(hWTSAPI32);
	}
	return ret;
}
BOOL pCreateEnvironmentBlock(_At_((PZZWSTR*)lpEnvironment, _Outptr_)LPVOID* lpEnvironment, _In_opt_ HANDLE  hToken, _In_ BOOL bInherit)
{
	BOOL ret = FALSE;
	typedef BOOL(WINAPI* pfnCreateEnvironmentBlock)(_At_((PZZWSTR*)lpEnvironment, _Outptr_)LPVOID* lpEnvironment, _In_opt_ HANDLE  hToken, _In_ BOOL bInherit);
	HMODULE hUserenv = LoadLibrary(L"userenv.dll");
	if (hUserenv)
	{
		pfnCreateEnvironmentBlock CreateEnvironmentBlock = (pfnCreateEnvironmentBlock)GetProcAddress(hUserenv, "CreateEnvironmentBlock");
		if (CreateEnvironmentBlock)
			ret = CreateEnvironmentBlock(lpEnvironment, hToken, bInherit);
		FreeLibrary(hUserenv);
	}
	return ret;
}
ULONG pCallNtPowerInformation(_In_ POWER_INFORMATION_LEVEL InformationLevel, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength)
{
	ULONG ret = -1;
	typedef BOOL(WINAPI* pfnCallNtPowerInformation)(_In_ POWER_INFORMATION_LEVEL InformationLevel, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength);
	HMODULE hPowrptof = LoadLibrary(L"powrprof.dll");
	if (hPowrptof)
	{
		pfnCallNtPowerInformation CallNtPowerInformation = (pfnCallNtPowerInformation)GetProcAddress(hPowrptof, "CallNtPowerInformation");
		if (CallNtPowerInformation)
			ret = CallNtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		FreeLibrary(hPowrptof);
	}
	return ret;
}
BOOL LaunchAppIntoDifferentSession(WCHAR* szExe, WCHAR* szDir, WCHAR* szLine)//以SYSTEM运行程序并可以交互窗口
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	BOOL bResult = FALSE;

	DWORD winlogonPid;
	ULONG dwSessionId;
	HANDLE hUserToken, hUserTokenDup = NULL, hPToken = NULL, hProcess;
	DWORD dwCreationFlags;

	// Log the client on to the local computer.

	dwSessionId = WTSGetActiveConsoleSessionId();

	//////////////////////////////////////////
	   // Find the winlogon process
	////////////////////////////////////////

	PROCESSENTRY32 procEntry;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	procEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnap, &procEntry))
	{
		return FALSE;
	}

	do
	{
		if (lstrcmpi(procEntry.szExeFile, L"winlogon.exe") == 0)
		{
			// We found a winlogon process...
		// make sure it's running in the console session
			DWORD winlogonSessId = 0;
			if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId)
				&& winlogonSessId == dwSessionId)
			{
				winlogonPid = procEntry.th32ProcessID;
				break;
			}
		}

	} while (Process32Next(hSnap, &procEntry));

	////////////////////////////////////////////////////////////////////////

	pWTSQueryUserToken(dwSessionId, &hUserToken);
	dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = (LPWSTR)L"winsta0\\default";
	memset(&pi, 0, sizeof(pi));
	TOKEN_PRIVILEGES tp;
	LUID luid;
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);
	if (hProcess)
	{
		if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
			| TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
			| TOKEN_READ | TOKEN_WRITE, &hPToken))
		{
			//			int abcd = GetLastError();
						//		printf("Process token open Error: %u\n", GetLastError());
		}

		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			//		printf("Lookup Privilege value Error: %u\n", GetLastError());
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL,
			SecurityIdentification, TokenPrimary, &hUserTokenDup);
		int dup = GetLastError();

		//Adjust Token privilege
		SetTokenInformation(hUserTokenDup,
			TokenSessionId, (LPVOID)dwSessionId, sizeof(ULONG));

		if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL, NULL))
		{
			//			int abc = GetLastError();
						//		printf("Adjust Privilege value Error: %u\n", GetLastError());
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			//		printf("Token does not have the provilege\n");
		}

		LPVOID pEnv = NULL;

		if (pCreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
		{
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		else
			pEnv = NULL;

		// Launch the process in the client's logon session.

		bResult = CreateProcessAsUser(
			hUserTokenDup,                     // client's access token
			szExe,    // file to execute
			szLine,                 // command line
			NULL,            // pointer to process SECURITY_ATTRIBUTES
			NULL,               // pointer to thread SECURITY_ATTRIBUTES
			FALSE,              // handles are not inheritable
			dwCreationFlags,     // creation flags
			pEnv,               // pointer to new environment block
			szDir,               // name of current directory
			&si,               // pointer to STARTUPINFO structure
			&pi                // receives information about new process
		);
	}
	if (hProcess)
	{
		CloseHandle(hProcess);
		CloseHandle(hUserToken);
		CloseHandle(hUserTokenDup);
		CloseHandle(hPToken);
	}
	return bResult;
}
//////////////////////////////////////////////////////////////////////////服务函数
BOOL bInstallService;
SERVICE_STATUS_HANDLE hServiceStatus;
SERVICE_STATUS status;
HANDLE hEvent = INVALID_HANDLE_VALUE;
void InitService()//初始化服务参数
{
	hServiceStatus = NULL;
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	status.dwCurrentState = SERVICE_STOPPED;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	status.dwWin32ExitCode = 0;
	status.dwServiceSpecificExitCode = 0;
	status.dwCheckPoint = 0;
	status.dwWaitHint = 0;
}
void WINAPI ServiceStrl(DWORD dwOpcode)//服务控制函数
{
	switch (dwOpcode)
	{
	case SERVICE_CONTROL_STOP:
		status.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(hServiceStatus, &status);
		//告诉服务线程停止工作
		::SetEvent(hEvent);
		break;
	case SERVICE_CONTROL_PAUSE:
		break;
	case SERVICE_CONTROL_CONTINUE:
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		break;
	default:
		break;
	}
}
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)//服务主线程入口
{
	// Register the control request handler
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	//注册服务控制
	hServiceStatus = RegisterServiceCtrlHandler(lpServiceName, ServiceStrl);
	if (hServiceStatus == NULL)
	{
		return;
	}
	SetServiceStatus(hServiceStatus, &status);
	//如下代码可以为启动服务前的准备工作
	hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hEvent == NULL)
	{
		status.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hServiceStatus, &status);
		return;
	}
	//更改服务状态为启动
	status.dwWin32ExitCode = S_OK;
	status.dwCheckPoint = 0;
	status.dwWaitHint = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hServiceStatus, &status);
	//等待用户选择停止服务，
	//当然你也可以把你的服务代码用线程来执行，
	//此时这里只需等待线程结束既可。
//	CloseHandle(CreateFile(L"d:\\topc.txt", GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL));
	WCHAR szExe[MAX_PATH];
	HINSTANCE hInst = GetModuleHandle(NULL);
	GetModuleFileName(hInst, szExe, MAX_PATH);
	size_t iLen = wcslen(szExe);
	szExe[iLen] = L'\0';
	WCHAR szLine[] = L" t";
	//	CreateProcessByExplorer(szExe, NULL, NULL);
	LaunchAppIntoDifferentSession(szExe, NULL, szLine);
	while (WaitForSingleObject(hEvent, 1000) != WAIT_OBJECT_0)
	{
	}
	//停止服务
	status.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(hServiceStatus, &status);
}
DWORD ServiceRunState()//服务运行状态
{
	BOOL bResult = FALSE;
	//打开服务控制管理器
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM != NULL)
	{
		//打开服务
		SC_HANDLE hService = ::OpenService(hSCM, lpServiceName, SERVICE_QUERY_STATUS);
		if (hService != NULL)
		{
			SERVICE_STATUS ss;
			QueryServiceStatus(hService, &ss);
			bResult = ss.dwCurrentState;
			::CloseServiceHandle(hService);
		}
		::CloseServiceHandle(hSCM);
	}
	return bResult;
}
BOOL IsServiceInstalled()//服务是否已经安装
{
	BOOL bResult = FALSE;
	//打开服务控制管理器
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM != NULL)
	{
		//打开服务
		SC_HANDLE hService = ::OpenService(hSCM, lpServiceName, SERVICE_QUERY_CONFIG);
		if (hService != NULL)
		{
			bResult = TRUE;
			::CloseServiceHandle(hService);
		}
		::CloseServiceHandle(hSCM);
	}
	return bResult;
}
BOOL InstallService()//安装服务
{
	if (IsServiceInstalled())
		return TRUE;
	//打开服务控制管理器
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		return FALSE;
	}
	// Get the executable file path
	TCHAR szFilePath[MAX_PATH];
	::GetModuleFileName(NULL, szFilePath, MAX_PATH);
	//创建服务
	SC_HANDLE hService = ::CreateService(
		hSCM,
		lpServiceName,
		lpServiceName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
		SERVICE_AUTO_START, //如果为SERVICE_DEMAND_START则表示此服务需手工启动
		SERVICE_ERROR_NORMAL,
		szFilePath,
		NULL,
		NULL,
		L"",
		NULL,
		NULL);
	if (hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return FALSE;
	}
	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);
	return TRUE;
}
BOOL UninstallService()//卸载服务
{
	if (!IsServiceInstalled())
		return TRUE;
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		return FALSE;
	}
	SC_HANDLE hService = ::OpenService(hSCM, lpServiceName, SERVICE_STOP | DELETE);
	if (hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return FALSE;
	}
	SERVICE_STATUS status;
	::ControlService(hService, SERVICE_CONTROL_STOP, &status);
	//删除服务
	BOOL bDelete = ::DeleteService(hService);
	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);
	if (bDelete)
		return TRUE;
	return FALSE;
}
BOOL ServiceCtrlStart()//开启服务
{
	BOOL bRet;
	SC_HANDLE hSCM;
	SC_HANDLE hService;
	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hSCM != NULL)
	{
		//		hService = OpenService(hSCM, szServiceName, SERVICE_START);
		hService = OpenService(hSCM, lpServiceName, SERVICE_ALL_ACCESS);
		if (hService != NULL)
		{
			TCHAR szFilePath[MAX_PATH];
			::GetModuleFileName(NULL, szFilePath, MAX_PATH);
			ChangeServiceConfig(hService, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_AUTO_START, SERVICE_NO_CHANGE, szFilePath, NULL, NULL, NULL, NULL, NULL, NULL);
			//开始Service
			bRet = StartService(hService, 0, NULL);
			CloseServiceHandle(hService);
		}
		else
		{
			bRet = FALSE;
		}
		CloseServiceHandle(hSCM);
	}
	else
	{
		bRet = FALSE;
	}
	return bRet;
}
BOOL ServiceCtrlStop()//停止服务
{
	BOOL bRet;
	SC_HANDLE hSCM;
	SC_HANDLE hService;
	SERVICE_STATUS ServiceStatus;
	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM != NULL)
	{
		hService = OpenService(hSCM, lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
		if (hService != NULL)
		{
			QueryServiceStatus(hService, &ServiceStatus);
			if (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
			{
				bRet = ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
			}
			else
			{
				bRet = FALSE;
			}
			CloseServiceHandle(hService);
		}
		else
		{
			bRet = FALSE;
		}
		CloseServiceHandle(hSCM);
	}
	else
	{
		bRet = FALSE;
	}
	return bRet;
}
int GetScreenRect(HWND hWnd, LPRECT lpRect, BOOL bTray)//获取窗口所在的屏幕大小可减去任务栏
{
	HMONITOR hMon = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
	MONITORINFO mi;
	mi.cbSize = sizeof mi;
	GetMonitorInfo(hMon, &mi);
	if (bTray)
	{
		RECT TrayRect;
		if (mi.rcMonitor.left == 0 && mi.rcMonitor.top == 0)
		{
			HWND hTrayWnd = ::FindWindow(szShellTray, NULL);
			GetWindowRect(hTrayWnd, &TrayRect);
		}
		else
		{
			HWND hSecondaryTray;
			hSecondaryTray = FindWindow(szSecondaryTray, NULL);
			while (hSecondaryTray)
			{
				GetWindowRect(hSecondaryTray, &TrayRect);
				POINT pt;
				pt.x = TrayRect.left;
				pt.y = TrayRect.top;
				if (PtInRect(lpRect, pt))
					break;
				hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
			}
		}
		RECT dRect;
		SubtractRect(&dRect, &mi.rcMonitor, &TrayRect);
		CopyRect(lpRect, &dRect);
	}
	else
		CopyRect(lpRect, &mi.rcMonitor);
	return 0;
}
typedef struct _PROCESS_BASIC_INFORMATION
{
	PVOID Reserved1;
	DWORD PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}PROCESS_BASIC_INFORMATION;
typedef LONG(WINAPI* pfnNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
DWORD GetParentProcessID(DWORD dwProcessId)//获取父进程ID
{
	if (dwProcessId == -1)
		return -1;
	LONG                        status;
	DWORD                       dwParentPID = (DWORD)-1;
	HANDLE                      hProcess;
	PROCESS_BASIC_INFORMATION   pbi;
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NULL == NtQueryInformationProcess)
		return (DWORD)-1;
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	if (!hProcess)
	{
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
	}
	if (!hProcess)
		return (DWORD)-1;
	status = NtQueryInformationProcess(hProcess, 0, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!status)
		dwParentPID = pbi.InheritedFromUniqueProcessId;
	CloseHandle(hProcess);
	return dwParentPID;
}
BOOL GetSetVolume(BOOL bSet, HWND hWnd, DWORD dwProcessId, float* fVolume, BOOL* bMute, BOOL IsMixer)
{
	DWORD dwCProcessId = -1;
	if (hWnd)
		GetWindowThreadProcessId(hWnd, &dwProcessId);
	BOOL ret = FALSE;
	HRESULT hr = S_OK;
	IMMDeviceCollection* pMultiDevice = NULL;
	IMMDevice* pDevice = NULL;
	IAudioSessionEnumerator* pSessionEnum = NULL;
	IAudioSessionManager2* pASManager = NULL;
	IMMDeviceEnumerator* m_pEnumerator = NULL;
	const IID IID_ISimpleAudioVolume = __uuidof(ISimpleAudioVolume);
	const IID IID_IAudioSessionControl2 = __uuidof(IAudioSessionControl2);

	GUID m_guidMyContext;
	CoInitialize(NULL);
	hr = CoCreateGuid(&m_guidMyContext);
	if (CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&m_pEnumerator) == S_OK)
	{
		if (IsMixer)
		{
			hr = m_pEnumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &pMultiDevice);
		}
		else
		{
			hr = m_pEnumerator->EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE, &pMultiDevice);
		}
		if (hr == S_OK)
		{
			UINT deviceCount = 0;
			if (pMultiDevice->GetCount(&deviceCount) == S_OK)
			{
				for (UINT ii = 0; ii < deviceCount; ii++)
				{
					pDevice = NULL;
					if (pMultiDevice->Item(ii, &pDevice) == S_OK)
					{
						if (pDevice->Activate(__uuidof(IAudioSessionManager), CLSCTX_ALL, NULL, (void**)&pASManager) == S_OK)
						{
							if (pASManager->GetSessionEnumerator(&pSessionEnum) == S_OK)
							{
								int nCount;
								if (pSessionEnum->GetCount(&nCount) == S_OK)
								{
									for (int i = 0; i < nCount; i++)
									{
										IAudioSessionControl* pSessionCtrl;
										if (pSessionEnum->GetSession(i, &pSessionCtrl) == S_OK)
										{
											IAudioSessionControl2* pSessionCtrl2;
											if (pSessionCtrl->QueryInterface(IID_IAudioSessionControl2, (void**)&pSessionCtrl2) == S_OK)
											{
												ULONG pid;
												if (pSessionCtrl2->GetProcessId(&pid) == S_OK)
												{
													ISimpleAudioVolume* pSimplevol;
													if (pSessionCtrl2->QueryInterface(IID_ISimpleAudioVolume, (void**)&pSimplevol) == S_OK)
													{
														if (pid == dwProcessId || dwProcessId == GetParentProcessID(pid))
														{
															if (bSet)
															{
																if (fVolume)
																	pSimplevol->SetMasterVolume(*fVolume, NULL);
																if (bMute)
																	pSimplevol->SetMute(*bMute, NULL);
															}
															else
															{
																if (fVolume)
																{
																	pSimplevol->GetMasterVolume(fVolume);
																}
																if (bMute)
																{
																	pSimplevol->GetMute(bMute);
																}
															}
															ret = TRUE;
														}
														pSimplevol->Release();
													}
												}
												pSessionCtrl2->Release();
											}
											pSessionCtrl->Release();
										}
									}
								}
								pSessionEnum->Release();
							}
							pASManager->Release();
						}
						pDevice->Release();
					}
				}
			}
			pMultiDevice->Release();
		}
		m_pEnumerator->Release();
	}
	CoUninitialize();
	return ret;
}
BOOL EnableDebugPrivilege(BOOL bEnableDebugPrivilege)//DEBUG提权
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		{
			tp.PrivilegeCount = 1;
			if (bEnableDebugPrivilege)
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			else
				tp.Privileges[0].Attributes = 0;
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
			{
				::CloseHandle(hToken);
				return TRUE;
			}
		}
		CloseHandle(hToken);
	}
	return FALSE;
}
BOOL IsUserAdmin()//判断是以管理员权限运行
{
	//	IsUserAnAdmin();
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
	if (b)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}
	return(b);
}
void SetToCurrentPath()
{
	WCHAR szDir[MAX_PATH];
	GetModuleFileName(NULL, szDir, MAX_PATH);
	int len = lstrlen(szDir);
	for (int i = len - 1; i > 0; i--)
	{
		if (szDir[i] == '\\')
		{
			szDir[i] = 0;
			SetCurrentDirectory(szDir);
			break;
		}
	}
}
BOOL RunProcess(LPTSTR szExe, const WCHAR* szCommandLine)
{
	BOOL ret = FALSE;
	STARTUPINFO StartInfo;
	PROCESS_INFORMATION procStruct;
	memset(&StartInfo, 0, sizeof(STARTUPINFO));
	StartInfo.cb = sizeof(STARTUPINFO);
	WCHAR* sz;
	WCHAR szName[MAX_PATH];
	if (szExe == (LPTSTR)1)
		sz = NULL;
	else if (szExe)
		sz = szExe;
	else
	{
		GetModuleFileName(NULL, szName, MAX_PATH);
		sz = szName;
	}
	WCHAR szLine[MAX_PATH];
	lstrcpy(szLine, szCommandLine);
	ret = CreateProcess(sz,// RUN_TEST.bat位于工程所在目录下
		szLine,
		NULL,
		NULL,
		FALSE,
		NULL,// 这里不为该进程创建一个控制台窗口
		NULL,
		NULL,
		&StartInfo, &procStruct);
	CloseHandle(procStruct.hProcess);
	CloseHandle(procStruct.hThread);
//	SetTimer(hMain, 11, 1000, NULL);
	return ret;
}
void SetTaskScheduler(BOOL bDelAdd, const WCHAR* szName)///////////////////////////////////设置开机任务计划/删除任务计划
{
	SetToCurrentPath();
	WCHAR szDelSchtasks[MAX_PATH];
	wsprintf(szDelSchtasks, L" s/Delete /TN %s /F", szName);
	RunProcess(NULL, szDelSchtasks);
	Sleep(300);
	if (bDelAdd)
	{
		const WCHAR szXML1[] = L"<\?xml version=\"1.0\" encoding=\"unicode\"\?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><URI>\\%s</URI></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled>%s</LogonTrigger></Triggers><Principals><Principal>%s</Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>";
		const WCHAR szXML2[] = L"<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>true</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context=\"Author\"><Exec><Command>%s</Command><Arguments>t</Arguments></Exec></Actions></Task>";
		WCHAR sXML[4096];
		WCHAR szExe[MAX_PATH];
		GetModuleFileName(NULL, szExe, MAX_PATH);
		//		LoadString(hInst, IDS_XML1, szXML, 2048);
		if (IsUserAdmin())
		{
			wsprintf(sXML, szXML1, szName, L" ", L"<RunLevel>HighestAvailable</RunLevel><GroupId>Builtin\\Administrators</GroupId>");
			//			LoadString(hInst, IDS_XML2, szXML, 2048);
			int iLen = lstrlen(sXML);
			wsprintf(&sXML[iLen], szXML2, szExe);
		}
		else
		{
			WCHAR szUserName[64];
			DWORD dwLen = 64;
			GetUserName(szUserName, &dwLen);
			WCHAR szID[64];
			wsprintf(szID, L"<UserId>%s</UserId>", szUserName);
			WCHAR szUserID[128];
			wsprintf(szUserID, L"<UserId>%s</UserId><LogonType>InteractiveToken</LogonType>", szUserName);
			wsprintf(sXML, szXML1, szName, szID, szUserID);
			//			LoadString(hInst, IDS_XML2, szXML, 2048);
			int iLen = lstrlen(sXML);
			wsprintf(&sXML[iLen], szXML2, szExe);
		}
		WCHAR szFileName[64];
		wsprintf(szFileName, L"%s.xml", szName);
		HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
		if (hFile)
		{
			DWORD dwBytes;
			WORD unicode_identifier = 0xfeff;
			WriteFile(hFile, &unicode_identifier, sizeof(WORD), &dwBytes, NULL);
			WriteFile(hFile, sXML, (DWORD)lstrlen(sXML) * 2, &dwBytes, NULL);
			CloseHandle(hFile);
		}
		WCHAR szCreateSchtasks[MAX_PATH];
		wsprintf(szCreateSchtasks, L" s/create /XML %s.xml /tn %s", szName, szName);
		//		WCHAR szRunSchtasks[] = L" s/Run /TN TaryS";
		RunProcess(NULL, szCreateSchtasks);
		//		RunProcess(szRunSchtasks);
	}
}
BOOL AutoRun(BOOL GetSet, BOOL bAutoRun,const WCHAR* szName)//读取、设置开机启动、关闭开机启动
{
//	UninstallService();
	BOOL ret = FALSE;
/*
	if (GetSet == FALSE)
	{
		WCHAR szExe[MAX_PATH];
		GetSystemDirectory(szExe, MAX_PATH);
		lstrcat(szExe, L"\\schtasks.exe");
		DWORD               exitCode = 0;
		PROCESS_INFORMATION pInfo = { 0 };
		STARTUPINFO         sInfo = { 0 };
		sInfo.cb = sizeof(STARTUPINFO);
		sInfo.wShowWindow = SW_HIDE;
		WCHAR szCommandLine[MAX_PATH];
		lstrcpy(szCommandLine, L"/Query /TN ");
		lstrcat(szCommandLine,szName);
		if (CreateProcess(szExe, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &sInfo, &pInfo))
		{
			// Wait until child process exits.
			WaitForSingleObject(pInfo.hProcess, INFINITE);

			if (GetExitCodeProcess(pInfo.hProcess, &exitCode))
			{
				CloseHandle(pInfo.hProcess);
				CloseHandle(pInfo.hThread);
				if (exitCode == 0)
					return TRUE;
			}
			else
			{
				CloseHandle(pInfo.hProcess);
				CloseHandle(pInfo.hThread);
			}
		}
	}
*/
	WCHAR sFileName[MAX_PATH];
	sFileName[0] = L'\"';
	GetModuleFileName(NULL, &sFileName[1], MAX_PATH);
	int sLen = lstrlen(sFileName);
	sFileName[sLen] = L'\"';
	sFileName[sLen + 1] = L' ';
	sFileName[sLen + 2] = L't';
	sFileName[sLen + 3] = L'\0';
	if (IsUserAdmin())
	{
		if (GetSet)
		{
			HKEY pKey;
			RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
			if (pKey)
			{
				RegDeleteValue(pKey, szName);
				RegCloseKey(pKey);
			}
			RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
			if (pKey)
			{
				RegDeleteValue(pKey, szName);
				RegCloseKey(pKey);
			}
			if (bAutoRun)
			{
				SetTaskScheduler(TRUE, szName);
				InstallService();
			}
			else
			{
				SetTaskScheduler(FALSE, szName);
				if (IsServiceInstalled())
					UninstallService();
			}
		}
		else
		{
			return IsServiceInstalled();
		}
	}
	else
	{
		HKEY pKey;
		RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
		if (pKey)
		{
			if (GetSet)
			{
				if (bAutoRun)
				{
					SetTaskScheduler(TRUE, szName);
					RegSetValueEx(pKey, szName, NULL, REG_SZ, (BYTE*)sFileName, (DWORD)lstrlen(sFileName) * 2);
				}
				else
				{
					SetTaskScheduler(FALSE, szName);
					RegDeleteValue(pKey, szName);
				}
				ret = TRUE;
			}
			else
			{
				WCHAR nFileName[MAX_PATH];
				DWORD cbData = MAX_PATH * sizeof WCHAR;
				DWORD dType = REG_SZ;
				if (RegQueryValueEx(pKey, szName, NULL, &dType, (LPBYTE)nFileName, &cbData) == ERROR_SUCCESS)
				{
					if (lstrcmp(sFileName, nFileName) == 0)
						ret = TRUE;
					else
						ret = FALSE;
				}
			}
			RegCloseKey(pKey);
		}
	}
	return ret;
}
BOOL SetWindowCompositionAttribute(HWND hWnd, ACCENT_STATE mode, DWORD AlphaColor)//设置窗口WIN10风格
{
	pfnSetWindowCompositionAttribute pSetWindowCompositionAttribute = NULL;
	if (mode == ACCENT_DISABLED)
	{
//		if (bAccentNormal == FALSE)
		{
			SendMessage(hWnd, WM_THEMECHANGED, 0, 0);
//			bAccentNormal = TRUE;
		}
		return TRUE;
	}
//	bAccentNormal = FALSE;
	BOOL ret = FALSE;
	HMODULE hUser = GetModuleHandle(L"user32.dll");
	if (hUser)
		pSetWindowCompositionAttribute = (pfnSetWindowCompositionAttribute)GetProcAddress(hUser, "SetWindowCompositionAttribute");
	if (pSetWindowCompositionAttribute)
	{
		ACCENT_POLICY accent = { mode, 2, AlphaColor, 0 };
		_WINDOWCOMPOSITIONATTRIBDATA data;
		data.Attrib = WCA_ACCENT_POLICY;
		data.pvData = &accent;
		data.cbData = sizeof(accent);
		ret = pSetWindowCompositionAttribute(hWnd, &data);
	}
	return ret;
}
/*
typedef BOOL(WINAPI*pfnGetWindowCompositionAttribute)(HWND, struct _WINDOWCOMPOSITIONATTRIBDATA*);
BOOL GetWindowCompositionAttribute(HWND hWnd, ACCENT_POLICY * accent)
{
	BOOL ret = FALSE;
	HMODULE hUser = GetModuleHandle(L"user32.dll");
	if (hUser)
	{
		pfnGetWindowCompositionAttribute getWindowCompositionAttribute = (pfnGetWindowCompositionAttribute)GetProcAddress(hUser, "GetWindowCompositionAttribute");
		if (getWindowCompositionAttribute)
		{
			_WINDOWCOMPOSITIONATTRIBDATA data;
			ACCENT_POLICY acc[2];
			data.Attrib = WCA_ACCENT_POLICY;
			data.pvData = acc;
			data.cbData = sizeof ACCENT_POLICY * 2;
			ret = getWindowCompositionAttribute(hWnd, &data);
		}
	}
	return ret;
}
*/
BOOL GetProcessFileName(DWORD dwProcessId, LPTSTR pszFileName, DWORD dwFileNameLength)
{
	BOOL bResult = false;
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProc == NULL)
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
	if (hProc)
	{
		HMODULE hPSAPI = LoadLibrary(L"psapi.dll");
		if (hPSAPI)
		{
			typedef DWORD(WINAPI* pfnGetModuleFileNameEx)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
			pfnGetModuleFileNameEx pGetModuleFileNameEx = (pfnGetModuleFileNameEx)GetProcAddress(hPSAPI, "GetModuleFileNameExW");
			bResult = pGetModuleFileNameEx(hProc, NULL, pszFileName, dwFileNameLength);
			if (bResult == 0)
			{
				typedef WINUSERAPI BOOL WINAPI QUERYFULLPROCESSIMAGENAME(HANDLE hProcess, DWORD  dwFlags, LPTSTR lpExeName, PDWORD lpdwSize);
				QUERYFULLPROCESSIMAGENAME* pQueryFullProcessImageName = (QUERYFULLPROCESSIMAGENAME*)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "QueryFullProcessImageNameW");
				if (pQueryFullProcessImageName)
				{
					DWORD dwSize = dwFileNameLength;
					bResult = pQueryFullProcessImageName(hProc, 0, pszFileName, &dwSize);
				}
			}
			FreeLibrary(hPSAPI);
			if (bResult == FALSE)
				bResult = GetProcessImageFileName(hProc, pszFileName, dwFileNameLength);
		}
		CloseHandle(hProc);
	}
	return bResult;
}
bool GetFileNameFromWindowHandle(HWND hWnd, LPTSTR lpFileName, DWORD dwFileNameLength)
{
	bool bResult = false;
	DWORD dwProcessId = 0;

	if (GetWindowThreadProcessId(hWnd, &dwProcessId) != 0)
	{
		bResult = GetProcessFileName(dwProcessId, lpFileName, dwFileNameLength);
	}
	return bResult;
}
typedef struct PACKAGE_VERSION {
	union {
		UINT64 Version;
		struct {
			USHORT Revision;
			USHORT Build;
			USHORT Minor;
			USHORT Major;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
} PACKAGE_VERSION;
typedef struct PACKAGE_ID {
	UINT32          reserved;
	UINT32          processorArchitecture;
	PACKAGE_VERSION version;
	PWSTR           name;
	PWSTR           publisher;
	PWSTR           resourceId;
	PWSTR           publisherId;
} PACKAGE_ID;
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define ARRAY_SIZEOF(array) (sizeof(array)/sizeof(array[0]))
HICON GetUWPAppIcon(HWND hWnd, UINT uiIconSize = 32) {
	HICON hIcon = NULL;
	static LONG(WINAPI * pGetPackageFullName)(HANDLE, UINT32*, PWSTR);
	static LONG(WINAPI * pGetPackagePathByFullName)(PCWSTR, UINT32*, PWSTR);
	static LONG(WINAPI * pPackageIdFromFullName)(PCWSTR, const UINT32, UINT32*, BYTE*);
	if (!pGetPackageFullName)pGetPackageFullName = (LONG(WINAPI*)(HANDLE, UINT32*, PWSTR))
		GetProcAddress(GetModuleHandle(L"kernel32"), "GetPackageFullName");
	if (!pGetPackagePathByFullName)pGetPackagePathByFullName = (LONG(WINAPI*)(PCWSTR, UINT32*, PWSTR))
		GetProcAddress(GetModuleHandle(L"kernel32"), "GetPackagePathByFullName");
	if (!pPackageIdFromFullName)pPackageIdFromFullName = (LONG(WINAPI*)(PCWSTR, const UINT32, UINT32*, BYTE*))
		GetProcAddress(GetModuleHandle(L"kernel32"), "PackageIdFromFullName");
	if (pGetPackageFullName && pGetPackagePathByFullName && pPackageIdFromFullName)
	{
		WCHAR szPackageName[MAX_PATH];
		WCHAR szPackagePath[MAX_PATH];
		szPackageName[0] = L'\0';
		UINT32 uiPackageNameLength = MAX_PATH;
		UINT32 uiPackagePathLength = MAX_PATH;
		UINT32 uiPackageIdLength = 0;
		DWORD dwProcessId = 0;
		GetWindowThreadProcessId(hWnd, &dwProcessId);
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
		pGetPackageFullName(hProcess, &uiPackageNameLength, szPackageName);
		pGetPackagePathByFullName(szPackageName, &uiPackagePathLength, szPackagePath);
		pPackageIdFromFullName(szPackageName, 0, &uiPackageIdLength, NULL);
		BYTE* byPackageId = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uiPackageIdLength);
		pPackageIdFromFullName(szPackageName, 0, &uiPackageIdLength, byPackageId);
		CloseHandle(hProcess);
		//		if (OpenProcessDir(dwProcessId, szPackagePath))
		if (byPackageId)
		{
			if (szPackageName[0] != 0)
			{
				if (szPackagePath[lstrlen(szPackagePath) - 1] != '\\')lstrcat(szPackagePath, L"\\");
				lstrcat(szPackagePath, L"AppxManifest.xml");
				HANDLE hFile = CreateFile(szPackagePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
				if (hFile)
				{
					DWORD dwSize = GetFileSize(hFile, NULL);
					BYTE* utf8 = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
					ReadFile(hFile, utf8, dwSize, NULL, NULL);
					CloseHandle(hFile);
					WCHAR* szXML = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize * 3);
					MultiByteToWideChar(CP_UTF8, 0, (LPCCH)utf8, dwSize, szXML, dwSize * 2);
					HeapFree(GetProcessHeap(), 0, utf8);
					WCHAR* sz44 = lstrstr(szXML, L"Square44x44Logo");
					WCHAR* szY = NULL;
					if (sz44)
					{
						szY = lstrstr(sz44, L"\"");
						if (szY)
						{
							WCHAR* szYY = lstrstr(&szY[1], L"\"");
							if (szYY)
								szYY[0] = L'\0';
						}
					}
					TCHAR szLogoPath[MAX_PATH];
					if (szY)
					{
						//						WCHAR szName[MAX_PATH];
						//						WCHAR* sz_ = wcsstr(szPackageName, L"_");
						//						if(sz_)
						//							wcsncpy_s(szName, MAX_PATH, szPackageName, sz_ - szPackageName);
						wsprintf(szLogoPath, L"@{%s?ms-resource://%s/Files/%s}", szPackageName, ((PACKAGE_ID*)byPackageId)->name, &szY[1]);
						for (int ii = 0, length = lstrlen(szLogoPath); ii < length; ii++)
							if (szLogoPath[ii] == '\\')szLogoPath[ii] = '/';
						pSHLoadIndirectString(szLogoPath, szLogoPath, MAX_PATH, 0);
						if (GetFileAttributes(szLogoPath) != 0xFFFFFFFF)
						{
							//							ULONG_PTR ulToken;
							//							Gdiplus::GdiplusStartupInput gdiplusStartupInput;
							//							Gdiplus::GdiplusStartup(&ulToken, &gdiplusStartupInput, NULL);
							{
								Gdiplus::Bitmap bBitmapOrig(szLogoPath);
								Gdiplus::Bitmap bBitmap(uiIconSize, uiIconSize);
								Gdiplus::Graphics gGraphics(&bBitmap);
								gGraphics.DrawImage(&bBitmapOrig, 0, 0, uiIconSize, uiIconSize);
								HICON sIcon;
								bBitmap.GetHICON(&sIcon);
								if (sIcon)
								{
									hIcon = CopyIcon(sIcon);
									DestroyIcon(sIcon);
								}
							}
							//							Gdiplus::GdiplusShutdown(ulToken);
						}
					}
					HeapFree(GetProcessHeap(), 0, szXML);
				}
			}
			HeapFree(GetProcessHeap(), 0, byPackageId);
		}
	}
	return hIcon;
}
HICON GetIcon(HWND hWnd, BOOL* bUWP, HWND* hUICoreWnd,int IconSize)
{
	HICON hIcon = NULL;
	*bUWP = FALSE;
	if (hUICoreWnd)
		*hUICoreWnd = FALSE;
	if (hWnd == NULL /*|| IsHungAppWindow(hWnd)*/)return NULL;
	WCHAR szClassName[MAX_PATH];
	GetClassName(hWnd, szClassName, MAX_PATH);
	if (lstrcmp(szClassName, L"Windows.UI.Core.CoreWindow") == 0)
	{
		hIcon = GetUWPAppIcon(hWnd, IconSize);
	}
	if (hIcon == NULL && GetWindowLongPtr(hWnd, GWL_EXSTYLE) & (0x00200000L/*WS_EX_NOREDIRECTIONBITMAP*/))
	{
		HWND hUWP = FindWindowEx(hWnd, NULL, L"Windows.UI.Core.CoreWindow", NULL);
		if (hUWP)
		{
			if (hUICoreWnd)
				*hUICoreWnd = hUWP;
			hIcon = GetUWPAppIcon(hUWP, IconSize);
		}
		else
		{
			TCHAR szApplicationFrameWindowTitle[MAX_PATH] = { 0 };
			TCHAR szClassName[128] = { 0 };
			TCHAR szCoreWindowTitle[MAX_PATH] = { 0 };
			InternalGetWindowText(hWnd, szApplicationFrameWindowTitle, ARRAY_SIZEOF(szApplicationFrameWindowTitle));
			HWND hCurrent = GetTopWindow(NULL);
			do {
				if (!IsHungAppWindow(hCurrent) &&
					GetWindowLongPtr(hCurrent, GWLP_HWNDPARENT) == NULL &&
					GetWindowLongPtr(hCurrent, GWL_EXSTYLE) & (0x00200000L/*WS_EX_NOREDIRECTIONBITMAP*/) &&
					IsWindowEnabled(hCurrent)) {
					GetClassName(hCurrent, szClassName, ARRAY_SIZEOF(szClassName));
					if (lstrcmp(szClassName, L"Windows.UI.Core.CoreWindow") == 0) {
						InternalGetWindowText(hCurrent, szCoreWindowTitle, ARRAY_SIZEOF(szCoreWindowTitle));
						if (lstrstr(szApplicationFrameWindowTitle, szCoreWindowTitle))
						{
							if (hUICoreWnd)
								*hUICoreWnd = hCurrent;
							hIcon = GetUWPAppIcon(hCurrent, IconSize);
							
							break;
						}
					}
				}
			} while ((hCurrent = GetNextWindow(hCurrent, GW_HWNDNEXT)) != NULL);
		}
	}
	if (hIcon == NULL)
	{
		WCHAR szExe[MAX_PATH];
		GetFileNameFromWindowHandle(hWnd, szExe, MAX_PATH);
		SHFILEINFO shfi;
		pSHGetFileInfo(szExe, 0, &shfi, sizeof(shfi), SHGFI_ICON);
		hIcon = shfi.hIcon;
	}
	if (hIcon == NULL)
	{
		LRESULT  dwResult = 1;
		dwResult = SendMessageTimeout(hWnd, WM_GETICON, ICON_BIG, 0, SMTO_ABORTIFHUNG, 300, (PDWORD_PTR)&hIcon);
		if (dwResult == 1)
		{
			if (hIcon == NULL)
				hIcon = (HICON)GetClassLongPtr(hWnd, GCLP_HICON);
			if (hIcon == NULL)
				hIcon = (HICON)SendMessage(hWnd, WM_GETICON, ICON_SMALL, 0);
			if (hIcon == NULL)
				hIcon = (HICON)GetClassLongPtr(hWnd, GCLP_HICONSM);
			if (hIcon == NULL)
			{
				WCHAR szExe[MAX_PATH];
				GetFileNameFromWindowHandle(hWnd, szExe, MAX_PATH);
				SHFILEINFO shfi;
				pSHGetFileInfo(szExe, 0, &shfi, sizeof(shfi), SHGFI_ICON);
				hIcon = shfi.hIcon;
			}
		}

	}
	else
		*bUWP = TRUE;
	/*
		Gdiplus::Bitmap gIcon(hIcon);
		Gdiplus::Bitmap bBitmap(IconSize, IconSize);
		Gdiplus::Graphics gGraphics(&bBitmap);
		gGraphics.SetInterpolationMode(InterpolationModeHighQuality);
		gGraphics.DrawImage(&gIcon, 0, 0, IconSize, IconSize);
		DestroyIcon(hIcon);
		bBitmap.GetHICON(&hIcon);
	*/
	return hIcon;
}
BOOL SetForeground(HWND hWnd)
{
	bool bResult = false;
	bool bHung = IsHungAppWindow(hWnd) != 0;
	DWORD dwCurrentThreadId = 0, dwTargetThreadId = 0;
	DWORD dwTimeout = 0;

	dwCurrentThreadId = GetCurrentThreadId();
	dwTargetThreadId = GetWindowThreadProcessId(hWnd, NULL);

	if (IsIconic(hWnd)) {
		//		ShowWindow(hWnd,SW_RESTORE);
		SendMessage(hWnd, WM_SYSCOMMAND, SC_RESTORE, 0);
	}

	if (!bHung) {
		for (int i = 0; i < 10 && hWnd != GetForegroundWindow(); i++) {
			dwCurrentThreadId = GetCurrentThreadId();
			dwTargetThreadId = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
			AttachThreadInput(dwCurrentThreadId, dwTargetThreadId, true);
			SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			BringWindowToTop(hWnd);
			AllowSetForegroundWindow(ASFW_ANY);
			bResult = SetForegroundWindow(hWnd) != 0;
			AttachThreadInput(dwCurrentThreadId, dwTargetThreadId, false);
			Sleep(10);
		}
	}
	else {
		BringWindowToTop(hWnd);
		bResult = SetForegroundWindow(hWnd) != 0;
	}
	return bResult;
	/*
		int tIdCur = GetWindowThreadProcessId(GetForegroundWindow(), NULL);//获取当前窗口句柄的线程ID
		int tIdCurProgram = GetWindowThreadProcessId(hWnd,NULL);//获取当前运行程序线程ID
		BOOL ret=AttachThreadInput(tIdCur, tIdCurProgram, 1);//是否能成功和当前自身进程所附加的输入上下文有关;
		SetForegroundWindow(hWnd);
		AttachThreadInput(tIdCur, tIdCurProgram, 0);
		return ret;
	*/
}
void lstrlwr(WCHAR* wString, size_t SizeInWords)
{
	for (size_t i = 0; i < SizeInWords; i++)
	{
		if ((wString[i] >= 'A') && (wString[i] <= 'Z'))
			wString[i] += ('a' - 'A');
	}
}

wchar_t* lstrstr(const wchar_t* str, const wchar_t* sub)
{
	if (str == NULL || sub == NULL)
		return NULL;
	int iStrLen = lstrlen(str);
	int iSubLen = lstrlen(sub);
	if (iStrLen < iSubLen)
		return NULL;
	if (iStrLen != 0 && iSubLen == 0)
		return NULL;
	if (iStrLen == 0 && iSubLen == 0)
	{
		return (wchar_t*)str;
	}
	for (int i = 0; i < iStrLen; ++i)
	{
		int m = 0, n = i;
		if (lstrlen(str + i) < iSubLen)
		{
			return NULL;
		}
		if (str[n] == sub[m])
		{
			while (str[n++] == sub[m++])
			{
				if (sub[m] == L'\0')
					return (wchar_t*)str + i;
			}
		}
	}
	return NULL;
}
BOOL OpenProcessPath(DWORD dwProcessId)//通过进程ID打开进程的路径
{
	BOOL ret = FALSE;
	WCHAR szExplorer[MAX_PATH] = L"/select,";
	WCHAR* sz;
	int iLen = lstrlen(szExplorer);
	sz = &szExplorer[iLen];
	if (GetProcessFileName(dwProcessId, sz, MAX_PATH))
	{
		WCHAR szExe[MAX_PATH];
		GetWindowsDirectory(szExe, MAX_PATH);
		lstrcat(szExe, L"\\explorer.exe ");
		lstrcat(szExe, szExplorer);
		ret = RunProcess((LPTSTR)1, szExe);
	}
	return ret;
}
BOOL OpenWindowPath(HWND hWnd)
{
	BOOL ret = FALSE;
	DWORD dwProcessId;
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	if (dwProcessId)
		ret = OpenProcessPath(dwProcessId);
	return ret;
}
HICON OpenProcessIcon(DWORD dProcessID, int cx)//通过进程ID ICON
{
	HICON ret = NULL;
	WCHAR szExe[MAX_PATH];
	GetProcessFileName(dProcessID, szExe, MAX_PATH);
	SHFILEINFO shellInfo;
	pSHGetFileInfo(szExe, 0, &shellInfo, sizeof(shellInfo), SHGFI_ICON | SHGFI_SMALLICON);
	ret = shellInfo.hIcon;
	//	ret = pExtractIcon(NULL, szExe, 0);;
	return ret;
}
HICON GetIconForCSIDL(int csidl)
{
	LPITEMIDLIST pidl = 0;
	SHGetSpecialFolderLocation(NULL, csidl, &pidl);
	if (pidl)
	{
		SHFILEINFO shellInfo;
		pSHGetFileInfo(LPCTSTR(pidl), FILE_ATTRIBUTE_NORMAL, &shellInfo, sizeof(shellInfo), SHGFI_PIDL | SHGFI_ICON);
		IMalloc* pMalloc;
		SHGetMalloc(&pMalloc);
		if (pMalloc)
		{
			pMalloc->Free(pidl);
			pMalloc->Release();
		}
		return shellInfo.hIcon;
	}
	return 0;
}
int DrawShadowText(HDC hDC, LPCTSTR lpString, int nCount, LPRECT lpRect, UINT uFormat,COLORREF bColor,BOOL bYes)//绘制阴影文字
{
	//	COLORREF cColor = GetTextColor(hDC);
	//	return DrawShadowText(hDC, lpString, nCount, lpRect, uFormat, cColor, RGB(066, 66,66), 1, 1);	
//	return DrawText(hDC, lpString, nCount, lpRect, uFormat);
	if (bYes)
	{
		COLORREF cColor = GetTextColor(hDC);
		SetTextColor(hDC, bColor);
		OffsetRect(lpRect, 1, 0);
		DrawText(hDC, lpString, nCount, lpRect, uFormat);
		OffsetRect(lpRect, -1, 1);
		DrawText(hDC, lpString, nCount, lpRect, uFormat);
		OffsetRect(lpRect, -1, -1);
		DrawText(hDC, lpString, nCount, lpRect, uFormat);
		OffsetRect(lpRect, 1, -1);
		DrawText(hDC, lpString, nCount, lpRect, uFormat);
		OffsetRect(lpRect, 0, 3);
		DrawText(hDC, lpString, nCount, lpRect, uFormat);
		OffsetRect(lpRect, 0, -2);
		SetTextColor(hDC, cColor);
		//		DrawText(hDC, lpString, nCount, lpRect, uFormat);
	}
	return DrawText(hDC, lpString, nCount, lpRect, uFormat);
}
DWORD GetSystemUsesLightTheme()
{
	////////////////////////////////////////////////////////////////////////////////////判断系统主题色是否更改
	HKEY pKey;
	RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", NULL, KEY_ALL_ACCESS, &pKey);
	DWORD dm = -1;
	if (pKey)
	{
		DWORD dType = REG_DWORD;
		DWORD cbData = sizeof(dm);
		RegQueryValueEx(pKey, L"SystemUsesLightTheme", NULL, &dType, (BYTE*)&dm, &cbData);
		RegCloseKey(pKey);		
	}
	return dm;
}
UINT pGetDpiForWindow(HWND hWnd)
{
	typedef UINT(WINAPI* pfnGetDpiForWindow)(HWND hWnd);
	pfnGetDpiForWindow getDpiForWindow = (pfnGetDpiForWindow)GetProcAddress(GetModuleHandle(L"user32.dll"), "GetDpiForWindow");
	if (getDpiForWindow)
		return getDpiForWindow(hWnd);
	return 0;
/*
	else
	{
		HDC hdc = GetDC(hWnd);
		UINT dpi = GetDeviceCaps(hdc, LOGPIXELSY);
		ReleaseDC(hWnd, hdc);
		return dpi;
	}
*/
}