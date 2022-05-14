#include <windows.h>
#include <shellapi.h>
#include <Psapi.h>
#include <Mmdeviceapi.h>
#include <audiopolicy.h>
#include <Shlobj.h>
#include <tlhelp32.h>
#include <commctrl.h>

//#include "Winhttp.h"
//#pragma comment(lib,"winhttp.lib")

//GDI+
/*
#include<gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;
*/

const WCHAR lpServiceName[] = L"TrayS";//程序名
const WCHAR szShellTray[] = L"Shell_TrayWnd";//主任务栏类名
const WCHAR szSecondaryTray[] = L"Shell_SecondaryTrayWnd";//副任务栏类名
typedef enum _WINDOWCOMPOSITIONATTRIB
{
	WCA_UNDEFINED = 0,
	WCA_NCRENDERING_ENABLED = 1,
	WCA_NCRENDERING_POLICY = 2,
	WCA_TRANSITIONS_FORCEDISABLED = 3,
	WCA_ALLOW_NCPAINT = 4,
	WCA_CAPTION_BUTTON_BOUNDS = 5,
	WCA_NONCLIENT_RTL_LAYOUT = 6,
	WCA_FORCE_ICONIC_REPRESENTATION = 7,
	WCA_EXTENDED_FRAME_BOUNDS = 8,
	WCA_HAS_ICONIC_BITMAP = 9,
	WCA_THEME_ATTRIBUTES = 10,
	WCA_NCRENDERING_EXILED = 11,
	WCA_NCADORNMENTINFO = 12,
	WCA_EXCLUDED_FROM_LIVEPREVIEW = 13,
	WCA_VIDEO_OVERLAY_ACTIVE = 14,
	WCA_FORCE_ACTIVEWINDOW_APPEARANCE = 15,
	WCA_DISALLOW_PEEK = 16,
	WCA_CLOAK = 17,
	WCA_CLOAKED = 18,
	WCA_ACCENT_POLICY = 19,
	WCA_FREEZE_REPRESENTATION = 20,
	WCA_EVER_UNCLOAKED = 21,
	WCA_VISUAL_OWNER = 22,
	WCA_LAST = 23
} WINDOWCOMPOSITIONATTRIB;
typedef struct _WINDOWCOMPOSITIONATTRIBDATA
{
	WINDOWCOMPOSITIONATTRIB Attrib;
	PVOID pvData;
	SIZE_T cbData;
} WINDOWCOMPOSITIONATTRIBDATA;
typedef enum _ACCENT_STATE
{
	ACCENT_DISABLED = 0,
	ACCENT_ENABLE_GRADIENT = 1,
	ACCENT_ENABLE_TRANSPARENTGRADIENT = 2,
	ACCENT_ENABLE_BLURBEHIND = 3,
	ACCENT_ENABLE_ACRYLICBLURBEHIND = 4,
	ACCENT_INVALID_STATE = 5,
	ACCENT_ENABLE_TRANSPARENT = 6,
	ACCENT_7 = 7,
	ACCENT_8 = 8,
	ACCENT_9 = 9,
	ACCENT_10 = 10,
	ACCENT_NORMAL = 150
} ACCENT_STATE;
typedef struct _ACCENT_POLICY
{
	ACCENT_STATE AccentState;
	DWORD AccentFlags;
	DWORD GradientColor;
	DWORD AnimationId;
} ACCENT_POLICY;
typedef BOOL(WINAPI* pfnSetWindowCompositionAttribute)(HWND, struct _WINDOWCOMPOSITIONATTRIBDATA*);
void		SetToCurrentPath();//设置进程路径为当前路径
void		EmptyProcessMemory(DWORD pID=NULL);
BOOL		RunProcess(LPTSTR szExe, const WCHAR* szCommandLine,HANDLE *pProcess=NULL);//运行程序
BOOL		SetWindowCompositionAttribute(HWND hWnd, ACCENT_STATE mode, DWORD AlphaColor,BOOL bWin11=FALSE);//设置窗口WIN10风格
BOOL		AutoRun(BOOL GetSet, BOOL bAutoRun, const WCHAR* szName);//读取、设置开机启动、关闭开机启动
HICON		GetIcon(HWND hWnd, BOOL* bUWP, HWND* hUICoreWnd, int IconSize);//获取窗口图标
BOOL		GetProcessFileName(DWORD dwProcessId, LPTSTR pszFileName, DWORD dwFileNameLength);//通过进程ID获取目录文件名
BOOL		SetForeground(HWND hWnd);//强制设置窗口为前台
void		lstrlwr(WCHAR* wString, size_t SizeInWords);//字符串转小写
wchar_t*	lstrstr(const wchar_t* str, const wchar_t* sub);//字符串查找
BOOL		OpenWindowPath(HWND hWnd);//打开窗口所在的进程路径
BOOL		OpenProcessPath(DWORD dwProcessId);//通过进程ID打开进程的路径
BOOL		EnableDebugPrivilege(BOOL bEnableDebugPrivilege);//DEBUG提权
int			GetScreenRect(HWND hWnd, LPRECT lpRect, BOOL bTray);//获取窗口所在的屏幕大小可减去任务栏
BOOL		GetSetVolume(BOOL bSet, HWND hWnd, DWORD dwProcessId, float* fVolume, BOOL* bMute, BOOL IsMixer);//获取与设置进程音量

void		InitService();//初始化服务参数
BOOL		IsUserAdmin();//判断是以管理员权限运行
BOOL		InstallService();//安装服务
BOOL		UninstallService();//卸载服务
BOOL		ServiceCtrlStart();//开启服务
BOOL		ServiceCtrlStop();//停止服务
DWORD		ServiceRunState();//服务运行状态
BOOL		IsServiceInstalled();//服务是否已经安装
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);//服务主线程入口

HRESULT		pSHLoadIndirectString(LPCWSTR pszSource, LPWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved);
UINT		pDragQueryFile(HDROP hDrop, UINT iFile, LPTSTR lpszFile, UINT cch);
HICON		pExtractIcon(HINSTANCE hInst, LPCTSTR lpszExeFileName, UINT nIconIndex);
DWORD		pSHGetFileInfo(LPCTSTR pszPath, DWORD dwFileAttributes, SHFILEINFO FAR* psfi, UINT cbFileInfo, UINT uFlags);
HRESULT		pSHDefExtractIcon(LPCWSTR pszIconFile, int iIndex, UINT uFlags, HICON* phiconLarge, HICON* phiconSmall, UINT nIconSize);
HINSTANCE	pShellExecute(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpOperation, _In_ LPCWSTR lpFile, _In_opt_ LPCWSTR lpParameters, _In_opt_ LPCWSTR lpDirectory, _In_ INT nShowCmd);
BOOL		pShell_NotifyIcon(DWORD dwMessage, _In_ PNOTIFYICONDATAW lpData);
BOOL		pWTSQueryUserToken(ULONG SessionId, PHANDLE phToken);
BOOL		pCreateEnvironmentBlock(_At_((PZZWSTR*)lpEnvironment, _Outptr_)LPVOID* lpEnvironment, _In_opt_ HANDLE  hToken, _In_ BOOL bInherit);
ULONG		pCallNtPowerInformation(_In_ POWER_INFORMATION_LEVEL InformationLevel, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength);
int			DrawShadowText(HDC hDC, LPCTSTR lpString, int nCount, LPRECT lpRect, UINT uFormat, COLORREF bColor, BOOL bYes);//绘制阴影文字
DWORD		GetSystemUsesLightTheme();//获取系统主题颜色模式
BOOL		pChangeWindowMessageFilter(UINT message, DWORD dwFlag);
UINT		pGetDpiForWindow(HWND hWnd);
UINT_PTR	pSHAppBarMessage(DWORD dwMessage,PAPPBARDATA pData);

BOOL GetOKXPrice(LPTSTR szName, LPTSTR szWeb, float* fOutLast, float* fOutOpen, WCHAR* szOutLast, WCHAR* szOutOpen);
BOOL GetSinaPrice(LPTSTR szName, float* fOutLast, float* fOutOpen, WCHAR* szOutLast, WCHAR* szOutOpen);

char* xstrstr(const char* str, const char* sub);
float xatof(const char* s);
float xwtof(const WCHAR * s);
BOOL FloatToStr(float f, WCHAR* sz);


typedef LPVOID HINTERNET;
typedef HINTERNET* LPHINTERNET;
typedef WORD INTERNET_PORT;
typedef INTERNET_PORT* LPINTERNET_PORT;
// WinHttpOpen dwAccessType values (also for WINHTTP_PROXY_INFO::dwAccessType)
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY               0
#define WINHTTP_ACCESS_TYPE_NO_PROXY                    1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY                 3
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY             4
#define INTERNET_DEFAULT_PORT           0           // use the protocol-specific default
#define INTERNET_DEFAULT_HTTP_PORT      80          //    "     "  HTTP   "
#define INTERNET_DEFAULT_HTTPS_PORT     443         //    "     "  HTTPS  "
// WinHttpOpenRequest prettifers for optional parameters
#define WINHTTP_NO_REFERER             NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES   NULL
// flags for WinHttpOpenRequest():
#define WINHTTP_FLAG_SECURE                0x00800000  // use SSL if applicable (HTTPS)
#define WINHTTP_FLAG_ESCAPE_PERCENT        0x00000004  // if escaping enabled, escape percent as well
#define WINHTTP_FLAG_NULL_CODEPAGE         0x00000008  // assume all symbols are ASCII, use fast convertion
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE    0x00000100 // add "pragma: no-cache" request header
#define WINHTTP_FLAG_REFRESH               WINHTTP_FLAG_BYPASS_PROXY_CACHE
#define WINHTTP_FLAG_ESCAPE_DISABLE        0x00000040  // disable escaping
#define WINHTTP_FLAG_ESCAPE_DISABLE_QUERY  0x00000080  // if escaping enabled escape path part, but do not escape query
// WinHttpSendRequest prettifiers for optional parameters.
#define WINHTTP_NO_ADDITIONAL_HEADERS   NULL
#define WINHTTP_NO_REQUEST_DATA         NULL
typedef HINTERNET (WINAPI * pfnWinHttpOpen)(LPCWSTR pszAgentW,DWORD dwAccessType,LPCWSTR pszProxyW,LPCWSTR pszProxyBypassW,DWORD dwFlags);
typedef HINTERNET (WINAPI * pfnWinHttpConnect)(HINTERNET hSession,LPCWSTR pswzServerName,INTERNET_PORT nServerPort,DWORD dwReserved);
typedef HINTERNET (WINAPI * pfnWinHttpOpenRequest)(HINTERNET hConnect,LPCWSTR pwszVerb,LPCWSTR pwszObjectName,LPCWSTR pwszVersion,LPCWSTR pwszReferrer OPTIONAL,LPCWSTR FAR* ppwszAcceptTypes OPTIONAL,DWORD dwFlags);
typedef BOOL (WINAPI * pfnWinHttpSendRequest)(HINTERNET hRequest,LPCWSTR lpszHeaders,DWORD dwHeadersLength,LPVOID lpOptional,DWORD dwOptionalLength,DWORD dwTotalLength,DWORD_PTR dwContext);
typedef BOOL (WINAPI * pfnWinHttpReceiveResponse)(HINTERNET hRequest,LPVOID lpReserved);
typedef BOOL (WINAPI * pfnWinHttpQueryDataAvailable)(HINTERNET hRequest,LPDWORD lpdwNumberOfBytesAvailable);
typedef BOOL (WINAPI* pfnWinHttpReadData)(HINTERNET hRequest,LPVOID lpBuffer,DWORD dwNumberOfBytesToRead,LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI* pfnWinHttpCloseHandle)(HINTERNET hInternet);