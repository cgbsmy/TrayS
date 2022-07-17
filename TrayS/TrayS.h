#pragma once
#include "resource.h"
#include "function.h"
#include <Commdlg.h>
#include <Oleacc.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include <dwmapi.h>


//WINRING0
#include "OlsDef.h"
#include "OlsApiInit.h"

//ATIGPU
#include "adl_sdk.h"

#define MSG_APPBAR_MSGID WM_USER+15//全屏幕消息
#define  WM_IAWENTRAY WM_USER+8//通知栏消息
#define  WM_TRAYS WM_USER+8888//打开设置消息
#define KEYDOWN(vk_code) ((GetAsyncKeyState(vk_code) & 0x8000) ? 1 : 0)
#define KEYUP(vk_code) ((GetAsyncKeyState(vk_code) & 0x8000) ? 0 : 1)
/*
//窗口图标结构
typedef HANDLE HTHUMBNAIL;
typedef HTHUMBNAIL* PHTHUMBNAIL;
typedef struct _WINDOW_INFO
{
	HICON hIcon;//图标
//	TCHAR szFileName[MAX_PATH];//文件名
	TCHAR szWindowTitle[MAX_PATH];//窗口标题
	//非显示项目
//	TCHAR szFilePath[MAX_PATH];//文件路径
	HWND hWnd;//窗口句柄
	BOOL bForegorund;//是否焦点
	BOOL bIconic;//是否最小化
	BOOL bTopMost;//是否置顶
	BOOL bHide;
//	bool bDesktopItem;//「デスクトップ」である
//	bool bCancelItem;//「キャンセル」である
	BOOL bUWPApp;//UWPApp
	HWND hUICoreWnd;//UWPApp的Windows.UI.Core.CoreWindow子窗口
//	HTHUMBNAIL hThumbnail;
}WINDOW_INFO, * LPWINDOW_INFO;
int g_iWindowCount = 0;
LPWINDOW_INFO g_WindowInfo;
HANDLE g_hHeapWindowInfo;
HWND hTaskIcon=NULL;
HWND hThumbnail = NULL;
HTHUMBNAIL hThumb=NULL;
HWND hThumbWnd = NULL;
HWND hThumbUWP = NULL;
int iTaskIconXY;
int iTaskIconWidth=48;
HICON hThumbIcon[14];
ULONG_PTR ulToken;
int IconSize;
HRESULT(WINAPI* pDwmRegisterThumbnail)(HWND, HWND, PHTHUMBNAIL);
HRESULT(WINAPI* pDwmUnregisterThumbnail)(HTHUMBNAIL);
HRESULT(WINAPI* pDwmUpdateThumbnailProperties)(HTHUMBNAIL, const DWM_THUMBNAIL_PROPERTIES*);
HRESULT(WINAPI* pDwmQueryThumbnailSourceSize)(HTHUMBNAIL, PSIZE);
void AddItem(LPWINDOW_INFO lpWindowInfo)
{
	bool bFirstTime = g_iWindowCount == 0;
	WINDOW_INFO* pTmp = NULL;
	if (bFirstTime)pTmp = (WINDOW_INFO*)HeapAlloc(g_hHeapWindowInfo, HEAP_ZERO_MEMORY, (++g_iWindowCount) * sizeof(WINDOW_INFO));
	else pTmp = (WINDOW_INFO*)HeapReAlloc(g_hHeapWindowInfo, HEAP_ZERO_MEMORY, g_WindowInfo, (++g_iWindowCount) * sizeof(WINDOW_INFO));
	g_WindowInfo = pTmp;
	g_WindowInfo[g_iWindowCount - 1] = *lpWindowInfo;
	return;
}
*/
/////////////////////////////////////////////自定义网卡数据结构
typedef struct _TRAFFIC
{
	ULONG64 in_bytes;
	ULONG64 out_bytes;
	ULONG64 in_byte;
	ULONG64 out_byte;	
	PWCHAR FriendlyName;
	PCHAR AdapterName;
	WCHAR IP4[16];
}TRAFFIC;
////////////////////////////////////////////进程的内存使用数据结构
typedef struct _PROCESSMEMORYUSAGE
{
	WCHAR szExe[37];
	DWORD dwProcessID;	
	SIZE_T dwMemUsage;
}PROCESSMEMORYUSAGE;
///////////////////////////////////////////进程的CPU使用率数据结构
typedef struct _PROCESSCPUUSAGE
{
	WCHAR szExe[37];
	DWORD dwProcessID;
	float fCpuUsage;
}PROCESSCPUUSAGE;
//////////////////////////////////////////进程使用时间
typedef struct _PROCESSTIME
{
	DWORD dwProcessID;
	LARGE_INTEGER g_slgProcessTimeOld;
}PROCESSTIME;
DWORD dNumProcessor = 0;//CPU数量
HINSTANCE hInst;// 当前实例
HWND hMain;//主窗口句柄
HWND hSetting;//设置窗口句柄
HWND hTaskBar;//工具窗口句柄
HWND hTaskTips;//提示窗口句柄
HWND hTime;//秒窗口
HWND hPrice;//行情窗口
//HWND hForeground;
HWND hTray=NULL;//系统主任务栏窗口句柄
HWND hTaskWnd;//系统主任务列表窗口句柄
HWND hReBarWnd=NULL;//系统主任务工具窗口句柄
HWND hTaskListWnd = NULL;
HWND hWin11UI = NULL;
HWND hStartWnd = NULL;
HWND hTrayNotifyWnd = NULL;
HWND hTrayClockWnd = NULL;
HICON iMain;//窗口图标
HANDLE hMutex;//只能运行一个程序
const WCHAR szAppName[] = L"TrayS";//程序名
const WCHAR szNetCpl[] = L" cncpa.cpl";//打开网络设置
const WCHAR szTaskmgr[] = L" oTaskmgr";//打开任务管理器
const WCHAR szPerfmon[] = L" operfmon.exe /res";//打开资源监测器
const WCHAR szOpenPerfDisk[] = L" olodctr /E:PerfDisk";//修复磁盘计数器
const WCHAR szCompmgmt[] = L" ocompmgmt.msc";//计算机管理
const WCHAR szPowerCpl[] = L" cpowercfg.cpl";//打开电源设置
const WCHAR szTimeDateCpl[] = L" ctimedate.cpl";//打开时间日期
const WCHAR szTraySave[] = L"TrayS.dat";
//PIP_ADAPTER_INFO ipinfo;
typedef struct _TRAYDATA
{
	BOOL bExit;//是否退出
	ULONG64 m_last_in_bytes;//总上一秒下载速度
	ULONG64 m_last_out_bytes;//总上一秒上传速度
	ULONG64 s_in_byte;//总下载速度
	ULONG64 s_out_byte;//总上传速度
	float fLastPrice1,fLastPrice2, fOpenPrice1, fOpenPrice2, fLastPrice3, fLastPrice4, fOpenPrice3, fOpenPrice4;//行情当前与昨天
	WCHAR szLastPrice1[16];//行情数值字符串
	WCHAR szLastPrice2[16];//行情数值字符串
	WCHAR szLastPrice3[16];//行情数值字符串
	WCHAR szLastPrice4[16];//行情数值字符串
	int iPriceUpDown[4];//行情升降提醒
	DWORD iHddTemperature;//硬盘温度
	DWORD iTemperature1;//CPU温度
	DWORD iTemperature2;//GPU温度
	double diskreadbyte;
	double diskwritebyte;
	DWORD disktime;
	/*
	int rNum=60;
	DWORD s_in_bytes[60];//一分钟内的下载数据
	DWORD s_out_bytes[60];//一分钟内的上传数据
	int iBytes = 0;//当前数据指针
	*/
}TRAYDATA;
TRAYDATA* TrayData;
PMIB_IFTABLE mi;//网速结构
PIP_ADAPTER_ADDRESSES piaa;//网卡结构
PMIB_IF_TABLE2 mit2;//网速结构
TRAFFIC* traffic;//每个网卡速度
int nTraffic = 0;//有几张网卡

int mWidth;//工具窗口宽度
int mHeight;//工具窗口竖排高度
int wSpace;//模块间隔
int iDPI = 96;//当前DPI
BOOL VTray = FALSE;//竖的任务栏
BOOL bRealClose = FALSE;
BOOL bSetting = FALSE;
/////////////////////////////////////////////////获取数据线程
DWORD WINAPI MainThreadProc(PVOID pParam);
DWORD WINAPI GetDataThreadProc(PVOID pParam);
//HANDLE hMainThread = NULL;
HANDLE hGetDataThread = NULL;
HANDLE hPriceThread = NULL;
HANDLE hMap = NULL;
BOOL bShadow = FALSE;//显示阴影文字
COLORREF bColor = 0x181818;//阴影颜色
DWORD bThemeMode = 0;//颜色模式


RTL_OSVERSIONINFOW rovi;//WIN系统版本号
///////////////////////////////////////////是否在全屏幕
BOOL bFullScreen = FALSE;

typedef struct _TRAYSAVE//默认参数
{
	DWORD Ver;//数据版本
	ACCENT_STATE aMode[2];//任务栏透明模式
	DWORD dAlphaColor[2];//任务栏颜色
	DWORD bAlpha[2];//
	DWORD dNumValues[12];
	BOOL bSound;//声音警告
	int iPos;//任务栏图标位置
	int iUnit;//流量单位
	BOOL bTrayIcon;//显示托盘图标
	BOOL bMonitor;//显示监控主窗口
	BOOL bMonitorLeft;//左上显示窗口
	BOOL bMonitorFloat;//浮动显示窗口
	BOOL bMonitorTransparent;//鼠标穿透//透明显示窗口
	BOOL bMonitorTraffic;//显示流量
	BOOL bMonitorTemperature;//显示温度
	BOOL bMonitorUsage;//显示占用
	BOOL bMonitorPDH;//高精度占用
	int iMonitorSimple;//简约显示
	COLORREF cMonitorColor[8];//颜色
	POINT dMonitorPoint;//浮动位置
	CHAR AdpterName[39];//网卡名
	DWORD FlushTime;//刷新时间
	BOOL bMonitorTips;//显示提示窗口
	LOGFONT TraybarFont;//监控窗口字体
	int TraybarFontSize;//监控字体大小
	LOGFONT TipsFont;//提示窗口字体
	int TipsFontSize;//提示窗口大小
	WCHAR szTrafficOut[8];//流量上传显示的文字
	WCHAR szTrafficIn[8];//流量正传显示的文字
	WCHAR szTemperatureCPU[8];//CPU温度显示的文字
	WCHAR szTemperatureCPUUnit[4];//CPU温度显示的单位
	WCHAR szTemperatureGPU[8];//GPU温度显示的文字
	WCHAR szTemperatureGPUUnit[4];//GPU温度显示的单位
	WCHAR szUsageCPU[8];//CPU占用显示的文字
	WCHAR szUsageCPUUnit[4];//CPU占用显示的单位
	WCHAR szUsageMEM[8];//内存占用显示的文字
	WCHAR szUsageMEMUnit[4];//内存占用显示的单位
	BOOL bMonitorFuse;//背景融合
	BOOL bMonitorTrafficUpDown;//上传下载位置调换
	BOOL bMonitorFloatVRow;//浮动竖排
	BOOL bMonitorTime;//显示时间
	BOOL bSecond;//在系统原来显示秒
	BOOL bNear;//靠近图标
	BOOL bMonitorTopmost;//任务栏窗口保持置顶
	BOOL bMonitorDisk;//显示硬盘
	DWORD dNumValues2[9];
	WCHAR szDiskReadSec[8];//硬盘读取显示的文字
	WCHAR szDiskWriteSec[8];//硬盘写入显示的文字
	WCHAR szDiskName[8];//硬盘名称
	WCHAR szDisk;//盘符
	BOOL bMonitorPrice;//显示行情
	float HighRemind[12];//超过价格提醒
	float LowRemind[12];//低过价格提醒
	BOOL bCheckHighRemind[12];
	BOOL bCheckLowRemind[12];
	WCHAR szPriceName1[64];
	WCHAR szPriceName2[64];
	WCHAR szPriceName3[64];
	WCHAR szPriceName4[64];
	int iPriceInterface[4];
	WCHAR szOKXWeb[32];
	BOOL bTwoFour;
	COLORREF cPriceColor[4];//行情颜色
	BOOL bTrayStyle;//任务栏风格开关
}TRAYSAVE;
TRAYSAVE TraySave = {
	116,
	{ ACCENT_ENABLE_TRANSPARENTGRADIENT,ACCENT_ENABLE_BLURBEHIND } ,
	{ 0x00111111,0x66000000 },{ 255,255 } ,
	{ 10 * 1024 * 1024,64 * 1024 * 1024,66,96,81,96,61,88,98 * 1048576,88,0,0 } ,
	FALSE,
	1,
	2,
	TRUE,
	TRUE,
	FALSE,
	FALSE,
	FALSE,
	TRUE,
	FALSE,
	TRUE,
	FALSE,
	0,
	{ RGB(0,0,1),RGB(128,128,128),RGB(255,255,255),RGB(255,0,0),RGB(0,168,0),RGB(255,128,0),RGB(255,0,0),RGB(0,0,0) },
	{ 666,666 },
	{0},
	11,
	TRUE,
	{-14,0,0,0,FW_BOLD,0,0,0,0,0,0,0,0,L"微软雅黑"} ,
	-14,
	{-14,0,0,0,FW_NORMAL,0,0,0,0,0,0,0,0,L"微软雅黑"} ,
	-14,
	L"上传:",
	L"下载:",
	L"CPU:",
	L"℃",
	L"GPU:",
	L"℃",
	L"CPU:" ,
	L"%",
	L"内存:",
	L"%",
	TRUE,
	TRUE,
	FALSE,
	TRUE,
	FALSE,
	FALSE,
	FALSE,
	FALSE,
	{18,111,88,0,0,0,0,0,0},
	L"读取:",
	L"写入:",
	L"硬盘:",
	0,
	FALSE,
	{0},
	{0},
	{0},
	{0},
	L"sh000001",
	L"sz399001",
	L"BTC-USDT-SWAP",
	L"ETH-USDT-SWAP",
	{0,0,1,1},
	L"www.okx.com",
	FALSE,
	{RGB(0, 168, 0), RGB(255, 0, 0),RGB(0,255,128),RGB(255,128,0)},
	TRUE
};
int wTraffic;//流量宽度
int wTemperature;//温度宽度
int wUsage;//利用率宽度
int wDisk;//硬盘流量宽度
int wTime;//时间宽度
int wPrice;//行情宽度
int wHeight;//监控字符高度
POINT pTime;//秒位置
HFONT hFont;//监控窗口字体
BOOL bSettingInit=FALSE;//设置在初始化
int wTipsHeight;//提示字符高度
BOOL inTipsProcessX = FALSE;//是否在X按键中
NOTIFYICONDATA nid = { 0 };//通知栏传入结构
//BOOL bErasebkgnd = TRUE;
int iProject = -1;
int iWindowMode=FALSE;
//BOOL bAccentNormal = FALSE;
MEMORYSTATUSEX MemoryStatusEx;/////////////////虚拟内存/内存大小
BOOL bTaskBarMoveing = FALSE;///////////////////窗口是否正在移动中
PROCESSMEMORYUSAGE pmu[6];
PROCESSMEMORYUSAGE *ppmu[6];
PROCESSCPUUSAGE pcu[6];
PROCESSCPUUSAGE *ppcu[6];
int nProcess;
PROCESSTIME * pProcessTime;

//BOOL bTaskOther = FALSE;

////////////////////////////////////////LibHardware库
HMODULE hOHMA = NULL;
typedef void(WINAPI* pfnGetTemperature)(float* fCpu, float* fGpu, float* fMain, float* fHdd,int iHdd, float* fCpuPackge);
pfnGetTemperature GetTemperature;

HMODULE hPDH = NULL;
////////////////////////////////////////////////查找隐藏试最大化窗口
HMODULE hDwmapi=NULL;
typedef BOOL(WINAPI* pfnDwmGetWindowAttribute)(HWND hwnd, DWORD dwAttribute, PVOID pvAttribute, DWORD cbAttribute);
pfnDwmGetWindowAttribute pDwmGetWindowAttribute;

////////////////////////////////////////////////获取网速
HMODULE hIphlpapi=NULL;
typedef ULONG(WINAPI* pfnGetAdaptersAddresses)(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved, _Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer);
typedef DWORD(WINAPI* pfnGetIfTable)(_Out_writes_bytes_opt_(*pdwSize) PMIB_IFTABLE pIfTable, _Inout_ PULONG pdwSize, _In_ BOOL bOrder);
pfnGetAdaptersAddresses GetAdaptersAddressesT;
pfnGetIfTable GetIfTableT;
typedef DWORD(WINAPI* pfnGetIfTable2)(PMIB_IF_TABLE2* Table);
pfnGetIfTable2 getIfTable2;
typedef VOID (WINAPI* pfnFreeMibTable)(PVOID Memory);
pfnFreeMibTable freeMibTable;
HMODULE hOleacc=NULL;
typedef ULONG(WINAPI* pfnAccessibleObjectFromWindow)(_In_ HWND hwnd, _In_ DWORD dwId, _In_ REFIID riid, _Outptr_ void** ppvObject);
typedef ULONG(WINAPI* pfnAccessibleChildren)(_In_ IAccessible* paccContainer, _In_ LONG iChildStart, _In_ LONG cChildren, _Out_writes_(cChildren) VARIANT* rgvarChildren, _Out_ LONG* pcObtained);
pfnAccessibleObjectFromWindow AccessibleObjectFromWindowT;
pfnAccessibleChildren AccessibleChildrenT;

/////////////////////////////////////////////////CPU温度
BOOL bRing0=NULL;
HMODULE m_hOpenLibSys = NULL;
BOOL bIntel;
////////////////////////////////////////////////ATI显卡温度
// Memory allocation function
void* __stdcall ADL_Main_Memory_Alloc(int iSize)
{
	void* lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, iSize);
	return lpBuffer;
}
// Optional Memory de-allocation function
void __stdcall ADL_Main_Memory_Free(void** lpBuffer)
{
	if (NULL != *lpBuffer)
	{
		HeapFree(GetProcessHeap(), 0, *lpBuffer);
		*lpBuffer = NULL;
	}
}
// Definitions of the used function pointers. Add more if you use other ADL APIs
typedef int(*ADL_MAIN_CONTROL_CREATE)(ADL_MAIN_MALLOC_CALLBACK, int);
typedef int(*ADL_MAIN_CONTROL_DESTROY)();
typedef int(*ADL_OVERDRIVE5_TEMPERATURE_GET) (int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
ADL_MAIN_CONTROL_CREATE					ADL_Main_Control_Create;
ADL_MAIN_CONTROL_DESTROY				ADL_Main_Control_Destroy;
ADL_OVERDRIVE5_TEMPERATURE_GET			ADL_Overdrive5_Temperature_Get;
ADLTemperature adlTemperature = { 0 };
HMODULE hATIDLL=NULL;
///////////////////////////////////////////////NVIDIA显卡温度
// 接口ID值
#define ID_NvAPI_Initialize                     0x0150E828
#define ID_NvAPI_GPU_GetFullName                0xCEEE8E9F
#define ID_NvAPI_GPU_GetThermalSettings         0xE3640A56
#define ID_NvAPI_EnumNvidiaDisplayHandle        0x9ABDD40D
#define ID_NvAPI_GetPhysicalGPUsFromDisplay     0x34EF9506
#define ID_NvAPI_EnumPhysicalGPUs               0xE5AC921F
#define ID_NvAPI_GPU_GetTachReading             0x5F608315
#define ID_NvAPI_GPU_GetAllClocks               0x1BD69F49
#define ID_NvAPI_GPU_GetPStates                 0x60DED2ED
#define ID_NvAPI_GPU_GetUsages                  0x189A1FDF
#define ID_NvAPI_GPU_GetCoolerSettings          0xDA141340
#define ID_NvAPI_GPU_SetCoolerLevels            0x891FA0AE
#define ID_NvAPI_GPU_GetMemoryInfo              0x774AA982
#define ID_NvAPI_GetDisplayDriverVersion        0xF951A4D1
#define ID_NvAPI_GetInterfaceVersionString      0x01053FA5
#define ID_NvAPI_GPU_GetPCIIdentifiers          0x2DDFB66E
#define NVAPI_MAX_THERMAL_SENSORS_PER_GPU 3
#define NVAPI_MAX_PHYSICAL_GPUS 64
#define NvU32 unsigned long
#define NvS32 signed int 
#define MAKE_NVAPI_VERSION(typeName,ver)(NvU32)(sizeof(typeName) | ((ver) << 16))
typedef int NvPhysicalGpuHandle;
typedef int NvDisplayHandle;
#define MAX_THERMAL_SENSORS_PER_GPU     3
typedef enum _NV_THERMAL_CONTROLLER
{
	NVAPI_THERMAL_CONTROLLER_NONE = 0,
	NVAPI_THERMAL_CONTROLLER_GPU_INTERNAL,
	NVAPI_THERMAL_CONTROLLER_ADM1032,
	NVAPI_THERMAL_CONTROLLER_MAX6649,
	NVAPI_THERMAL_CONTROLLER_MAX1617,
	NVAPI_THERMAL_CONTROLLER_LM99,
	NVAPI_THERMAL_CONTROLLER_LM89,
	NVAPI_THERMAL_CONTROLLER_LM64,
	NVAPI_THERMAL_CONTROLLER_ADT7473,
	NVAPI_THERMAL_CONTROLLER_SBMAX6649,
	NVAPI_THERMAL_CONTROLLER_VBIOSEVT,
	NVAPI_THERMAL_CONTROLLER_OS,
	NVAPI_THERMAL_CONTROLLER_UNKNOWN = -1,
} NV_THERMAL_CONTROLLER;
typedef enum _NV_THERMAL_TARGET
{
	NVAPI_THERMAL_TARGET_NONE = 0,
	NVAPI_THERMAL_TARGET_GPU = 1,     //!< GPU core temperature requires NvPhysicalGpuHandle
	NVAPI_THERMAL_TARGET_MEMORY = 2,     //!< GPU memory temperature requires NvPhysicalGpuHandle
	NVAPI_THERMAL_TARGET_POWER_SUPPLY = 4,     //!< GPU power supply temperature requires NvPhysicalGpuHandle
	NVAPI_THERMAL_TARGET_BOARD = 8,     //!< GPU board ambient temperature requires NvPhysicalGpuHandle
	NVAPI_THERMAL_TARGET_VCD_BOARD = 9,     //!< Visual Computing Device Board temperature requires NvVisualComputingDeviceHandle
	NVAPI_THERMAL_TARGET_VCD_INLET = 10,    //!< Visual Computing Device Inlet temperature requires NvVisualComputingDeviceHandle
	NVAPI_THERMAL_TARGET_VCD_OUTLET = 11,    //!< Visual Computing Device Outlet temperature requires NvVisualComputingDeviceHandle

	NVAPI_THERMAL_TARGET_ALL = 15,
	NVAPI_THERMAL_TARGET_UNKNOWN = -1,
} NV_THERMAL_TARGET;
typedef struct _NV_GPU_THERMAL_SETTINGS_V1
{
	NvU32   version;                //!< structure version
	NvU32   count;                  //!< number of associated thermal sensors
	struct
	{
		NV_THERMAL_CONTROLLER       controller;        //!< internal, ADM1032, MAX6649...
		NvU32                       defaultMinTemp;    //!< The min default temperature value of the thermal sensor in degree Celsius
		NvU32                       defaultMaxTemp;    //!< The max default temperature value of the thermal sensor in degree Celsius
		NvU32                       currentTemp;       //!< The current temperature value of the thermal sensor in degree Celsius
		NV_THERMAL_TARGET           target;            //!< Thermal sensor targeted @ GPU, memory, chipset, powersupply, Visual Computing Device, etc.
	} sensor[NVAPI_MAX_THERMAL_SENSORS_PER_GPU];

} NV_GPU_THERMAL_SETTINGS_V1;
typedef struct _NV_GPU_THERMAL_SETTINGS_V2
{
	NvU32   version;                //!< structure version
	NvU32   count;                  //!< number of associated thermal sensors
	struct
	{
		NV_THERMAL_CONTROLLER       controller;         //!< internal, ADM1032, MAX6649...
		NvS32                       defaultMinTemp;     //!< Minimum default temperature value of the thermal sensor in degree Celsius
		NvS32                       defaultMaxTemp;     //!< Maximum default temperature value of the thermal sensor in degree Celsius
		NvS32                       currentTemp;        //!< Current temperature value of the thermal sensor in degree Celsius
		NV_THERMAL_TARGET           target;             //!< Thermal sensor targeted - GPU, memory, chipset, powersupply, Visual Computing Device, etc
	} sensor[NVAPI_MAX_THERMAL_SENSORS_PER_GPU];

} NV_GPU_THERMAL_SETTINGS_V2;
typedef NV_GPU_THERMAL_SETTINGS_V2  NV_GPU_THERMAL_SETTINGS;
#define NV_GPU_THERMAL_SETTINGS_VER_1   MAKE_NVAPI_VERSION(NV_GPU_THERMAL_SETTINGS_V1,1)
#define NV_GPU_THERMAL_SETTINGS_VER_2   MAKE_NVAPI_VERSION(NV_GPU_THERMAL_SETTINGS_V2,2)
#define NV_GPU_THERMAL_SETTINGS_VER     NV_GPU_THERMAL_SETTINGS_VER_2
typedef UINT32 NvAPI_Status;
typedef void* (*NvAPI_QueryInterface_t)(UINT32 offset);
typedef NvAPI_Status(__cdecl *NvAPI_Initialize_t)(void);
typedef NvAPI_Status(*NvAPI_EnumPhysicalGPUs_t)(NvPhysicalGpuHandle *pGpuHandles, int *pGpuCount);
typedef NvAPI_Status(__cdecl *NvAPI_GPU_GetThermalSettings_t)(const NvPhysicalGpuHandle gpuHandle, int sensorIndex, NV_GPU_THERMAL_SETTINGS *pnvGPUThermalSettings);
NvAPI_QueryInterface_t NvAPI_QueryInterface;
NvAPI_GPU_GetThermalSettings_t NvAPI_GPU_GetThermalSettings;
HMODULE hNVDLL = NULL;
NvPhysicalGpuHandle hPhysicalGpu[4];
/////////////////////////////////////////////////////CPU频率
typedef struct _PROCESSOR_POWER_INFORMATION {
	ULONG Number;
	ULONG MaxMhz;
	ULONG CurrentMhz;
	ULONG MhzLimit;
	ULONG MaxIdleState;
	ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;


INT_PTR CALLBACK    ColorButtonProc(HWND, UINT, WPARAM, LPARAM);//颜色按钮子类化过程
WNDPROC oldColorButtonPoroc;//原来的颜色按钮控件过程
void AdjustWindowPos();//////////////////////////////////////////调整窗口大小位置
BOOL                InitInstance(HINSTANCE, int);//////////////////////////////////////初始化
INT_PTR CALLBACK    MainProc(HWND, UINT, WPARAM, LPARAM);//主窗口过程
INT_PTR CALLBACK    SettingProc(HWND, UINT, WPARAM, LPARAM);//设置窗口过程
INT_PTR CALLBACK    TaskBarProc(HWND, UINT, WPARAM, LPARAM);//任务栏监控窗口过程
INT_PTR CALLBACK    TaskTipsProc(HWND, UINT, WPARAM, LPARAM);//提示窗口过程
INT_PTR CALLBACK    TimeProc(HWND, UINT, WPARAM, LPARAM);//秒窗口过程
INT_PTR CALLBACK    PriceProc(HWND, UINT, WPARAM, LPARAM);//行情窗口过程
void SetTaskBarPos(HWND, HWND, HWND, HWND, BOOL);//设置任务栏图标位置
int DrawShadowText(HDC hDC, LPCTSTR lpString, int nCount, LPRECT lpRect, UINT uFormat);//绘制阴影文字
void FreeTemperatureDLL();//
void LoadTemperatureDLL();//加载DLL
void SetWH();//计算监控窗口高宽
int GetProcessMemUsage();//获取内存使用大小
void GetProcessCpuUsage();//获取进程CPU使用率
void GetTrafficStr(WCHAR* sz, ULONG64 uByte, BOOL bBit,int iUnit=0);//流量转字符串
void ShowSelectMenu(BOOL bNet);//显示网卡/硬盘菜单
void DrawPrice(HDC mdc, LPRECT crc, float fLast, float fOpen, WCHAR* szLast, int iPriceUpDown);//绘制行情