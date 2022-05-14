#pragma once
#include <memory>
#include "OpenHardwareMonitorGlobal.h"
#include <map>
#include <string>

namespace OpenHardwareMonitorApi
{
    class IOpenHardwareMonitor
    {
    public:
        virtual void GetHardwareInfo() = 0;     //获取一次硬件信息
        virtual float CpuTemperature() = 0;     //返回获取到的CPU温度
        virtual float GpuTemperature() = 0;     //返回获取到的GPU温度
        virtual float HDDTemperature() = 0;     //返回获取到的硬盘温度
        virtual float MainboardTemperature() = 0;   //返回获取到的主板温度
        virtual float GpuUsage() = 0;           //返回获取到的GPU利用率
        virtual const std::map<std::wstring, float>& AllHDDTemperature() = 0;   //返回所有硬盘的温度。map的key是硬盘的名称，value是硬盘的温度
        virtual const std::map<std::wstring, float>& AllCpuTemperature() = 0;   //返回所有CPU（核心）的温度。map的key是CPU的名称，value是硬盘的温度
        virtual const std::map<std::wstring, float>& AllHDDUsage() = 0;         //返回所有硬盘的使用率

        virtual void SetCpuEnable(bool enable) = 0;
        virtual void SetGpuEnable(bool enable) = 0;
        virtual void SetHddEnable(bool enable) = 0;
        virtual void SetMainboardEnable(bool enable) = 0;
    };

    std::shared_ptr<IOpenHardwareMonitor> CreateInstance();
//    OPENHARDWAREMONITOR_API std::wstring GetErrorMessage();
}
std::shared_ptr<OpenHardwareMonitorApi::IOpenHardwareMonitor> m_pMonitor{};
extern "C" OPENHARDWAREMONITOR_API void GetTemperature(float* fCpu,float * fGpu,float* fMain,float *fHdd,int iHDD,float * fCpuPackge)
{
    if (m_pMonitor == 0)
    {
        m_pMonitor = OpenHardwareMonitorApi::CreateInstance();
        if(fCpu)
            m_pMonitor->SetCpuEnable(true);
        if (fGpu)
            m_pMonitor->SetGpuEnable(true);
        if (fHdd)
            m_pMonitor->SetHddEnable(true);
        if (fMain)
            m_pMonitor->SetMainboardEnable(true);        
    }
    m_pMonitor->GetHardwareInfo();
    if (fCpu)
    {
        std::wstring cpu_core_name=L"CPU Core #1";
		auto iter = m_pMonitor->AllCpuTemperature().find(cpu_core_name);
		if (iter == m_pMonitor->AllCpuTemperature().end())
		{
			iter = m_pMonitor->AllCpuTemperature().begin();
		}
		*fCpu = iter->second;
    }
	if (fCpuPackge)
	{
        std::wstring cpu_core_name = L"CPU Package";
        auto iter = m_pMonitor->AllCpuTemperature().find(cpu_core_name);
		if (iter == m_pMonitor->AllCpuTemperature().end())
		{
			iter = m_pMonitor->AllCpuTemperature().begin();
			iter++;
		}
		*fCpuPackge = iter->second;
	}
    if (fGpu)
        *fGpu = m_pMonitor->GpuTemperature();
    if (fMain)
        *fMain = m_pMonitor->MainboardTemperature();
    if (fHdd)
    {
        auto iter = m_pMonitor->AllHDDTemperature().begin();
        if (iHDD == -1)
        {
            size_t n = m_pMonitor->AllHDDTemperature().size();
            float f = 0;
            for (size_t i = 0; i < n; i++)
            {
                if (iter->second > f)
                    f = iter->second;
            }
            *fHdd = f;
        }
        else
        {
            for (int i = 0; i < iHDD; i++)
            {
                ++iter;
            }
            *fHdd = iter->second;
        }
    }
}