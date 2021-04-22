#pragma once
#ifndef _HVM_VMX_H_
#define _HVM_VMX_H_

#include "Common.h"
#include "VMCS.h"

EXTERN_C_BEGIN

typedef struct _VMX_CPU
{
	PVOID pVmxonRegion;
	PVOID pVmcsRegion;
	PVOID pVmStack;
	PVOID pVmStackBase;

	ULONG64 originalLstar;
	PVOID newKiSystemCall64;
	BOOLEAN bIsVmxEnable;
}VMX_CPU, * PVMX_CPU;

extern VMX_CPU* g_vmxCpu;

NTSTATUS __stdcall AsmVmLaunch(void* arg1, void* arg2);

/// <summary>
/// 填充VMCS
/// </summary>
/// <param name="vCpu">当前处理器VMX上下文</param>
/// <param name="guestStack">客户机Rsp</param>
/// <param name="guestResumeRip">客户机Rip</param>
/// <returns>成功与否</returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/28</changed>
Private BOOLEAN VmSetupVMCS(VMX_CPU* vCpu, PVOID guestStack, PVOID guestResumeRip);

/// <summary>
/// 填充客户机段选择子
/// </summary>
/// <param name="gdtBase"></param>
/// <param name="segreg"></param>
/// <param name="selector"></param>
/// <returns></returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/7/6</changed>
Private NTSTATUS FillGuestSelectorData(const ULONG_PTR gdtBase, ULONG segreg, USHORT selector);

/// <summary>
/// 加载段描述符
/// </summary>
/// <param name="segmentSelector">段描述符缓冲区</param>
/// <param name="selector">段选择子</param>
/// <param name="gdtBase">GDT地址</param>
/// <returns>状态</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
Private NTSTATUS VmLoadSementDescriptor(OUT SEGMENT_SELECTOR* segmentSelector, USHORT selector, ULONG_PTR gdtBase);

/// <summary>
/// 获取段描述符访问权限
/// </summary>
/// <param name="segmentSelector">段选择子</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/7</created>
/// <changed>FeJQ,2020/7/7</changed>
Private ULONG VmGetSegmentAccessRight(USHORT selector);
/// <summary>
/// 检查VMX是否可用
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS VmIsVmxAvailable();

/// <summary>
/// 申请VMX域空间
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/24</changed>
Private NTSTATUS VmAllocateVMXRegion();


/// <summary>
/// 开启VMX特征
/// </summary>
/// <param name="arg1">未用到</param>
/// <param name="arg2">未用到</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/9/12</changed>
Private NTSTATUS VmxEnableVmxFeature(void* arg1, void* arg2);

/// <summary>
/// 在当前处理器上开启VMX
/// </summary>
/// <param name="guestStack">客户机rsp</param>
/// <param name="guestResumeRip">客户机rip</param>
/// <returns>成功与否</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
BOOLEAN VmLaunchVmx(PVOID guestStack, PVOID guestResumeRip);


/// <summary>
/// 在当前处理器上退出Vmx
/// </summary>
/// <param name="arg1">未用到</param>
/// <param name="arg2">未用到</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/3</created>
/// <changed>FeJQ,2020/9/12</changed>
NTSTATUS VmQuitVmx(void* arg1, void* arg2);

/// <summary>
/// 开启Root模式,执行vmxon,激活VMCS
/// </summary>
/// <param name="vCpu">VMX上下文</param>
/// <returns>成功与否</returns>
/// <created>FeJQ,2020/6/27</created>
/// <changed>FeJQ,2020/6/27</changed>
Private BOOLEAN VmEnableRoot(VMX_CPU* vCpu);

/// <summary>
/// 调整Msr寄存器值
/// </summary>
/// <param name="msr"></param>
/// <param name="ctl"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/3</created>
/// <changed>FeJQ,2020/7/3</changed>
Private ULONG VmxAdjustControlValue(ULONG msr, ULONG ctl);


/// <summary>
/// AsmVmx.asm里的vmm入口点
/// </summary>
/// <created>FeJQ,2020/7/6</created>
/// <changed>FeJQ,2020/7/6</changed>
void __stdcall AsmVmmEntryPoint();


/// <summary>
/// AsmVmx.asm里的加载段描述符访问权限
/// </summary>
/// <param name="segmentSelector"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/7</created>
/// <changed>FeJQ,2020/7/7</changed>
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segmentSelector);

/// <summary>
/// 设置MTF
/// </summary>
/// <param name="state">状态</param>
/// <created>FeJQ,2020/8/9</created>
/// <changed>FeJQ,2020/8/9</changed>
void VmSetMonitorTrapFlag(BOOLEAN state);

EXTERN_C_END
#endif // !_HVM_VMX_H_



