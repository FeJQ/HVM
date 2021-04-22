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
/// ���VMCS
/// </summary>
/// <param name="vCpu">��ǰ������VMX������</param>
/// <param name="guestStack">�ͻ���Rsp</param>
/// <param name="guestResumeRip">�ͻ���Rip</param>
/// <returns>�ɹ����</returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/28</changed>
Private BOOLEAN VmSetupVMCS(VMX_CPU* vCpu, PVOID guestStack, PVOID guestResumeRip);

/// <summary>
/// ���ͻ�����ѡ����
/// </summary>
/// <param name="gdtBase"></param>
/// <param name="segreg"></param>
/// <param name="selector"></param>
/// <returns></returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/7/6</changed>
Private NTSTATUS FillGuestSelectorData(const ULONG_PTR gdtBase, ULONG segreg, USHORT selector);

/// <summary>
/// ���ض�������
/// </summary>
/// <param name="segmentSelector">��������������</param>
/// <param name="selector">��ѡ����</param>
/// <param name="gdtBase">GDT��ַ</param>
/// <returns>״̬</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
Private NTSTATUS VmLoadSementDescriptor(OUT SEGMENT_SELECTOR* segmentSelector, USHORT selector, ULONG_PTR gdtBase);

/// <summary>
/// ��ȡ������������Ȩ��
/// </summary>
/// <param name="segmentSelector">��ѡ����</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/7</created>
/// <changed>FeJQ,2020/7/7</changed>
Private ULONG VmGetSegmentAccessRight(USHORT selector);
/// <summary>
/// ���VMX�Ƿ����
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS VmIsVmxAvailable();

/// <summary>
/// ����VMX��ռ�
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/24</changed>
Private NTSTATUS VmAllocateVMXRegion();


/// <summary>
/// ����VMX����
/// </summary>
/// <param name="arg1">δ�õ�</param>
/// <param name="arg2">δ�õ�</param>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/9/12</changed>
Private NTSTATUS VmxEnableVmxFeature(void* arg1, void* arg2);

/// <summary>
/// �ڵ�ǰ�������Ͽ���VMX
/// </summary>
/// <param name="guestStack">�ͻ���rsp</param>
/// <param name="guestResumeRip">�ͻ���rip</param>
/// <returns>�ɹ����</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
BOOLEAN VmLaunchVmx(PVOID guestStack, PVOID guestResumeRip);


/// <summary>
/// �ڵ�ǰ���������˳�Vmx
/// </summary>
/// <param name="arg1">δ�õ�</param>
/// <param name="arg2">δ�õ�</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/3</created>
/// <changed>FeJQ,2020/9/12</changed>
NTSTATUS VmQuitVmx(void* arg1, void* arg2);

/// <summary>
/// ����Rootģʽ,ִ��vmxon,����VMCS
/// </summary>
/// <param name="vCpu">VMX������</param>
/// <returns>�ɹ����</returns>
/// <created>FeJQ,2020/6/27</created>
/// <changed>FeJQ,2020/6/27</changed>
Private BOOLEAN VmEnableRoot(VMX_CPU* vCpu);

/// <summary>
/// ����Msr�Ĵ���ֵ
/// </summary>
/// <param name="msr"></param>
/// <param name="ctl"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/3</created>
/// <changed>FeJQ,2020/7/3</changed>
Private ULONG VmxAdjustControlValue(ULONG msr, ULONG ctl);


/// <summary>
/// AsmVmx.asm���vmm��ڵ�
/// </summary>
/// <created>FeJQ,2020/7/6</created>
/// <changed>FeJQ,2020/7/6</changed>
void __stdcall AsmVmmEntryPoint();


/// <summary>
/// AsmVmx.asm��ļ��ض�����������Ȩ��
/// </summary>
/// <param name="segmentSelector"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/7</created>
/// <changed>FeJQ,2020/7/7</changed>
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segmentSelector);

/// <summary>
/// ����MTF
/// </summary>
/// <param name="state">״̬</param>
/// <created>FeJQ,2020/8/9</created>
/// <changed>FeJQ,2020/8/9</changed>
void VmSetMonitorTrapFlag(BOOLEAN state);

EXTERN_C_END
#endif // !_HVM_VMX_H_



