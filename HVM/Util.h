#pragma once

#ifndef _HVM_UTIL_H_
#define _HVM_UTIL_H_

#include <ntddk.h>
#include "Common.h"
#include "IA32Structures.h"

EXTERN_C_BEGIN

enum VmcallReason
{
	VmcallVmxOff= 54886475,
	VmcallLstarHookEnable,	
	VmcallLstarHookDisable,
};

/// <summary>
/// �������ַתΪ�����ַ
/// </summary>
/// <param name="virtualAddress"></param>
/// <returns></returns>
/// <created>FeJQ,2020/6/28</created>
/// <changed>FeJQ,2020/6/28</changed>
ULONG_PTR UtilVaToPa(void* virtualAddress);

/// <summary>
/// Ϊÿһ��������ִ�лص�
/// </summary>
/// <param name="NTSTATUS(*routine)(void*)">�ص�����</param>
/// <param name="context">�ص������Ĳ���</param>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS UtilForEachProcessor(NTSTATUS(*routine)(void* arg1, void* arg2), void* context1=NULL, void*context2=NULL);

/// <summary>
/// Ϊÿһ������������DPC
/// </summary>
/// <param name="routine">DPC����</param>
/// <param name="context">����ָ��</param>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS UtilForEachProcessorDpc(PKDEFERRED_ROUTINE routine, void* context);

/// <summary>
/// �ж��Ƿ�Ϊ64λ����
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
bool UtilIsAmd64();

/// <summary>
/// �ж��Ƿ���Debugģʽ
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/9/24</created>
/// <changed>FeJQ,2020/9/24</changed>
bool UtilIsDebug();

/// <summary>
/// ����Ƿ�ҳ�����ڴ�
/// </summary>
/// <param name="size"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
PVOID UtilMalloc(ULONG_PTR size);

/// <summary>
/// �ͷŷǷ�ҳ�����ڴ�
/// </summary>
/// <param name="p"></param>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
void UtilFree(PVOID p);

/// <summary>
/// �����ַת�����ַ
/// </summary>
/// <param name="pa">�����ַ</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/7/27</changed>
void* UtilPaToVa(ULONG64 pa);

ASM ULONG64 __readcs();
ASM ULONG64 __readds();
ASM ULONG64 __reades();
ASM ULONG64 __readss();
ASM ULONG64 __readfs();
ASM ULONG64 __readgs();
ASM ULONG64 __readldtr();
ASM ULONG64 __readtr();
ASM ULONG64 __getidtbase();
ASM ULONG64 __getidtlimit();
ASM ULONG64 __getgdtbase();
ASM ULONG64 __getgdtlimit();
ASM void __invd();
ASM void __vmcall(VmcallReason vmcallReason, VmxoffContext* context);
ASM void __lgdt(void* gdtr);
ASM void __pushall();
ASM void __popall();

ASM void __svreg(Registers64* reg);
ASM void __ldreg(Registers64* reg);

EXTERN_C_END
#endif // !_HVM_UTIL_H_