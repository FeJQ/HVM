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
/// 将虚拟地址转为物理地址
/// </summary>
/// <param name="virtualAddress"></param>
/// <returns></returns>
/// <created>FeJQ,2020/6/28</created>
/// <changed>FeJQ,2020/6/28</changed>
ULONG_PTR UtilVaToPa(void* virtualAddress);

/// <summary>
/// 为每一个处理器执行回调
/// </summary>
/// <param name="NTSTATUS(*routine)(void*)">回调函数</param>
/// <param name="context">回调函数的参数</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS UtilForEachProcessor(NTSTATUS(*routine)(void* arg1, void* arg2), void* context1=NULL, void*context2=NULL);

/// <summary>
/// 为每一个处理器插入DPC
/// </summary>
/// <param name="routine">DPC例程</param>
/// <param name="context">参数指针</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS UtilForEachProcessorDpc(PKDEFERRED_ROUTINE routine, void* context);

/// <summary>
/// 判断是否为64位环境
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
bool UtilIsAmd64();

/// <summary>
/// 判断是否处于Debug模式
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/9/24</created>
/// <changed>FeJQ,2020/9/24</changed>
bool UtilIsDebug();

/// <summary>
/// 申请非分页连续内存
/// </summary>
/// <param name="size"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
PVOID UtilMalloc(ULONG_PTR size);

/// <summary>
/// 释放非分页连续内存
/// </summary>
/// <param name="p"></param>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
void UtilFree(PVOID p);

/// <summary>
/// 物理地址转虚拟地址
/// </summary>
/// <param name="pa">物理地址</param>
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