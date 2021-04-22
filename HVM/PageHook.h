#pragma once
#ifndef _HVM_PageHook_H_
#define _HVM_PageHook_H_

#include "Common.h"
#include "Ept.h"
#include "KNHook.h"
#include "IA32Structures.h"

EXTERN_C_BEGIN


enum HookFunction
{
	HKNtReadVirtualMemory,
	HKTestFunc,
	FunctionCount,
};



struct PhData
{
	//hook相关数据
	HookData* hookData;
};

extern PhData g_phData[HookFunction::FunctionCount];

/// <summary>
/// Ept Page Hook
/// </summary>
/// <param name="target">要hook的地址</param>
/// <param name="detour">目标函数地址</param>
/// <param name="phData">hook上下文数据缓冲区</param>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/8/9</changed>
void PhHook(PVOID target, PVOID detour, OUT PhData* phData);

/// <summary>
/// 根据hook函数索引获取hook数据
/// </summary>
/// <param name="functionIndex">函数索引</param>
/// <returns>hook数据</returns>
/// <created>FeJQ,2020/9/21</created>
/// <changed>FeJQ,2020/9/21</changed>
PhData* GetHookData(HookFunction functionIndex);


void PhRootine();

ULONG TestFunc(ULONG a1,ULONG a2);

ULONG DetourTestFunc(ULONG a1,ULONG a2);


EXTERN_C_END
#endif // !_HVM_PageHook_H_
