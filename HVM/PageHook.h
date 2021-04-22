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
	//hook�������
	HookData* hookData;
};

extern PhData g_phData[HookFunction::FunctionCount];

/// <summary>
/// Ept Page Hook
/// </summary>
/// <param name="target">Ҫhook�ĵ�ַ</param>
/// <param name="detour">Ŀ�꺯����ַ</param>
/// <param name="phData">hook���������ݻ�����</param>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/8/9</changed>
void PhHook(PVOID target, PVOID detour, OUT PhData* phData);

/// <summary>
/// ����hook����������ȡhook����
/// </summary>
/// <param name="functionIndex">��������</param>
/// <returns>hook����</returns>
/// <created>FeJQ,2020/9/21</created>
/// <changed>FeJQ,2020/9/21</changed>
PhData* GetHookData(HookFunction functionIndex);


void PhRootine();

ULONG TestFunc(ULONG a1,ULONG a2);

ULONG DetourTestFunc(ULONG a1,ULONG a2);


EXTERN_C_END
#endif // !_HVM_PageHook_H_
