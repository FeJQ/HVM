#pragma once
#ifndef _HVM_SYSCALLHOOK_H_
#define _HVM_SYSCALLHOOK_H_

#include "Common.h"

EXTERN_C_BEGIN

typedef struct _SERVICE_DESCRIPTOR_TABLE 
{

	PLONG32 serviceTable;
	PULONG  counterTable;
	ULONG   tableSize;
	PUCHAR  argumentTable;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE_SHADOW 
{
	PLONG32 ssdtServiceTable;
	PULONG  ssdtCounterTable;
	ULONG	ssdtTableSize;
	PUCHAR  ssdtArgumentTable;

	PLONG32 serviceTable;
	PULONG  counterTable;
	ULONG	tableSize;
	PUCHAR  argumentTable;
} SERVICE_DESCRIPTOR_TABLE_SHADOW, * PSERVICE_DESCRIPTOR_TABLE_SHADOW;

/// <summary>
/// 初始化msr:lstar hook
/// </summary>
/// <returns>状态</returns>
/// <created>FeJQ,2020/9/13</created>
/// <changed>FeJQ,2020/9/13</changed>
NTSTATUS ShInitializeSystemCallHook();

/// <summary>
/// 代理系统调用入口
/// </summary>
/// <created>FeJQ,2020/9/12</created>
/// <changed>FeJQ,2020/9/12</changed>
void DetourKiSystemCall64();



EXTERN_C_END
#endif // !_HVM_SYSCALLHOOK_H_
