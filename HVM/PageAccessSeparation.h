#pragma once
#ifndef _HVM_PAGEACCESSSEPARATION_H_
#define _HVM_PAGEACCESSSEPARATION_H_

#include "Common.h"
#include "Ept.h"

EXTERN_C_BEGIN

struct PgEntry
{
	LIST_ENTRY pageList;
	//目标指令所在的地址
	ULONG_PTR targetAddressVa;
	//目标页首地址
	ULONG_PTR pageAddressVa;
	//假页首地址
	ULONG_PTR shadowPageAddressVa;
	//目标页所对应的pte
	EptEntry* pte;
	
	ULONG_PTR readPage;
	ULONG_PTR writePage;
	ULONG_PTR excutePage;
	
};

extern PgEntry* g_pgEntry;


/// <summary>
/// 初始化工作,需在隐藏页面前调用一次
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/9</changed>
NTSTATUS PASInitialize();

/// <summary>
/// 通过pte权限分离,实现隐藏真实的物理页
/// </summary>
/// <param name="targetAddressVa">目标虚拟地址</param>
/// <param name="eptAccess">要改写的权限</param>
/// <param name="outPgEntry">传出参数,页项</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/14</changed>
NTSTATUS PASHidePage(PVOID targetAddressVa, EptAccess eptAccess, OUT PgEntry** outPgEntry);

NTSTATUS PASUnHidePage(ULONG_PTR bpAddress);


EXTERN_C_END
#endif
