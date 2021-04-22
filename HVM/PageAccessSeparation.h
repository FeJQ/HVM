#pragma once
#ifndef _HVM_PAGEACCESSSEPARATION_H_
#define _HVM_PAGEACCESSSEPARATION_H_

#include "Common.h"
#include "Ept.h"

EXTERN_C_BEGIN

struct PgEntry
{
	LIST_ENTRY pageList;
	//Ŀ��ָ�����ڵĵ�ַ
	ULONG_PTR targetAddressVa;
	//Ŀ��ҳ�׵�ַ
	ULONG_PTR pageAddressVa;
	//��ҳ�׵�ַ
	ULONG_PTR shadowPageAddressVa;
	//Ŀ��ҳ����Ӧ��pte
	EptEntry* pte;
	
	ULONG_PTR readPage;
	ULONG_PTR writePage;
	ULONG_PTR excutePage;
	
};

extern PgEntry* g_pgEntry;


/// <summary>
/// ��ʼ������,��������ҳ��ǰ����һ��
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/9</changed>
NTSTATUS PASInitialize();

/// <summary>
/// ͨ��pteȨ�޷���,ʵ��������ʵ������ҳ
/// </summary>
/// <param name="targetAddressVa">Ŀ�������ַ</param>
/// <param name="eptAccess">Ҫ��д��Ȩ��</param>
/// <param name="outPgEntry">��������,ҳ��</param>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/14</changed>
NTSTATUS PASHidePage(PVOID targetAddressVa, EptAccess eptAccess, OUT PgEntry** outPgEntry);

NTSTATUS PASUnHidePage(ULONG_PTR bpAddress);


EXTERN_C_END
#endif
