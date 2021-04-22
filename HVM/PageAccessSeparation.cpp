#include "PageAccessSeparation.h"
#include "PageHook.h"
#include "Util.h"

EXTERN_C_BEGIN

//已隐藏的页面-双向链表
PgEntry* g_pgEntry;

/// <summary>
/// 初始化工作,需在隐藏页面前调用一次
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/9</changed>
NTSTATUS PASInitialize()
{
	g_pgEntry = (PgEntry*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PgEntry), 'bp');
	if (!g_pgEntry)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(g_pgEntry, sizeof(PgEntry));
	InitializeListHead(&g_pgEntry->pageList);
	return STATUS_SUCCESS;
}

/// <summary>
/// 通过pte权限分离,实现隐藏真实的物理页
/// </summary>
/// <param name="targetAddressVa">目标虚拟地址</param>
/// <param name="eptAccess">要改写的权限</param>
/// <param name="outPgEntry">传出参数,页项</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/14</changed>
NTSTATUS PASHidePage(PVOID targetAddressVa, EptAccess eptAccess,OUT PgEntry** outPgEntry)
{
	bool isReplaced = false;
	for (LIST_ENTRY* pLink = g_pgEntry->pageList.Flink; pLink != (PLIST_ENTRY)&g_pgEntry->pageList.Flink; pLink = pLink->Flink)
	{
		PgEntry* tmpPgEntry = CONTAINING_RECORD(pLink, PgEntry, pageList);
		//判断目标页是否已被替换过
		if (tmpPgEntry->pageAddressVa == (ULONG_PTR)targetAddressVa)
		{
			isReplaced = true;
			break;
		}
	}
	if (isReplaced == false)
	{
		//配置pgae项
		PgEntry*pgEntry = (PgEntry*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PgEntry), 'pg');
		if (!pgEntry)
		{
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlZeroMemory(pgEntry, sizeof(PgEntry));
		pgEntry->targetAddressVa = (ULONG_PTR)targetAddressVa;
		pgEntry->pageAddressVa = (ULONG_PTR)PAGE_ALIGN(targetAddressVa);
		//DbgBreakPoint();
		InsertHeadList(&g_pgEntry->pageList, &pgEntry->pageList);

		//获取目标地址对应的pte
		EptEntry* pte = EptGetPtEntry(eptCtrl.pml4t, MmGetPhysicalAddress(targetAddressVa).QuadPart);
		pgEntry->pte = pte;
		//目标页首地址
		PVOID targetPageHeadVa = PAGE_ALIGN(targetAddressVa);
		//配置假页面
		pgEntry->shadowPageAddressVa = (ULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'fake');
		if (!pgEntry->shadowPageAddressVa)
		{
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlMoveMemory((PVOID)pgEntry->shadowPageAddressVa, targetPageHeadVa, PAGE_SIZE);
		//phData->readWritePagePa = UtilVaToPa(phData->readWritePageVa);

		PVOID NtLoadDriver = (PVOID)0xFFFFF800043594F0;
		mem_protect_close();
		*(PCHAR)NtLoadDriver = 0xCC;
		mem_protect_open();

		//配置权限
		pte->fields.readAccess = (eptAccess & EptAccess::EptAccessRead) >> 0;
		pte->fields.writeAccess = (eptAccess & EptAccess::EptAccessWrite) >> 1;
		pte->fields.executeAccess = (eptAccess & EptAccess::EptAccessExecute) >> 2;
		pte->fields.memoryType = kWriteBack;
		*outPgEntry = pgEntry;
	}

	return STATUS_SUCCESS;

}

NTSTATUS PASUnHidePage(ULONG_PTR bpAddress)
{
	return STATUS_SUCCESS;
}


EXTERN_C_END