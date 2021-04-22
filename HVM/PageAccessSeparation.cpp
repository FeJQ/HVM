#include "PageAccessSeparation.h"
#include "PageHook.h"
#include "Util.h"

EXTERN_C_BEGIN

//�����ص�ҳ��-˫������
PgEntry* g_pgEntry;

/// <summary>
/// ��ʼ������,��������ҳ��ǰ����һ��
/// </summary>
/// <returns>״̬��</returns>
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
/// ͨ��pteȨ�޷���,ʵ��������ʵ������ҳ
/// </summary>
/// <param name="targetAddressVa">Ŀ�������ַ</param>
/// <param name="eptAccess">Ҫ��д��Ȩ��</param>
/// <param name="outPgEntry">��������,ҳ��</param>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/10/9</created>
/// <changed>FeJQ,2020/10/14</changed>
NTSTATUS PASHidePage(PVOID targetAddressVa, EptAccess eptAccess,OUT PgEntry** outPgEntry)
{
	bool isReplaced = false;
	for (LIST_ENTRY* pLink = g_pgEntry->pageList.Flink; pLink != (PLIST_ENTRY)&g_pgEntry->pageList.Flink; pLink = pLink->Flink)
	{
		PgEntry* tmpPgEntry = CONTAINING_RECORD(pLink, PgEntry, pageList);
		//�ж�Ŀ��ҳ�Ƿ��ѱ��滻��
		if (tmpPgEntry->pageAddressVa == (ULONG_PTR)targetAddressVa)
		{
			isReplaced = true;
			break;
		}
	}
	if (isReplaced == false)
	{
		//����pgae��
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

		//��ȡĿ���ַ��Ӧ��pte
		EptEntry* pte = EptGetPtEntry(eptCtrl.pml4t, MmGetPhysicalAddress(targetAddressVa).QuadPart);
		pgEntry->pte = pte;
		//Ŀ��ҳ�׵�ַ
		PVOID targetPageHeadVa = PAGE_ALIGN(targetAddressVa);
		//���ü�ҳ��
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

		//����Ȩ��
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