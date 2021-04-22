#include "PageHook.h"
#include "IA32Structures.h"
#include "Util.h"
#include "Vmx.h"
#include "PageAccessSeparation.h"

EXTERN_C_BEGIN



PhData g_phData[FunctionCount];

/// <summary>
/// Ept Page Hook
/// </summary>
/// <param name="target">Ҫhook�ĵ�ַ</param>
/// <param name="detour">Ŀ�꺯����ַ</param>
/// <param name="phData">hook���������ݻ�����</param>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/8/9</changed>
void PhHook(PVOID target, PVOID detour, OUT PhData* phData)
{
	PgEntry* pgEntry = NULL;
	PASHidePage(target, EptAccessExecute, &pgEntry);
	if (pgEntry == NULL)
	{
		return;
	}
	//��ʼhook
	phData->hookData = KHook(target, detour);
}

void PhHideOpCode(PVOID target, ULONG opCodeLength)
{
	ULONG pageCount = 1;
	while (((LONGLONG)target & 0b111) + opCodeLength > 0x1000)
	{
		pageCount++;
		opCodeLength -= 0x1000;
	}
	for (int i = 0; i < pageCount; i++)
	{
		PVOID pageAddress = (PVOID)((ULONG_PTR)target + (i * 0x1000));
		EptAccess eptAccess = (EptAccess)(EptAccessExecute);
		PgEntry* pgEntry = NULL;
		KSPIN_LOCK spinLock;
		KIRQL irql;
		// ���������,��ֹ�ڻ�û�����ú� ��/д/ִ�� ҳ��ַʱ,����vmexit,�Ӷ���������
		//(��ʵ�ϴ˴�����ִ��ʱ,vmlauch��δִ��)
		//KeInitializeSpinLock(&spinLock);
		//KeAcquireSpinLock(&spinLock, &irql);
		PASHidePage(pageAddress, eptAccess, &pgEntry);
		if (pgEntry == NULL)
		{
			return;
		}
		// �ֱ�����ҳ��� ��/д/ִ�� ��ַ   
		pgEntry->readPage = pgEntry->shadowPageAddressVa;
		pgEntry->writePage = pgEntry->shadowPageAddressVa;
		pgEntry->excutePage = pgEntry->pageAddressVa;



		//KeReleaseSpinLock(&spinLock,irql);
	}


}

/// <summary>
/// ����hook����������ȡhook����
/// </summary>
/// <param name="functionIndex">��������</param>
/// <returns>hook����</returns>
/// <created>FeJQ,2020/9/21</created>
/// <changed>FeJQ,2020/9/21</changed>
PhData* GetHookData(HookFunction functionIndex)
{
	return &g_phData[functionIndex];
}

typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
NTSTATUS NTAPI DetourNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength)
{
	PhData* phData = GetHookData(HookFunction::HKNtReadVirtualMemory);
	if (phData)
	{
		_NtReadVirtualMemory func = (_NtReadVirtualMemory)phData->hookData;
		return func(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
	}
}

void PhRootine()
{

	PASInitialize();
	PVOID target = (void*)0xFFFFF8000417D9C0;
	//PhHook(target, DetourNtReadVirtualMemory, &g_phData[HookFunction::HKNtReadVirtualMemory]);

	//DbgBreakPoint();

	//PVOID NtLoadKey2 = (PVOID)0xFFFFF8000435E9A0;
	PVOID NtLoadDriver = (PVOID)0xFFFFF800043594F0;
	
	PhHideOpCode(NtLoadDriver, 1);
}

ULONG TestFunc(ULONG a1, ULONG a2)
{
	return a1 + a2;
}

ULONG DetourTestFunc(ULONG a1, ULONG a2)
{
	return 0x12345678;
}




EXTERN_C_END
