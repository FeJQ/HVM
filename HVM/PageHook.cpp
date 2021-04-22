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
/// <param name="target">要hook的地址</param>
/// <param name="detour">目标函数地址</param>
/// <param name="phData">hook上下文数据缓冲区</param>
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
	//开始hook
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
		// 添加自旋锁,防止在还没有配置好 读/写/执行 页地址时,发生vmexit,从而引发错误
		//(事实上此处代码执行时,vmlauch还未执行)
		//KeInitializeSpinLock(&spinLock);
		//KeAcquireSpinLock(&spinLock, &irql);
		PASHidePage(pageAddress, eptAccess, &pgEntry);
		if (pgEntry == NULL)
		{
			return;
		}
		// 分别配置页面的 读/写/执行 地址   
		pgEntry->readPage = pgEntry->shadowPageAddressVa;
		pgEntry->writePage = pgEntry->shadowPageAddressVa;
		pgEntry->excutePage = pgEntry->pageAddressVa;



		//KeReleaseSpinLock(&spinLock,irql);
	}


}

/// <summary>
/// 根据hook函数索引获取hook数据
/// </summary>
/// <param name="functionIndex">函数索引</param>
/// <returns>hook数据</returns>
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
