#include "Util.h"
#include "Common.h"

EXTERN_C_BEGIN

static const ULONG uDPCPoolTag = 'dpc';


/// <summary>
/// 将虚拟地址转为物理地址
/// </summary>
/// <param name="virtualAddress"></param>
/// <returns></returns>
/// <created>FeJQ,2020/6/28</created>
/// <changed>FeJQ,2020/6/28</changed>
ULONG_PTR UtilVaToPa(void* virtualAddress)
{
	PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(virtualAddress);
	return pa.QuadPart;
}


/// <summary>
/// 为每一个处理器执行回调
/// </summary>
/// <param name="NTSTATUS(*routine)(void*)">回调函数</param>
/// <param name="context">回调函数的参数</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS UtilForEachProcessor(NTSTATUS(*routine)(void* arg1, void* arg2), void* context1, void* context2)
{
	for (ULONG i = 0; i < CPU_COUNT; i++)
	{
		PROCESSOR_NUMBER processorNumber = { 0 };
		NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processorNumber);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
		//切换到i号处理器
		GROUP_AFFINITY affinity = { 0 };
		affinity.Group = processorNumber.Group;
		affinity.Mask = 1ull << processorNumber.Number;
		GROUP_AFFINITY preAffinity = { 0 };
		KeSetSystemGroupAffinityThread(&affinity, &preAffinity);

		//执行回调
		status = routine(context1, context2);

		KeRevertToUserGroupAffinityThread(&preAffinity);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
	}
	return STATUS_SUCCESS;
}


/// <summary>
/// 为每一个处理器插入DPC
/// </summary>
/// <param name="routine">DPC例程</param>
/// <param name="context">参数指针</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS UtilForEachProcessorDpc(PKDEFERRED_ROUTINE routine, void* context)
{
	ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG i = 0; i < processorCount; i++)
	{
		PROCESSOR_NUMBER processorNumber = { 0 };
		NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processorNumber);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
		PRKDPC pDpc = (PRKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), uDPCPoolTag);
		if (!pDpc)
		{
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		KeInitializeDpc(pDpc, routine, context);
		KeSetImportanceDpc(pDpc, HighImportance);
		status = KeSetTargetProcessorDpcEx(pDpc, &processorNumber);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(pDpc, uDPCPoolTag);
			return status;
		}
		KeInsertQueueDpc(pDpc, nullptr, nullptr);
	}
	return STATUS_SUCCESS;
}

/// <summary>
/// 判断是否为64位环境
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
bool UtilIsAmd64()
{
#ifdef AMD64
	return true;
#else
	return false;
#endif // AMD64
}

/// <summary>
/// 判断是否处于Debug模式
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/9/24</created>
/// <changed>FeJQ,2020/9/24</changed>
bool UtilIsDebug()
{
#ifdef DEBUG
	return true;
#else
	return false;
#endif // DEBUG
}

/// <summary>
/// 申请非分页连续内存
/// </summary>
/// <param name="size"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
PVOID UtilMalloc(ULONG_PTR size)
{
	PHYSICAL_ADDRESS p = { -1 };
	return MmAllocateContiguousMemory(size, p);
}

/// <summary>
/// 释放非分页连续内存
/// </summary>
/// <param name="p"></param>
/// <created>FeJQ,2020/7/1</created>
/// <changed>FeJQ,2020/7/1</changed>
void UtilFree(PVOID p)
{
	MmFreeContiguousMemory(p);
}

/// <summary>
/// 物理地址转虚拟地址
/// </summary>
/// <param name="pa">物理地址</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/7/27</changed>
void* UtilPaToVa(ULONG64 pa)
{
	PHYSICAL_ADDRESS paddr = { 0 };
	paddr.QuadPart = pa;
	return MmGetVirtualForPhysical(paddr);
}

typedef ULONG KCriticalSection;
void UtilInitializeCriticalSection(KCriticalSection* kCriticalSecion)
{
	kCriticalSecion = 0;
}

void UtilEnterCriticalSection(KCriticalSection* kCriticalSecion);

void UtilDeleteCriticalSection(KCriticalSection* kCriticalSecion);


EXTERN_C_END