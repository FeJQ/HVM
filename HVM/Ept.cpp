#include "Ept.h"
#include "IA32Structures.h"
#include <intrin.h>
#include "VMCS.h"
#include "Util.h"
#include "PageHook.h"

EXTERN_C_BEGIN

EptControl eptCtrl = { 0 };

/// <summary>
/// 检查EPT是否可用
/// </summary>
/// <returns>是否可用</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
BOOLEAN EptIsEptAvailable()
{
	// Check the followings:
	// - page walk length is 4 steps
	// - extended page tables can be laid out in write-back memory
	// - INVEPT instruction with all possible types is supported
	// - INVVPID instruction with all possible types is supported

	IA32_VMX_EPT_VPID_CAP_MSR capability = { __readmsr(MSR_IA32_VMX_EPT_VPID_CAP) };
	if (!capability.fields.support_page_walk_length4 ||
		!capability.fields.support_write_back_memory_type ||
		!capability.fields.support_invept ||
		!capability.fields.support_single_context_invept ||
		!capability.fields.support_all_context_invept ||
		!capability.fields.support_invvpid ||
		!capability.fields.support_individual_address_invvpid ||
		!capability.fields.support_single_context_invvpid ||
		!capability.fields.support_all_context_invvpid ||
		!capability.fields.support_single_context_retaining_globals_invvpid)
	{
		Log("ept不可用", 0);
		return FALSE;
	}
	return TRUE;
}



/// <summary>
/// 开启Ept
/// </summary>
/// <created>FeJQ,2020/7/24</created>
/// <changed>FeJQ,2020/7/24</changed>
void EptEnable()
{
	EptPointer eptp = { 0 };
	VMX_CPU_BASED_CONTROLS primary = { 0 };
	VMX_SECONDARY_CPU_BASED_CONTROLS secondary = { 0 };


	eptCtrl.pml4t = EptAllocateTable();

	// Set up the EPTP
	eptp.fields.physAddr = MmGetPhysicalAddress(eptCtrl.pml4t).QuadPart >> 12;
	eptp.fields.memoryType = kWriteBack;
	eptp.fields.pageWalkLength = 3;
	__vmx_vmwrite(EPT_POINTER, eptp.all);

	__vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (size_t*)&secondary.All);
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&primary.All);
	primary.Fields.ActivateSecondaryControl = TRUE;
	secondary.Fields.EnableEPT = TRUE;
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary.All);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, primary.All);

	PhRootine();
}

/// <summary>
/// 分配页表内存
/// </summary>
/// <returns>1级页表(PML4T)的首地址</returns>
/// <created>FeJQ,2020/7/17</created>
/// <changed>FeJQ,2020/7/21</changed>
EptEntry* EptAllocateTable()
{
	//EPT寻址结构
	//表名      容量        大小(位)
	//PML4T		256T		9
	//PDPT		512G		9
	//PDT		1G			9
	//PT		2M			9
	//PAGE		4K			12

	EptEntry* pml4t = 0;
	EptEntry* pdpt = 0;
	EptEntry* pdt = 0;
	EptEntry* pt = 0;

	const ULONG pm4tCount = 1;
	const ULONG pdptCount = 1;
	const ULONG pdtCount = 8;
	const ULONG ptCount = 512;
	const ULONG pageCount = 512;

	//ULONG pteCount = pm4tCount * pdptCount * pdtCount * ptCount * pageCount;


	//1张PML4T
	pml4t = (EptEntry*)(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'pml4'));

	if (!pml4t)
	{
		return 0;
	}
	RtlZeroMemory(pml4t, PAGE_SIZE);

	//1张PDPT
	pdpt = (EptEntry*)(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'pdpt'));
	if (!pdpt)
	{
		return 0;
	}
	RtlZeroMemory(pdpt, PAGE_SIZE);

	//PML4T存储PDPT的首地址(物理地址)
	pml4t[0].all = *(ULONG64*)&MmGetPhysicalAddress(pdpt);
	pml4t[0].fields.readAccess = true;
	pml4t[0].fields.writeAccess = true;
	pml4t[0].fields.executeAccess = true;
	//8张PDT
	for (ULONG i = 0; i < pdtCount; i++)
	{
		pdt = (EptEntry*)(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'pdt'));
		if (!pdt)
		{
			return 0;
		}
		RtlZeroMemory(pdt, PAGE_SIZE);
		pdpt[i].all = *(ULONG64*)&MmGetPhysicalAddress(pdt);
		pdpt[i].fields.readAccess = true;
		pdpt[i].fields.writeAccess = true;
		pdpt[i].fields.executeAccess = true;
		for (ULONG j = 0; j < ptCount; j++)
		{
			pt = (EptEntry*)(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'pt'));
			if (!pt)
			{
				return 0;
			}
			RtlZeroMemory(pt, PAGE_SIZE);
			pdt[j].all = *(ULONG64*)&MmGetPhysicalAddress(pt);
			pdt[j].fields.readAccess = true;
			pdt[j].fields.writeAccess = true;
			pdt[j].fields.executeAccess = true;
			for (ULONG k = 0; k < pageCount; k++)
			{
				pt[k].all = (i * (ULONG64)(1 << 30) + j * (ULONG64)(1 << 21) + k * (ULONG64)(1 << 12));
				pt[k].fields.readAccess = true;
				pt[k].fields.writeAccess = true;
				pt[k].fields.executeAccess = true;
				pt[k].fields.memoryType = kWriteBack;
			}
		}
	}
	return pml4t;
}

/// <summary>
/// 获取物理地址所对应的PTE
/// </summary>
/// <param name="pml4t">pml4t首地址</param>
/// <param name="pa">要查询的物理地址</param>
/// <returns>PTE</returns>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/8/9</changed>
EptEntry* EptGetPtEntry(EptEntry* pml4t, ULONG_PTR pa)
{
	ULONG pml4teIndex = (pa & 0xFF8000000000ull) >> (12 + 9 + 9 + 9);
	ULONG pdpteIndex = (pa & 0x007FC0000000ull) >> (12 + 9 + 9);
	ULONG pdteIndex = (pa & 0x00003FE00000ull) >> (12 + 9);
	ULONG pteIndex = (pa & 0x0000001FF000ull) >> (12);

	EptEntry* pml4te = 0;
	EptEntry* pdpte = 0;
	EptEntry* pdte = 0;
	EptEntry* pte = 0;

	pml4te = &pml4t[pml4teIndex];
	pdpte = &((EptEntry*)UtilPaToVa(GetPageHead(pml4t->all)))[pdpteIndex];
	pdte = &((EptEntry*)UtilPaToVa(GetPageHead(pdpte->all)))[pdteIndex];
	pte = &((EptEntry*)UtilPaToVa(GetPageHead(pdte->all)))[pteIndex];
	return pte;
}

EXTERN_C_END