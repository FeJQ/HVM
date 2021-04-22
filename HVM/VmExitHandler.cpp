#include "VmExitHandler.h"
#include "Util.h"
#include <intrin.h>
#include "VMCS.h"
#include "Ept.h"
#include "PageHook.h"
#include "Vmx.h"
#include "PageAccessSeparation.h"

EXTERN_C_BEGIN

ULONG_PTR tagExitVmx = 'exit';



/// <summary>
/// 恢复客户机的Rip,执行"导致vmexit的指令"的下一条指令
/// </summary>
/// <param name="guestRsp">指定客户机rsp</param>
/// <param name="guestRip">指定客户机rip</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
void VmResumeGuestRip()
{
	ULONG instLen = 0;
	ULONG_PTR rip = 0;
	__vmx_vmread(GUEST_RIP, &rip);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, (size_t*)&instLen);
	__vmx_vmwrite(GUEST_RIP, rip + instLen);
}

/// <summary>
/// vmexit事件处理
/// </summary>
/// <param name="pGuestRegisters">
/// Guest进入Host前的寄存器
/// RSP,RIP,RFlags会保存在VMCS的Guest-state area里
/// 其他通用寄存器手动保存在堆栈里
/// 这个参数就是堆栈指针</param>
/// <returns>是否执行vmresume</returns>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
BOOLEAN VmExitHandler(Registers64* pGuestRegisters)
{

	VmExitInformation exitReson = { 0 };
	BOOLEAN isVmresume = TRUE;
	//查询导致vmexit的原因
	// See:AppendixC VMX Basic Exit Reson ,Table C-1 Basic Exit Reson
	__vmx_vmread(VM_EXIT_REASON, (ULONG_PTR*)&exitReson);

	ULONG_PTR rip = 0;
	ULONG_PTR rsp = 0;
	ULONG_PTR guestPhysicalAddress = 0;
	__vmx_vmread(GUEST_RIP, &rip);
	__vmx_vmread(GUEST_RSP, &rsp);
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &guestPhysicalAddress);


	switch (exitReson.fields.reason)
	{
	case EXIT_REASON_CPUID:
		VmExitCpuid(pGuestRegisters);
		break;
	case EXIT_REASON_INVD:
		VmExitInvd(pGuestRegisters);
		break;
	case EXIT_REASON_VMCALL:
		VmExitVmcall(pGuestRegisters, isVmresume);
		break;
	case EXIT_REASON_CR_ACCESS:
		VmExitCrAccess(pGuestRegisters);
		break;
	case EXIT_REASON_MSR_READ:
		VmExitMsrRead(pGuestRegisters);
		break;
	case EXIT_REASON_MSR_WRITE:
		VmExitMsrWrite(pGuestRegisters);
		break;
	case EXIT_REASOM_MTF:
		VmExitMtf(pGuestRegisters);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		VmExitEptViolation(pGuestRegisters);
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		VmExitEptMisconfiguration(pGuestRegisters);
		break;
	default:
		DbgBreakPoint();
		break;
	}

	return isVmresume;
}

/// <summary>
/// 执行cpuid导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitCpuid(Registers64* pGuestRegisters)
{
	CPUID cpuInfo = { 0 };
	__cpuidex((int*)&cpuInfo, (int)pGuestRegisters->rax, (int)pGuestRegisters->rcx);
	pGuestRegisters->rax = cpuInfo.rax;
	pGuestRegisters->rbx = cpuInfo.rbx;
	pGuestRegisters->rcx = cpuInfo.rcx;
	pGuestRegisters->rdx = cpuInfo.rdx;
	VmResumeGuestRip();
}

/// <summary>
/// 执行invd指令导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitInvd(Registers64* pGuestRegisters)
{
	__invd();
	VmResumeGuestRip();
}

/// <summary>
/// 执行vmcall指令导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <param name="isVmresume">是否继续执行vmresume</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
VMEXIT_PROC void VmExitVmcall(Registers64* pGuestRegisters, BOOLEAN& isVmresume)
{
	VmcallReason reason = VmcallReason(pGuestRegisters->rcx & 0xFFFF);
	VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];
	switch (reason)
	{
	case VmcallReason::VmcallVmxOff:
	{
		// 产生vm-exit时,LDTR的选择子被清为0,GDTR和IDTR的limit会被设置成0xFFFF
		// rflags除了bit 1,其他位会被清0.正常的vmresume,会在vmcs里来读取并恢复这些值
		// 但是此处要退出vmx,不执行vmresume,所以需要手动的去恢复这些值
		// See:27.5.2 
		// ...
		ULONG instLen = 0;
		ULONG_PTR rsp = 0;
		ULONG_PTR rip = 0;
		GDTR gdtr = { 0 };
		IDTR idtr = { 0 };
		RFLAGS rflags = { 0 };
		VmxoffContext* context = (VmxoffContext*)pGuestRegisters->rdx;
		USHORT temp = 0;
		__vmx_vmread(GUEST_RSP, &rsp);
		__vmx_vmread(GUEST_RIP, &rip);
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, (size_t*)&instLen);
		__vmx_vmread(GUEST_RFLAGS, (size_t*)&rflags);
		__vmx_vmread(GUEST_GDTR_BASE, (size_t*)&gdtr.base);
		//用精度只有两字节的temp来做中间变量,以防止缓冲区溢出,覆盖掉后面的base
		__vmx_vmread(GUEST_GDTR_LIMIT, (size_t*)&temp);
		gdtr.limit = temp;
		__vmx_vmread(GUEST_IDTR_BASE, (size_t*)&idtr.base);
		__vmx_vmread(GUEST_IDTR_LIMIT, (size_t*)&temp);
		idtr.limit = temp;
		__lidt(&idtr);
		__lgdt(&gdtr);

		isVmresume = FALSE;
		context->rsp = rsp;
		context->rip = rip + instLen;
		context->rflags = *(ULONG_PTR*)&rflags;
		//__security_check_cookie 占用了rcx,所以这里用rdx传参
		pGuestRegisters->rdx = (ULONG_PTR)context;
		return;
	}
	case VmcallReason::VmcallLstarHookEnable:
	{
		UtilForEachProcessor([](void* _pGuestRegisters, void* arg2)->NTSTATUS {
			VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];
			currentVcpu->originalLstar = __readmsr(MSR_LSTAR);
			__writemsr(MSR_LSTAR, ((Registers64*)_pGuestRegisters)->rdx);
			return STATUS_SUCCESS;
			}, pGuestRegisters);

		break;
	}

	case VmcallReason::VmcallLstarHookDisable:
		UtilForEachProcessor([](void* arg1, void* arg2)->NTSTATUS {
			VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];
			if (currentVcpu->originalLstar != NULL)
			{
				__writemsr(MSR_LSTAR, currentVcpu->originalLstar);
			}
			currentVcpu->originalLstar = NULL;
			return STATUS_SUCCESS;
			});
		break;
	default:
		break;
	}
	VmResumeGuestRip();
}

/// <summary>
/// 访问(读/写)控制寄存器导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
void VmExitCrAccess(Registers64* pGuestRegisters)
{
	ExitQualification data;
	__vmx_vmread(EXIT_QUALIFICATION, (size_t*)&data);
	ULONG_PTR* pReg = VmGetUsedRegister(data.crAccess.generalRegister, pGuestRegisters);
	switch (data.crAccess.accessType)
	{
	case AccessType::MOV_TO_CR:
		switch (data.crAccess.registerNumber)
		{
		case 0:
			__vmx_vmwrite(GUEST_CR0, *pReg);
			break;
		case 3:
			__vmx_vmwrite(GUEST_CR3, *pReg);
			break;
		case 4:
			__vmx_vmwrite(GUEST_CR4, *pReg);
			break;
		default:
			Log("Error", 0);
			DbgBreakPoint();
			break;
		}
	case AccessType::MOV_FROM_CR:
		switch (data.crAccess.registerNumber)
		{
		case 0:
			__vmx_vmread(GUEST_CR0, pReg);
			break;
		case 3:
			__vmx_vmread(GUEST_CR3, pReg);
			break;
		case 4:
			__vmx_vmread(GUEST_CR4, pReg);
			break;
		default:
			Log("Error", 0);
			DbgBreakPoint();
			break;
		}
		break;
	default:
		Log("Error\n", 0);
		DbgBreakPoint();
		break;
	}
	VmResumeGuestRip();
}

/// <summary>
/// 读取Msr寄存器导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitMsrRead(Registers64* pGuestRegisters)
{
	LARGE_INTEGER msrValue = { 0 };
	ULONG32 msrIndex = pGuestRegisters->rcx;
	VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];
	switch (msrIndex)
	{
	case MSR_LSTAR:
		if (currentVcpu->originalLstar)
		{
			msrValue.QuadPart = currentVcpu->originalLstar;
		}
		else
		{
			msrValue.QuadPart = __readmsr(MSR_LSTAR);
		}
		break;
	default:
		msrValue.QuadPart = __readmsr(msrIndex);
		break;
	}

	pGuestRegisters->rax = msrValue.LowPart;
	pGuestRegisters->rdx = msrValue.HighPart;
	VmResumeGuestRip();
}
/// <summary>
/// 写入Msr寄存器导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitMsrWrite(Registers64* pGuestRegisters)
{
	LARGE_INTEGER msrValue = { 0 };
	ULONG32 msrIndex = pGuestRegisters->rcx;
	VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];
	msrValue.LowPart = (ULONG32)pGuestRegisters->rax;
	msrValue.HighPart = (ULONG32)pGuestRegisters->rdx;
	switch (msrIndex)
	{
	case MSR_LSTAR:
		if (currentVcpu->originalLstar == NULL)
		{
			__writemsr(MSR_LSTAR, msrValue.QuadPart);
		}
		break;
	default:
		__writemsr(msrIndex, msrValue.QuadPart);
		break;
	}
	VmResumeGuestRip();
}

/// <summary>
/// 开启MTF后执行指令所产生的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/8/9</created>
/// <changed>FeJQ,2020/8/9</changed>
VMEXIT_PROC void VmExitMtf(Registers64* pGuestRegisters)
{
	ULONG_PTR rip = 0;
	ULONG64 faultPagePa = 0;

	__vmx_vmread(GUEST_RIP, &rip);
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &faultPagePa);


	for (int i = 0; i < HookFunction::FunctionCount; i++)
	{

	}
}


/// <summary>
/// 内存属性不匹配导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/26</created>
/// <changed>FeJQ,2020/7/26</changed>
VMEXIT_PROC void VmExitEptViolation(Registers64* pGuestRegisters)
{
	ULONG64 guestPhysicalAddress = 0;
	ULONG_PTR guestVirtualAddress = 0;
	ExitQualification data;
	ULONG_PTR rip = 0;
	PgEntry* pgEntry = NULL;

	// GuestPhysicalAddress 是出错的地址,而 GuestRip 是导致出错的指令的地址
	// 如,地址 0x123456 为不可读的页面,而 0x654321 处尝试去读 0x123456 所在的页
	// 则 GuestRip=0x654321,GuestPhysicalAddress=0x123456

	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &guestPhysicalAddress);
	__vmx_vmread(GUEST_RIP, &rip);
	__vmx_vmread(EXIT_QUALIFICATION, (size_t*)&data);

	guestVirtualAddress = (ULONG_PTR)UtilPaToVa(guestPhysicalAddress);
	DbgBreakPoint();
	//获取替换过的页面的相关数据
	for (LIST_ENTRY* pLink = g_pgEntry->pageList.Flink; pLink != (PLIST_ENTRY)&g_pgEntry->pageList; pLink = pLink->Flink)
	{
		PgEntry* tempPgEntry = CONTAINING_RECORD(pLink, PgEntry, pageList);
		ULONG_PTR pageAddressHeadPa = (ULONG_PTR)PAGE_ALIGN((PVOID)UtilVaToPa((PVOID)tempPgEntry->pageAddressVa));
		ULONG_PTR guestAddressHeadPa = (ULONG_PTR)PAGE_ALIGN(guestPhysicalAddress);
		if (pageAddressHeadPa == guestAddressHeadPa)
		{
			pgEntry = tempPgEntry;
			break;
		}
	}
	if (pgEntry == NULL)
	{
		DbgBreakPoint();
		return;
	}
	if (data.eptViolation.readAccess)
	{
		// 读不可读的内存页导致的vmexit		
		pgEntry->pte->all = (ULONG64)PAGE_ALIGN(UtilVaToPa((PVOID)pgEntry->readPage));
		pgEntry->pte->fields.readAccess = true;
		pgEntry->pte->fields.writeAccess = false;
		pgEntry->pte->fields.executeAccess = false;
		pgEntry->pte->fields.memoryType = kWriteBack;
	}
	else if (data.eptViolation.writeAccess)
	{
		// 写不可写的内存页导致的vmexit	
		pgEntry->pte->all = (ULONG64)PAGE_ALIGN(UtilVaToPa((PVOID)pgEntry->writePage));
		pgEntry->pte->fields.readAccess = true;
		pgEntry->pte->fields.writeAccess = true;
		pgEntry->pte->fields.executeAccess = false;
		pgEntry->pte->fields.memoryType = kWriteBack;
	}
	else if (data.eptViolation.executeAccess)
	{
		// 执行不可执行的内存页导致的vmexit
		pgEntry->pte->all = (ULONG64)PAGE_ALIGN(UtilVaToPa((PVOID)pgEntry->excutePage));
		pgEntry->pte->fields.readAccess = false;
		pgEntry->pte->fields.writeAccess = false;
		pgEntry->pte->fields.executeAccess = true;
		pgEntry->pte->fields.memoryType = kWriteBack;
	}
}

/// <summary>
/// 内存属性错误导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/10/18</created>
/// <changed>FeJQ,2020/10/18</changed>
VMEXIT_PROC void VmExitEptMisconfiguration(Registers64* pGuestRegisters)
{
	/*
	EPT Misconfigurations
		如果 guest - physical address的转换遇到满足以下任一条件的EPT分页结构，则会发生EPT Misconfigurations：
		• 该条目的位0清除（指示不允许进行数据读取），并且将位1置1（指示允许进行数据写入）。

		• 如果处理器不支持以下任一操作，则仅执行translations ：
		— 该条目的位0被清除（指示不允许进行数据读取），并且位2被置位（指示允许进行指令提取）。
		— “用于EPT的基于模式的执行控制” VM - execution control 为1，该条目的位0被清除（指示不允许进行数据读取），
		并且已设置位10（指示允许从用户提取指令）模式线性地址）。
		软件应阅读VMX功能MSR IA32_VMX_EPT_VPID_CAP，以确定是否支持仅执行转换。

		• 该条目存在，并且具有以下条件之一：
		— 保留位被置位。这包括设置超出逻辑处理器的物理地址宽度的范围为51 : 12的位。
		有关在哪些EPT page struceture条目中保留哪些位的详细信息。
		— 该条目是最后一个用于转换guest - physical address（第7位设置为1的EPT PDE或EPT PTE），
		而第5：3位（EPT存储器类型）的值是2、3或7 （这些值是保留的）。
		当为EPT paging - structure条目配置了保留用于将来功能的设置时，会导致EPT misconfigurations 。
		developer应注意，将来可能会使用此类设置，并且导致一个处理器上的EPT配置错误的EPT paging - structure条目将来可能不会使用。
	*/
	DbgBreakPoint();
	KdPrint(("EptMisconfiguration\n"));
}



/// <summary>
/// 获取目标寄存器的地址 
/// 从保存在堆栈的客户机上下文中,取出目标寄存器的地址
/// See:Table 27-3 Exit Qualification for Control-Register Access
/// </summary>
/// <param name="index">目标寄存器索引</param>
/// <param name="pGuestRegisters">客户机上下文</param>
/// <returns>目标寄存器地址</returns>
/// <created>FeJQ,2020/7/13</created>
/// <changed>FeJQ,2020/7/13</changed>
ULONG_PTR* VmGetUsedRegister(ULONG index, Registers64* pGuestRegisters)
{
	ULONG_PTR* registerUsed = nullptr;
	// clang-format off
	switch (index)
	{
	case 0: registerUsed = &pGuestRegisters->rax; break;
	case 1: registerUsed = &pGuestRegisters->rcx; break;
	case 2: registerUsed = &pGuestRegisters->rdx; break;
	case 3: registerUsed = &pGuestRegisters->rbx; break;
	case 4: registerUsed = &pGuestRegisters->rsp; break;
	case 5: registerUsed = &pGuestRegisters->rbp; break;
	case 6: registerUsed = &pGuestRegisters->rsi; break;
	case 7: registerUsed = &pGuestRegisters->rdi; break;
#if defined(_AMD64_)
	case 8: registerUsed = &pGuestRegisters->r8; break;
	case 9: registerUsed = &pGuestRegisters->r9; break;
	case 10: registerUsed = &pGuestRegisters->r10; break;
	case 11: registerUsed = &pGuestRegisters->r11; break;
	case 12: registerUsed = &pGuestRegisters->r12; break;
	case 13: registerUsed = &pGuestRegisters->r13; break;
	case 14: registerUsed = &pGuestRegisters->r14; break;
	case 15: registerUsed = &pGuestRegisters->r15; break;
#endif
	default: DbgBreakPoint(); break;
	}
	// clang-format on
	return registerUsed;
}
EXTERN_C_END