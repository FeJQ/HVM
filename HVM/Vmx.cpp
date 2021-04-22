#include "Vmx.h"
#include "IA32Structures.h"
#include <intrin.h>
#include "Util.h"
#include "Ept.h"

EXTERN_C_BEGIN

const int poolTagVmxon = 'vmon';
const int poolTagVmcs = 'vmcs';
const int poolTagHostStack = 'hesp';

VMX_CPU* g_vmxCpu = NULL;


/// <summary>
/// 检查VMX是否可用
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/23</created>
/// <changed>FeJQ,2020/6/23</changed>
NTSTATUS VmIsVmxAvailable()
{
	CPUID data = { 0 };
	CR0 cr0;
	CR4 cr4;
	IA32_FEATURE_CONTROL_MSR controlMsr = { 0 };
	IA32_VMX_BASIC_MSR basicMsr = { 0 };

	//1.CPUID
	__cpuid((int*)&data, 1);
	CPUID_ECX* cpuidEcx = (CPUID_ECX*)(&data.rcx);
	if (cpuidEcx->fields.vmx != 1)
	{
		Log("Error:这个CPU不支持VT!", 0);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}

	//2.检测cr0
	cr0.all = __readcr0();
	if (!cr0.fields.pg || !cr0.fields.ne || !cr0.fields.pe)
	{
		Log("Error:cr0不支持虚拟化", 0);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}

	//2.检查 BASIC_MSR,判断是否支持回写内存
	//See 24.2 Fromat of the VMCX region
	basicMsr.all = __readmsr(MSR_IA32_VMX_BASIC);
	if (basicMsr.fields.memory_type != kWriteBack)
	{
		Log("Write-back cache type is not supported", 0);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}

	////3.检查 CONTROL_MSR
	//controlMsr.all = __readmsr(MSR_IA32_FEATURE_CONTROL);
	////controlMsr.fields.enable_vmxon = TRUE;
	//if (!controlMsr.fields.lock)
	//{
	//	controlMsr.fields.lock = TRUE;
	//	//将每一个处理器的lock位设为 1
	//	UtilForEachProcessor([](void* context) {
	//		IA32_FEATURE_CONTROL_MSR* tempControlMsr = (IA32_FEATURE_CONTROL_MSR*)context;
	//		__writemsr(MSR_IA32_FEATURE_CONTROL, tempControlMsr->all);
	//		return STATUS_SUCCESS;
	//		}, &controlMsr);
	//}
	//if (!controlMsr.fields.enable_vmxon)
	//{
	//	Log("Error:CPU %d: %s: VMX 不支持\n", KeGetCurrentProcessorIndex(), __FUNCTION__);
	//	return STATUS_HV_FEATURE_UNAVAILABLE;
	//}
	return TRUE;
}


/// <summary>
/// 申请VMX域空间
/// </summary>
/// <returns></returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/24</changed>
Private NTSTATUS VmAllocateVMXRegion()
{
	for (int i = 0; i < CPU_COUNT; i++)
	{
		PVOID pVmxonRegion;
		PVOID pVmcsRegion;
		PVOID pVmStack;

		pVmxonRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, poolTagVmxon); //4KB
		if (!pVmxonRegion)
		{
			Log("Error:申请VMXON内存区域失败!", 0);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlZeroMemory(pVmxonRegion, 0x1000);

		pVmcsRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, poolTagVmcs);
		if (!pVmcsRegion)
		{
			Log("Error:申请VMCS内存区域失败!", 0);
			ExFreePoolWithTag(pVmxonRegion, 0x1000);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlZeroMemory(pVmcsRegion, 0x1000);

		pVmStack = ExAllocatePoolWithTag(NonPagedPool, KERNEL_STACK_SIZE, poolTagHostStack);
		if (!pVmStack)
		{
			Log("Error:申请宿主机堆载区域失败!", 0);
			ExFreePoolWithTag(pVmxonRegion, 0x1000);
			ExFreePoolWithTag(pVmcsRegion, 0x1000);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlZeroMemory(pVmStack, KERNEL_STACK_SIZE);

		Log("Tip:VMXON内存区域地址", pVmxonRegion);
		Log("Tip:VMCS内存区域地址", pVmcsRegion);
		Log("Tip:宿主机堆载区域地址", pVmStack);


		g_vmxCpu[i].pVmxonRegion = pVmxonRegion;
		g_vmxCpu[i].pVmcsRegion = pVmcsRegion;
		g_vmxCpu[i].pVmStack = pVmStack;
		g_vmxCpu[i].pVmStackBase = (CHAR*)pVmStack + KERNEL_STACK_SIZE;
	}
	return STATUS_SUCCESS;
}

/// <summary>
/// 开启VMX特征
/// </summary>
/// <param name="arg1">未用到</param>
/// <param name="arg2">未用到</param>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/9/12</changed>
Private NTSTATUS VmxEnableVmxFeature(void* arg1, void* arg2)
{
	//检测cr0和开启cr4.vmxe
	CR0 cr0 = { 0 };
	CR4 cr4 = { 0 };

	cr0.all = __readcr0();
	if (!cr0.fields.pg || !cr0.fields.ne || !cr0.fields.pe)
	{
		Log("Error:cr0不支持虚拟化", 0);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}
	cr4.all = __readcr4();
	cr4.fields.vmxe = TRUE;
	__writecr4(cr4.all);

	//对每个cpu开启vmxon指令的限制
	IA32_FEATURE_CONTROL_MSR msr = { 0 };
	msr.all = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (!msr.fields.lock)
	{
		msr.fields.lock = TRUE;
		msr.fields.enable_vmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, msr.all);
		msr.all = __readmsr(MSR_IA32_FEATURE_CONTROL);
	}
	if (!msr.fields.lock && !msr.fields.enable_vmxon)
	{
		Log("Error:BIOS未开启虚拟化", 0);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}
	return STATUS_SUCCESS;
}

/// <summary>
/// 在当前处理器上开启VMX
/// </summary>
/// <param name="guestStack">客户机rsp</param>
/// <param name="guestResumeRip">客户机rip</param>
/// <returns>成功与否</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
BOOLEAN VmLaunchVmx(PVOID guestStack, PVOID guestResumeRip)
{
	BOOLEAN bRet;
	VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];

	//开启Root模式
	bRet = VmEnableRoot(currentVcpu);
	if (!bRet)
	{
		return FALSE;
	}
	currentVcpu->bIsVmxEnable = TRUE;

	//设置VMCS 
	//DbgBreakPoint();
	bRet = VmSetupVMCS(currentVcpu, guestStack, guestResumeRip);
	if (!bRet)
	{
		return FALSE;
	}

	EptEnable();


	//开启虚拟机
	__vmx_vmlaunch();

	// See:30.4 VM Instruction Error Numbers
	int error = 0;
	if (__vmx_vmread(VM_INSTRUCTION_ERROR, (size_t*)&error) != 0)
	{
		Log("查询错误码失败!", 0);
		return FALSE;
	}
	Log("vmlauch失败,错误码:", error);
	return FALSE;
}

/// <summary>
/// 在当前处理器上退出Vmx
/// </summary>
/// <param name="arg1">未用到</param>
/// <param name="arg2">未用到</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/3</created>
/// <changed>FeJQ,2020/9/12</changed>
NTSTATUS VmQuitVmx(void* arg1, void* arg2)
{
	CR4 cr4;

	//以Guest身份执行vmoff会导致26号vmexit
	//__vmx_off();

	VmxoffContext context = { 0 };
	__vmcall(VmcallReason::VmcallVmxOff, &context);


	//Cr4.VMXE置0
	cr4.all = __readcr4();
	cr4.fields.vmxe = FALSE;
	__writecr4(cr4.all);

	if (g_vmxCpu)
	{
		if (g_vmxCpu[CPU_INDEX].pVmxonRegion)
		{
			ExFreePoolWithTag(g_vmxCpu[CPU_INDEX].pVmxonRegion, poolTagVmxon);
			g_vmxCpu[CPU_INDEX].pVmxonRegion = NULL;
		}
		if (g_vmxCpu[CPU_INDEX].pVmcsRegion)
		{
			ExFreePoolWithTag(g_vmxCpu[CPU_INDEX].pVmcsRegion, poolTagVmcs);
			g_vmxCpu[CPU_INDEX].pVmcsRegion = NULL;
		}
		if (g_vmxCpu[CPU_INDEX].pVmStackBase)
		{
			ExFreePoolWithTag(g_vmxCpu[CPU_INDEX].pVmStack, poolTagHostStack);
			g_vmxCpu[CPU_INDEX].pVmStack = NULL;
			g_vmxCpu[CPU_INDEX].pVmStackBase = NULL;
		}
		UtilFree(g_vmxCpu);
	}

	return STATUS_SUCCESS;

}

/// <summary>
/// 开启Root模式,执行vmxon,激活VMCS
/// </summary>
/// <param name="vCpu">VMX上下文</param>
/// <returns>成功与否</returns>
/// <created>FeJQ,2020/6/27</created>
/// <changed>FeJQ,2020/6/27</changed>
Private BOOLEAN VmEnableRoot(VMX_CPU* vCpu)
{
	CR0 cr0;
	CR4 cr4;
	IA32_VMX_BASIC_MSR msr = { 0 };
	ULONG_PTR tmpVmxonRegionPa;
	ULONG uRet;
	ULONG_PTR tmpVmcsRegionPa;

	cr0 = { __readcr0() };
	cr0.all &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0.all |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	__writecr0(cr0.all);

	// See: VMX-FIXED BITS IN CR4
	cr4 = { __readcr4() };
	cr4.all &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4.all |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	__writecr4(cr4.all);


	msr.all = __readmsr(MSR_IA32_VMX_BASIC);

	// See: 31.5 VMM setup 
	*(ULONG*)vCpu->pVmxonRegion = msr.fields.revision_identifier;

	// See: 24.2 Format of the VMCX region
	*(ULONG*)vCpu->pVmcsRegion = msr.fields.revision_identifier;

	//vmxon
	tmpVmxonRegionPa = UtilVaToPa(vCpu->pVmxonRegion);
	uRet = __vmx_on(&tmpVmxonRegionPa);
	if (uRet != 0)
	{
		Log("Error:vmxon调用失败", 0);
		return FALSE;
	}

	//vmclear
	tmpVmcsRegionPa = UtilVaToPa(vCpu->pVmcsRegion);
	uRet = __vmx_vmclear(&tmpVmcsRegionPa);
	if (uRet != 0)
	{
		Log("Error:vmclear调用失败", 0);
		return FALSE;
	}

	//vmptrld
	tmpVmcsRegionPa = UtilVaToPa(vCpu->pVmcsRegion);
	uRet = __vmx_vmptrld(&tmpVmcsRegionPa);
	if (uRet != 0)
	{
		Log("Error:vmptrld调用失败", 0);
		return FALSE;
	}
	return TRUE;
}

/// <summary>
/// 填充VMCS 
/// </summary>
/// <param name="vCpu">当前处理器VMX上下文</param>
/// <param name="guestStack">客户机Rsp</param>
/// <param name="guestResumeRip">客户机Rip</param>
/// <returns>成功与否</returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/28</changed>
Private BOOLEAN VmSetupVMCS(VMX_CPU* vCpu, PVOID guestStack, PVOID guestResumeRip)
{
	GDTR gdtr = { 0 };
	IDTR idtr = { 0 };
	SEGMENT_SELECTOR segmentSelector;
	VMX_PIN_BASED_CONTROLS vmPinCtlRequested = { 0 };
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	VMX_VM_ENTER_CONTROLS vmEnterCtlRequested = { 0 };
	VMX_VM_EXIT_CONTROLS vmExitCtlRequested = { 0 };
	VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 };
	VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];

	gdtr.base = __getgdtbase();
	gdtr.limit = __getgdtlimit();
	idtr.base = __getidtbase();
	idtr.limit = __getidtlimit();
	//_sgdt(&gdtr);
	//__sidt(&idtr);

	/********************************************
	 填充VMCS See: 24.3 Organization of VMCX data
	********************************************/

	//
	// 1.虚拟机状态域 (Guest-state area) See: 24.4
	// 	

	// See: 24.4.1 Guest Register State
	//CR0,CR3 and CR4
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	//Debug register DR7
	__vmx_vmwrite(GUEST_DR7, __readdr(7));

	//RSP,RIP and RFLAGS
	__vmx_vmwrite(GUEST_RSP, (ULONG_PTR)guestStack);
	__vmx_vmwrite(GUEST_RIP, (ULONG_PTR)guestResumeRip);
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());

	//Selector,Base address,Segment limit,Access rights for each of following registers:
	//CS,SS,DS,ES,FS,GS,LDTR and TR
	__vmx_vmwrite(GUEST_ES_SELECTOR, __reades());
	__vmx_vmwrite(GUEST_CS_SELECTOR, __readcs());
	__vmx_vmwrite(GUEST_SS_SELECTOR, __readss());
	__vmx_vmwrite(GUEST_DS_SELECTOR, __readds());
	__vmx_vmwrite(GUEST_FS_SELECTOR, __readfs());
	__vmx_vmwrite(GUEST_GS_SELECTOR, __readgs());
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, __readldtr());
	__vmx_vmwrite(GUEST_TR_SELECTOR, __readtr());

	__vmx_vmwrite(GUEST_ES_BASE, 0);
	__vmx_vmwrite(GUEST_CS_BASE, 0);
	__vmx_vmwrite(GUEST_SS_BASE, 0);
	__vmx_vmwrite(GUEST_DS_BASE, 0);
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
	VmLoadSementDescriptor(&segmentSelector, __readldtr(), gdtr.base);
	__vmx_vmwrite(GUEST_LDTR_BASE, segmentSelector.base);
	VmLoadSementDescriptor(&segmentSelector, __readtr(), gdtr.base);
	__vmx_vmwrite(GUEST_TR_BASE, segmentSelector.base);

	__vmx_vmwrite(GUEST_ES_LIMIT, GetSegmentLimit(__reades()));
	__vmx_vmwrite(GUEST_CS_LIMIT, GetSegmentLimit(__readcs()));
	__vmx_vmwrite(GUEST_SS_LIMIT, GetSegmentLimit(__readss()));
	__vmx_vmwrite(GUEST_DS_LIMIT, GetSegmentLimit(__readds()));
	__vmx_vmwrite(GUEST_FS_LIMIT, GetSegmentLimit(__readfs()));
	__vmx_vmwrite(GUEST_GS_LIMIT, GetSegmentLimit(__readgs()));
	__vmx_vmwrite(GUEST_LDTR_LIMIT, GetSegmentLimit(__readldtr()));
	__vmx_vmwrite(GUEST_TR_LIMIT, GetSegmentLimit(__readtr()));

	__vmx_vmwrite(GUEST_ES_AR_BYTES, VmGetSegmentAccessRight(__reades()));
	__vmx_vmwrite(GUEST_CS_AR_BYTES, VmGetSegmentAccessRight(__readcs()));
	__vmx_vmwrite(GUEST_SS_AR_BYTES, VmGetSegmentAccessRight(__readss()));
	__vmx_vmwrite(GUEST_DS_AR_BYTES, VmGetSegmentAccessRight(__readds()));
	__vmx_vmwrite(GUEST_FS_AR_BYTES, VmGetSegmentAccessRight(__readfs()));
	__vmx_vmwrite(GUEST_GS_AR_BYTES, VmGetSegmentAccessRight(__readgs()));
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, VmGetSegmentAccessRight(__readldtr()));
	__vmx_vmwrite(GUEST_TR_AR_BYTES, VmGetSegmentAccessRight(__readtr()));


	//Base address,limit for each of following registers:
	//GDTR,IDTR
	__vmx_vmwrite(GUEST_GDTR_BASE, gdtr.base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);
	__vmx_vmwrite(GUEST_IDTR_BASE, idtr.base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.limit);

	//MSRs
	//必填:IA32_DEBUGCTL,IA32_SYSENTER_CS,IA32_SYSENTER_ESP,and IA32_SYSENTER_EIP
	//以下 MSR 寄存器仅当对应的 VM-exit control 位被置为 1 后才需要填充其状态域
	//IA32_PERF_GLOBAL_CTRL,IA32_PAT,IA32_EFER
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP)); // KiFastCallEntry
	//__vmx_vmwrite(GUEST_IA32_EFER,__readmsr(MSR_EFER));

	//SMBASE 0
	__vmx_vmwrite(GUEST_SMBASE, 0);

	//See: 24.2.2 Guest Non-Register State
	//Active state 0
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);

	//Interruptibility state 0
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);

	//Pending debug exceptions 0
	__vmx_vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	//VMCS link pointer不使用的话必须填FFFFFFFF_FFFFFFFF See: 26.3.1.5 Checks on Guest Non-Register State
	__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

	//可选:VMX-preemption timer value,Page-directory-pointer-table-entries,Guest interrupt status
	//...


	//
	// 2.宿主机状态域 (Host-state area) See: 24.5
	//

	// CR0 CR3,and CR4
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	// RSP and RIP
	__vmx_vmwrite(HOST_RSP, (ULONG_PTR)currentVcpu->pVmStackBase);
	__vmx_vmwrite(HOST_RIP, (ULONG_PTR)AsmVmmEntryPoint);

	// Selector fileds
	// RPL和TI必须为0  
	// See: 26.2.3 Check on Host Segment and Descriptor-Table Registers
	__vmx_vmwrite(HOST_ES_SELECTOR, __reades() & 0xf8);
	__vmx_vmwrite(HOST_CS_SELECTOR, __readcs() & 0xf8);
	__vmx_vmwrite(HOST_SS_SELECTOR, __readss() & 0xf8);
	__vmx_vmwrite(HOST_DS_SELECTOR, __readds() & 0xf8);
	__vmx_vmwrite(HOST_FS_SELECTOR, __readfs() & 0xf8);
	__vmx_vmwrite(HOST_GS_SELECTOR, __readgs() & 0xf8);
	__vmx_vmwrite(HOST_TR_SELECTOR, __readtr() & 0xf8);

	// Base-address fileds for FS,GS,TR,GDTR,and IDTR	
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
	VmLoadSementDescriptor(&segmentSelector, __readtr(), gdtr.base);
	__vmx_vmwrite(HOST_TR_BASE, segmentSelector.base);
	__vmx_vmwrite(HOST_GDTR_BASE, gdtr.base);
	__vmx_vmwrite(HOST_IDTR_BASE, idtr.base);

	// MSRs
	// 必填:IA32_SYSENTER_CS,IA32_SYSENTER_ESP,IA32_SYSENTER_EIP,
	// 以下 MSR 寄存器仅当对应的 VM-exit control 位被置为 1 后才需要填充其状态域
	// IA32_PERF_GLOBAL_CTRL,IA32_PAT,IA32_EFER
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));//MSR[0x174] KiFastCallEntry的地址
	//__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_EFER));

	//
	// 3.虚拟机执行控制域 (VM-execution control fields) See:24.6 
	//

	// 通过 MSR_IA32_VMX_BASIC 寄存器的 55 位来判断是否使用 True 类型的 Msrs
	// See: 31.5.1 Algorithms for Determining VMX Capabilities	
	IA32_VMX_BASIC_MSR vmxBasicMsr;
	vmxBasicMsr.all = __readmsr(MSR_IA32_VMX_BASIC);
	BOOLEAN isUseTrueMsrs = vmxBasicMsr.fields.vmx_capability_hint;

	// 针脚执行控制域,主要用于拦截硬件中断
	// See: 24.6.1 Pin-Based VM-Execution Controls	
	__vmx_vmwrite(
		PIN_BASED_VM_EXEC_CONTROL,
		VmxAdjustControlValue(
			isUseTrueMsrs ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS,
			vmPinCtlRequested.All
		));

	// 处理器执行控制域,主要用于拦截特殊指令
	// Primary Processor
	// See: 24.6.2 Processor-Based VM-Execution Controls:Table 24-6
	__vmx_vmwrite(
		CPU_BASED_VM_EXEC_CONTROL,
		VmxAdjustControlValue(
			isUseTrueMsrs ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS,
			vmCpuCtlRequested.All
		));

	// Secondary Processor
	// See: 24.6.2 Processor-Based VM-Execution Controls:Table 24-7
	__vmx_vmwrite(
		SECONDARY_VM_EXEC_CONTROL,
		VmxAdjustControlValue(
			MSR_IA32_VMX_PROCBASED_CTLS2,
			vmCpuCtl2Requested.All
		));

	//
	// 4.虚拟机退出控制域 (VM-exit control fields) See:24.7 
	//

	// See: 24.7.1 VM-Exit Controls: Table 24-10	
	vmExitCtlRequested.Fields.HostAddressSpaceSize = UtilIsAmd64();
	vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = TRUE;
	__vmx_vmwrite(
		VM_EXIT_CONTROLS,
		VmxAdjustControlValue(
			isUseTrueMsrs ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS,
			vmExitCtlRequested.All
		));

	//
	// 5.虚拟机进入控制域 (VM-entry control fields) See:24.8 
	//

	// See: 24.8.1 VM-Entry Controls: Table 24-12 
	vmEnterCtlRequested.Fields.IA32eModeGuest = TRUE;
	//vmEnterCtlRequested.Fields.LoadIA32_EFER = TRUE;
	__vmx_vmwrite(
		VM_ENTRY_CONTROLS,
		VmxAdjustControlValue(
			isUseTrueMsrs ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS,
			vmEnterCtlRequested.All
		));

	//
	// 6.虚拟机退出信息域 (VM-exit information fields)
	//

	return 1;
}



/// <summary>
/// 加载段描述符
/// </summary>
/// <param name="segmentSelector">段描述符缓冲区</param>
/// <param name="selector">段选择子</param>
/// <param name="gdtBase">GDT地址</param>
/// <returns>状态</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
Private NTSTATUS VmLoadSementDescriptor(OUT SEGMENT_SELECTOR* segmentSelector, USHORT selector, ULONG_PTR gdtBase)
{
	PSEGMENT_DESCRIPTOR2 SegDesc;
	if (!segmentSelector)
	{
		return STATUS_INVALID_PARAMETER;
	}
	// 如果段选择子的T1 = 1表示索引LDT中的项, 这里没有实现这个功能
	if (selector & 0x4)
	{
		return STATUS_INVALID_PARAMETER;
	}
	// 在GDT中取出原始的段描述符
	SegDesc = (PSEGMENT_DESCRIPTOR2)((PUCHAR)gdtBase + (selector & ~0x7));
	// 段选择子
	segmentSelector->sel = selector;
	// 段基址15-39位 55-63位
	segmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
	// 段限长0-15位  47-51位, 看它的取法
	segmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
	// 段属性39-47 51-55 注意观察取法
	segmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;
	// 这里判断属性的DT位, 判断是否是系统段描述符还是代码数据段描述符
	if (!(SegDesc->attr0 & LA_STANDARD))
	{
		ULONG64 tmp;
		// 这里表示是系统段描述符或者门描述符, 感觉这是为64位准备的吧,
		// 32位下面段基址只有32位啊. 难道64位下面有什么区别了?
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		segmentSelector->base = (segmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	// 这是段界限的粒度位, 1为4K. 0为1BYTE
	if (segmentSelector->attributes.fields.g)
	{
		// 如果粒度位为1, 那么就乘以4K. 左移动12位
		segmentSelector->limit = (segmentSelector->limit << 12) + 0xfff;
	}
	return STATUS_SUCCESS;
}

/// <summary>
/// 获取段描述符访问权限
/// </summary>
/// <param name="segmentSelector">段选择子</param>
/// <returns></returns>
/// <created>FeJQ,2020/7/7</created>
/// <changed>FeJQ,2020/7/7</changed>
Private ULONG VmGetSegmentAccessRight(USHORT selector)
{
	VmxRegmentDescriptorAccessRight accessRight = { 0 };
	if (selector)
	{
		ULONG_PTR nativeAccessRight = AsmLoadAccessRightsByte(selector);
		nativeAccessRight >>= 8;
		accessRight.all = (ULONG)(nativeAccessRight);
		accessRight.fields.reserved1 = 0;
		accessRight.fields.reserved2 = 0;
		accessRight.fields.unusable = FALSE;
	}
	else
	{
		accessRight.fields.unusable = TRUE;
	}
	return accessRight.all;
}


/// <summary>
/// 填充客户机段选择子
/// </summary>
/// <param name="gdtBase"></param>
/// <param name="segreg"></param>
/// <param name="selector"></param>
/// <returns></returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/7/6</changed>
Private NTSTATUS FillGuestSelectorData(const ULONG_PTR gdtBase, ULONG segreg, USHORT selector)
{
	SEGMENT_SELECTOR segmentSelector = { 0 };
	ULONG uAccessRights;

	VmLoadSementDescriptor(&segmentSelector, selector, gdtBase);
	uAccessRights = ((PUCHAR)&segmentSelector.attributes)[0] + (((PUCHAR)&segmentSelector.attributes)[1] << 12);

	if (!selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + segreg * 2, selector & 0xFFF8);
	__vmx_vmwrite(GUEST_ES_BASE + segreg * 2, segmentSelector.base);
	__vmx_vmwrite(GUEST_ES_LIMIT + segreg * 2, segmentSelector.limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + segreg * 2, uAccessRights);


	// 	if ((Segreg == LDTR) || (Segreg == TR))
	// 		// don't setup for FS/GS - their bases are stored in MSR values
	// 		Vmx_VmWrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

	return STATUS_SUCCESS;
}




/// <summary>
/// 调整Msr寄存器值
/// </summary>
/// <param name="msr"></param>
/// <param name="ctl"></param>
/// <returns></returns>
/// <created>FeJQ,2020/7/3</created>
/// <changed>FeJQ,2020/7/3</changed>
Private ULONG VmxAdjustControlValue(ULONG msr, ULONG ctl)
{
	// See:24.6.1 Pin-Base VM-Execution Controls
	// vmwrite虚拟机控制域时,有些位必须置为0,有些位必须置为1
	// 通过读取相应的MSR寄存器来确定哪些位必须置0,哪些位必须置1
	LARGE_INTEGER MsrValue = { 0 };
	MsrValue.QuadPart = __readmsr(msr);
	ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return ctl;
}

/// <summary>
/// 设置MTF
/// see: 25.5.2 Monitor trap flag
/// </summary>
/// <param name="state">状态</param>
/// <created>FeJQ,2020/8/9</created>
/// <changed>FeJQ,2020/8/9</changed>
void VmSetMonitorTrapFlag(BOOLEAN state)
{
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&vmCpuCtlRequested.All);
	vmCpuCtlRequested.Fields.MonitorTrapFlag = state;
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmCpuCtlRequested.All);
}

EXTERN_C_END