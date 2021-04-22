#include "VmDeploy.h"
#include "Util.h"
#include "Ept.h"
#include "Vmx.h"
#include "PageHook.h"

EXTERN_C_BEGIN


/// <summary>
/// 初始化VMX
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/24</changed>
NTSTATUS VmInitializeVmx()
{
	NTSTATUS status;

	//检查是否支持VMX
	status = VmIsVmxAvailable();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//检查是否支持EPT
	status = EptIsEptAvailable();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//为每一个处理器开启VMX特征
	status = UtilForEachProcessor(VmxEnableVmxFeature);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//VMX上下文
	g_vmxCpu = (VMX_CPU*)UtilMalloc(sizeof(VMX_CPU) * CPU_COUNT);
	RtlZeroMemory(g_vmxCpu, sizeof(VMX_CPU) * CPU_COUNT);

	//为每一个处理器申请VMX域空间
	status = VmAllocateVMXRegion();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	/************************/
	/*       设置位图        */
	/************************/


	return STATUS_SUCCESS;
}

/// <summary>
/// 开启VMX
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
NTSTATUS VmStartVmx()
{
	NTSTATUS status;
	//在每个处理器上开启VMX
	status = UtilForEachProcessor(AsmVmLaunch);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

/// <summary>
/// 关闭VMX
/// </summary>
/// <returns>状态码</returns>
/// <created>FeJQ,2020/6/27</created>
/// <changed>FeJQ,2020/6/27</changed>
NTSTATUS VmStopVmx()
{
	NTSTATUS status;

	//在每个处理器上关闭VMX
	status = UtilForEachProcessor(VmQuitVmx, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}




EXTERN_C_END