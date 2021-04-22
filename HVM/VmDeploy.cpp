#include "VmDeploy.h"
#include "Util.h"
#include "Ept.h"
#include "Vmx.h"
#include "PageHook.h"

EXTERN_C_BEGIN


/// <summary>
/// ��ʼ��VMX
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/24</changed>
NTSTATUS VmInitializeVmx()
{
	NTSTATUS status;

	//����Ƿ�֧��VMX
	status = VmIsVmxAvailable();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//����Ƿ�֧��EPT
	status = EptIsEptAvailable();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//Ϊÿһ������������VMX����
	status = UtilForEachProcessor(VmxEnableVmxFeature);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//VMX������
	g_vmxCpu = (VMX_CPU*)UtilMalloc(sizeof(VMX_CPU) * CPU_COUNT);
	RtlZeroMemory(g_vmxCpu, sizeof(VMX_CPU) * CPU_COUNT);

	//Ϊÿһ������������VMX��ռ�
	status = VmAllocateVMXRegion();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	/************************/
	/*       ����λͼ        */
	/************************/


	return STATUS_SUCCESS;
}

/// <summary>
/// ����VMX
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
NTSTATUS VmStartVmx()
{
	NTSTATUS status;
	//��ÿ���������Ͽ���VMX
	status = UtilForEachProcessor(AsmVmLaunch);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

/// <summary>
/// �ر�VMX
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/27</created>
/// <changed>FeJQ,2020/6/27</changed>
NTSTATUS VmStopVmx()
{
	NTSTATUS status;

	//��ÿ���������Ϲر�VMX
	status = UtilForEachProcessor(VmQuitVmx, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}




EXTERN_C_END