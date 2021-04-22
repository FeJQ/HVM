#include "driver.h"
#include <ntddk.h>
#include "VmDeploy.h"
#include "Common.h"
#include "IA32Structures.h"

EXTERN_C_BEGIN


void DriverUnload(PDRIVER_OBJECT pDriver)
{
	NTSTATUS status;
	Log("驱动已卸载",0);
	status = VmStopVmx();
	if (!NT_SUCCESS(status))
	{
		Log("VMX开启失败", 0);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegStr)
{
	NTSTATUS status;
	//DbgBreakPoint();
	Log("驱动已装载",0);
	pDriver->DriverUnload = DriverUnload;
	//DbgBreakPoint();	
	
	status=VmInitializeVmx();
	if(!NT_SUCCESS(status))
	{
		Log("VMX初始化失败",0);
	}
	status = VmStartVmx();
	
	if (!NT_SUCCESS(status))
	{
		Log("VMX开启失败",0);
	}
	
	
	return STATUS_SUCCESS;
}


EXTERN_C_END