#include "driver.h"
#include <ntddk.h>
#include "VmDeploy.h"
#include "Common.h"
#include "IA32Structures.h"

EXTERN_C_BEGIN


void DriverUnload(PDRIVER_OBJECT pDriver)
{
	NTSTATUS status;
	Log("������ж��",0);
	status = VmStopVmx();
	if (!NT_SUCCESS(status))
	{
		Log("VMX����ʧ��", 0);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegStr)
{
	NTSTATUS status;
	//DbgBreakPoint();
	Log("������װ��",0);
	pDriver->DriverUnload = DriverUnload;
	//DbgBreakPoint();	
	
	status=VmInitializeVmx();
	if(!NT_SUCCESS(status))
	{
		Log("VMX��ʼ��ʧ��",0);
	}
	status = VmStartVmx();
	
	if (!NT_SUCCESS(status))
	{
		Log("VMX����ʧ��",0);
	}
	
	
	return STATUS_SUCCESS;
}


EXTERN_C_END