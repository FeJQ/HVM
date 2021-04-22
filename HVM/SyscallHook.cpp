#include "SyscallHook.h"
#include "Vmx.h"
#include "Util.h"
#include <intrin.h>

EXTERN_C_BEGIN





/// <summary>
/// ³õÊ¼»¯msr:lstar hook
/// </summary>
/// <returns>×´Ì¬</returns>
/// <created>FeJQ,2020/9/13</created>
/// <changed>FeJQ,2020/9/13</changed>
NTSTATUS ShInitializeSystemCallHook()
{
	UtilForEachProcessor([](void* arg1, void* arg2)->NTSTATUS {
		VMX_CPU* currentVcpu = &g_vmxCpu[CPU_INDEX];
		ULONG syscall64Length = 0;
		PUCHAR pKiSystemCall64 = (PUCHAR)__readmsr(MSR_LSTAR);
		currentVcpu->originalLstar = (ULONG64)pKiSystemCall64;
		//currentVcpu->newKiSystemCall64 = DetourKiSystemCall64;

		// 0x1000 may be enough?
		for (int i = 0; i < 0x1000; i++)
		{
			if (*(pKiSystemCall64 + i) == 0xE9)
			{
				if (*(pKiSystemCall64 + i + 1) == 0x59 &&
					*(pKiSystemCall64 + i + 2) == 0xFD &&
					*(pKiSystemCall64 + i + 3) == 0xFF &&
					*(pKiSystemCall64 + i + 4) == 0xFF)
				{
					syscall64Length = i + 5;
					break;
				}
			}
		}
		if (syscall64Length ==0)
		{
			syscall64Length = 0x1000 - sizeof(SERVICE_DESCRIPTOR_TABLE_SHADOW) * 2;
		}
		PVOID newKiSystemCall64 = (PVOID)ExAllocatePoolWithTag(NonPagedPool, 0x15000, 'DeDf');
		if (!newKiSystemCall64)
		{
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		currentVcpu->newKiSystemCall64 = newKiSystemCall64;
		RtlZeroMemory(newKiSystemCall64, 0x15000);
		RtlCopyMemory(newKiSystemCall64, pKiSystemCall64, syscall64Length);
		});

	return STATUS_SUCCESS;
}

void DetourKiSystemCall64()
{

}



EXTERN_C_END