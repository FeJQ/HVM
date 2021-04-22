#pragma once

#ifndef _HVM_COMMON_H_
#define _HVM_COMMON_H_
#include <ntddk.h>

#ifdef  __cplusplus
#define EXTERN_C_BEGIN extern "C"{           
#else 
#define EXTERN_C_BEGIN
#endif

#ifdef __cplusplus 
#define EXTERN_C_END }      
#else
#define EXTERN_C_END
#endif

#ifdef DEBUG
#define Log(message,value) {{KdPrint(("[HVM] %-40s [%p]\n",message,value));}}
#else 
#define Log(message,value)
#endif // DEBUG

#define GetPageHead(PA) (PA & 0xFFFFFFFFFFFFF000ull)

#define CPU_INDEX KeGetCurrentProcessorNumberEx(NULL)
#define CPU_COUNT KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)

#define Public
#define Private //�������ⲿ����

#define VMEXIT_PROC //vmexit�¼���Ӧ�Ĵ�����

#define ASM //��ຯ��


#endif // !_HVM_COMMON_H_

