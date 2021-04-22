#pragma once
#include "Common.h"
#include "IA32Structures.h"

#ifndef _HVM_VMEXITHANDLER_H_
#define _HVM_VMEXITHANDLER_H_



EXTERN_C_BEGIN



/// <summary>
/// 恢复客户机的Rip,执行"导致vmexit的指令"的下一条指令
/// </summary>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
void VmResumeGuestRip();
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
BOOLEAN VmExitHandler(Registers64* pGuestRegisters);

/// <summary>
/// 执行cpuid导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitCpuid(Registers64* pGuestRegisters);

/// <summary>
/// 执行invd指令导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitInvd(Registers64* pGuestRegisters);

/// <summary>
/// 执行vmcall指令导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <param name="isVmresume">是否继续执行vmresume</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
VMEXIT_PROC void VmExitVmcall(Registers64* pGuestRegisters, BOOLEAN& isVmresume);

/// <summary>
/// 访问(读/写)控制寄存器导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitCrAccess(Registers64* pGuestRegisters);

/// <summary>
/// 读取Msr寄存器导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitMsrRead(Registers64* pGuestRegisters);

/// <summary>
/// 写入Msr寄存器导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitMsrWrite(Registers64* pGuestRegisters);

/// <summary>
/// 开启MTF后执行指令所产生的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/8/9</created>
/// <changed>FeJQ,2020/8/9</changed>
VMEXIT_PROC void VmExitMtf(Registers64* pGuestRegisters);

/// <summary>
/// 内存属性不匹配导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/7/26</created>
/// <changed>FeJQ,2020/7/26</changed>
VMEXIT_PROC void VmExitEptViolation(Registers64* pGuestRegisters);

/// <summary>
/// 内存属性错误导致的vmexit处理函数
/// </summary>
/// <param name="pGuestRegisters">客户机通用寄存器</param>
/// <created>FeJQ,2020/10/18</created>
/// <changed>FeJQ,2020/10/18</changed>
VMEXIT_PROC void VmExitEptMisconfiguration(Registers64* pGuestRegisters);

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
ULONG_PTR* VmGetUsedRegister(ULONG index, Registers64* pGuestRegisters);

/// <summary>
/// 执行vmxoff,并手动恢复客户机寄存器
/// </summary>
/// <param name="guestRsp">指定客户机rsp</param>
/// <param name="guestRip">指定客户机rip</param>
/// <created>FeJQ,2020/7/13</created>
/// <changed>FeJQ,2020/7/13</changed>
ASM void AsmVmxoff(ULONG_PTR guestRsp, ULONG_PTR guestRip);

EXTERN_C_END
#endif // !_HVM_VMEXITHANDLER_H_
