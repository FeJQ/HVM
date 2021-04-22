#pragma once
#include "Common.h"
#include "IA32Structures.h"

#ifndef _HVM_VMEXITHANDLER_H_
#define _HVM_VMEXITHANDLER_H_



EXTERN_C_BEGIN



/// <summary>
/// �ָ��ͻ�����Rip,ִ��"����vmexit��ָ��"����һ��ָ��
/// </summary>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
void VmResumeGuestRip();
/// <summary>
/// vmexit�¼�����
/// </summary>
/// <param name="pGuestRegisters">
/// Guest����Hostǰ�ļĴ���
/// RSP,RIP,RFlags�ᱣ����VMCS��Guest-state area��
/// ����ͨ�üĴ����ֶ������ڶ�ջ��
/// ����������Ƕ�ջָ��</param>
/// <returns>�Ƿ�ִ��vmresume</returns>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
BOOLEAN VmExitHandler(Registers64* pGuestRegisters);

/// <summary>
/// ִ��cpuid���µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitCpuid(Registers64* pGuestRegisters);

/// <summary>
/// ִ��invdָ��µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitInvd(Registers64* pGuestRegisters);

/// <summary>
/// ִ��vmcallָ��µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <param name="isVmresume">�Ƿ����ִ��vmresume</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/13</changed>
VMEXIT_PROC void VmExitVmcall(Registers64* pGuestRegisters, BOOLEAN& isVmresume);

/// <summary>
/// ����(��/д)���ƼĴ������µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitCrAccess(Registers64* pGuestRegisters);

/// <summary>
/// ��ȡMsr�Ĵ������µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitMsrRead(Registers64* pGuestRegisters);

/// <summary>
/// д��Msr�Ĵ������µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/7/12</created>
/// <changed>FeJQ,2020/7/12</changed>
VMEXIT_PROC void VmExitMsrWrite(Registers64* pGuestRegisters);

/// <summary>
/// ����MTF��ִ��ָ����������vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/8/9</created>
/// <changed>FeJQ,2020/8/9</changed>
VMEXIT_PROC void VmExitMtf(Registers64* pGuestRegisters);

/// <summary>
/// �ڴ����Բ�ƥ�䵼�µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/7/26</created>
/// <changed>FeJQ,2020/7/26</changed>
VMEXIT_PROC void VmExitEptViolation(Registers64* pGuestRegisters);

/// <summary>
/// �ڴ����Դ����µ�vmexit������
/// </summary>
/// <param name="pGuestRegisters">�ͻ���ͨ�üĴ���</param>
/// <created>FeJQ,2020/10/18</created>
/// <changed>FeJQ,2020/10/18</changed>
VMEXIT_PROC void VmExitEptMisconfiguration(Registers64* pGuestRegisters);

/// <summary>
/// ��ȡĿ��Ĵ����ĵ�ַ 
/// �ӱ����ڶ�ջ�Ŀͻ�����������,ȡ��Ŀ��Ĵ����ĵ�ַ
/// See:Table 27-3 Exit Qualification for Control-Register Access
/// </summary>
/// <param name="index">Ŀ��Ĵ�������</param>
/// <param name="pGuestRegisters">�ͻ���������</param>
/// <returns>Ŀ��Ĵ�����ַ</returns>
/// <created>FeJQ,2020/7/13</created>
/// <changed>FeJQ,2020/7/13</changed>
ULONG_PTR* VmGetUsedRegister(ULONG index, Registers64* pGuestRegisters);

/// <summary>
/// ִ��vmxoff,���ֶ��ָ��ͻ����Ĵ���
/// </summary>
/// <param name="guestRsp">ָ���ͻ���rsp</param>
/// <param name="guestRip">ָ���ͻ���rip</param>
/// <created>FeJQ,2020/7/13</created>
/// <changed>FeJQ,2020/7/13</changed>
ASM void AsmVmxoff(ULONG_PTR guestRsp, ULONG_PTR guestRip);

EXTERN_C_END
#endif // !_HVM_VMEXITHANDLER_H_
