#pragma once

#ifndef _DEBUGCONTROL_SYSCALL_H_
#define _DEBUGCONTROL_SYSCALL_H_

#include <Windows.h>

/// <summary>
/// RvaתFoa
/// </summary>
/// <param name="dwRVA">Rva</param>
/// <param name="pSectionHeader">����ͷ</param>
/// <param name="dwNumberOfSections">��������</param>
/// <returns>Foa</returns>
/// <created>FeJQ,2020/8/7</created>
/// <changed>FeJQ,2020/8/7</changed>
DWORD RvaToFoa(DWORD dwRVA, IMAGE_SECTION_HEADER* pSectionHeader, DWORD dwNumberOfSections);

/// <summary>
/// ��ȡϵͳ���ú�
/// </summary>
/// <param name="szFunctionName">ϵͳ��������</param>
/// <returns>���ú�</returns>
/// <created>FeJQ,2020/8/7</created>
/// <changed>FeJQ,2020/8/7</changed>
ULONG GetSyscallNumber(char* szFunctionName);

#endif // !_DEBUGCONTROL_SYSCALL_H_