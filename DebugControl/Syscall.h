#pragma once

#ifndef _DEBUGCONTROL_SYSCALL_H_
#define _DEBUGCONTROL_SYSCALL_H_

#include <Windows.h>

/// <summary>
/// Rva转Foa
/// </summary>
/// <param name="dwRVA">Rva</param>
/// <param name="pSectionHeader">区段头</param>
/// <param name="dwNumberOfSections">区段数量</param>
/// <returns>Foa</returns>
/// <created>FeJQ,2020/8/7</created>
/// <changed>FeJQ,2020/8/7</changed>
DWORD RvaToFoa(DWORD dwRVA, IMAGE_SECTION_HEADER* pSectionHeader, DWORD dwNumberOfSections);

/// <summary>
/// 获取系统调用号
/// </summary>
/// <param name="szFunctionName">系统调用名字</param>
/// <returns>调用号</returns>
/// <created>FeJQ,2020/8/7</created>
/// <changed>FeJQ,2020/8/7</changed>
ULONG GetSyscallNumber(char* szFunctionName);

#endif // !_DEBUGCONTROL_SYSCALL_H_