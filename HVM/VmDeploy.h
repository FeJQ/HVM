#pragma once

#ifndef _HVM_VMDEPLOY_H_
#define _HVM_VMDEPLOY_H_

#include "Common.h"

EXTERN_C_BEGIN



/// <summary>
/// ��ʼ��VMX
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/24</created>
/// <changed>FeJQ,2020/6/24</changed>
NTSTATUS VmInitializeVmx();


/// <summary>
/// ����VMX
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
NTSTATUS VmStartVmx();


/// <summary>
/// �ر�VMX
/// </summary>
/// <returns>״̬��</returns>
/// <created>FeJQ,2020/6/27</created>
/// <changed>FeJQ,2020/6/27</changed>
NTSTATUS VmStopVmx();


EXTERN_C_END
#endif // !_HVM_VMDEPLOY_H_


