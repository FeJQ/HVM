#pragma once
#ifndef _HVM_EPT_H_
#define _HVM_EPT_H_

#include "Common.h"

EXTERN_C_BEGIN

enum EptAccess
{
	EptAccessAll = 0b111,
	EptAccessRead = 0b001,
	EptAccessWrite = 0b010,
	EptAccessExecute = 0b100
};

union Pml4Entry
{
	ULONG64 all;
	struct
	{
		ULONG64 readAccess : 1;       //!< [0]
		ULONG64 writeAccess : 1;      //!< [1]
		ULONG64 executeAccess : 1;    //!< [2]
		ULONG64 reserved1 : 5;       //!< [3:7]
		ULONG64 accessFlag : 1;         //!< [8]
		ULONG64 ignored : 3;  //!< [9:11]
		ULONG64 physAddr : 40;  //   [12:51]
		ULONG64 reserved2 : 12;       //!< [52:63]
	}fields;
};

union EptEntry
{
	ULONG64 all;
	struct
	{
		ULONG64 readAccess : 1;       //!< [0]
		ULONG64 writeAccess : 1;      //!< [1]
		ULONG64 executeAccess : 1;    //!< [2]
		ULONG64 memoryType : 3;       //!< [3:5]
		ULONG64 reserved1 : 6;         //!< [6:11]
		ULONG64 physialAddress : 36;  //!< [12:48-1]
		ULONG64 reserved2 : 16;        //!< [48:63]
	} fields;
};



union EptPointer
{
	ULONG64 all;
	struct
	{
		ULONG64 memoryType : 3;         // EPT Paging structure memory type (0 for UC)
		ULONG64 pageWalkLength : 3;     // Page-walk length
		ULONG64 reserved1 : 6;
		ULONG64 physAddr : 40;          // Physical address of the EPT PML4 table
		ULONG64 reserved2 : 12;
	} fields;
};

struct EptControl
{
	EptEntry* pml4t;
};
extern EptControl eptCtrl;

/// <summary>
/// 检查EPT是否可用
/// </summary>
/// <returns>是否可用</returns>
/// <created>FeJQ,2020/6/25</created>
/// <changed>FeJQ,2020/6/25</changed>
BOOLEAN EptIsEptAvailable();

/// <summary>
/// 开启Ept
/// </summary>
/// <created>FeJQ,2020/7/24</created>
/// <changed>FeJQ,2020/7/24</changed>
void EptEnable();

/// <summary>
/// 分配页表内存
/// </summary>
/// <returns>1级页表(PML4T)的首地址</returns>
/// <created>FeJQ,2020/7/17</created>
/// <changed>FeJQ,2020/7/21</changed>
EptEntry* EptAllocateTable();

/// <summary>
/// 获取物理地址所对应的PTE
/// </summary>
/// <param name="pml4t">pml4t首地址</param>
/// <param name="pa">要查询的物理地址</param>
/// <returns>PTE</returns>
/// <created>FeJQ,2020/7/27</created>
/// <changed>FeJQ,2020/8/9</changed>
EptEntry* EptGetPtEntry(EptEntry* pml4t, ULONG_PTR pa);

EXTERN_C_END
#endif // !_HVM_EPT_H_
