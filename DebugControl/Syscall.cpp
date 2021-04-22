#include "pch.h"
#include "Syscall.h"

/// <summary>
/// Rva转Foa
/// </summary>
/// <param name="dwRVA">Rva</param>
/// <param name="pSectionHeader">区段头</param>
/// <param name="dwNumberOfSections">区段数量</param>
/// <returns>Foa</returns>
/// <created>FeJQ,2020/8/7</created>
/// <changed>FeJQ,2020/8/7</changed>
DWORD RvaToFoa(DWORD dwRVA, IMAGE_SECTION_HEADER* pSectionHeader, DWORD dwNumberOfSections)
{
	DWORD nFileOffset = -1;
	for (int i = 0; i < dwNumberOfSections; ++i)
	{
		if ((DWORD)dwRVA >= pSectionHeader[i].VirtualAddress &&
			(DWORD)dwRVA <= pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			nFileOffset = dwRVA - pSectionHeader[i].VirtualAddress;
			nFileOffset += pSectionHeader[i].PointerToRawData;
			return nFileOffset;
		}
	}
	return nFileOffset;
}

/// <summary>
/// 获取系统调用号
/// </summary>
/// <param name="szFunctionName">系统调用名字</param>
/// <returns>调用号</returns>
/// <created>FeJQ,2020/8/7</created>
/// <changed>FeJQ,2020/8/7</changed>
ULONG GetSyscallNumber(char* szFunctionName)
{
	char szWinDir[MAXBYTE] = { 0 };
	int nSize = MAXBYTE;
	HANDLE hFile;
	HANDLE hMapping;
	PVOID pFile;
	DWORD dwNumberOfSections;
	DWORD dwNumberOfNames;
	ULONG ulCallNumber=0;

	GetWindowsDirectory(szWinDir, nSize);
	strcat_s(szWinDir, "\\system32\\ntdll.dll");
	hFile = CreateFile(szWinDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	pFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pFile;

	// 判断DOS头是不是MZ
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//printf("不是一个有效PE文件,DOS头不对!\n");
		return false;
	}

	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((char*)pDos + pDos->e_lfanew);

	// 判断PE标志
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		//printf("不是一个有效PE文件,NT头不对\n");
		return false;
	}

	// 这里要判断一下有没有导出表
	// 导出表是在第一项
	if (pNt->OptionalHeader.NumberOfRvaAndSizes < 1)
	{
		//printf("没有导出表!\r\n");
		return false;
	}

	// 取得导出表的RVA地址
	ULONG_PTR exportDirectory = (ULONG_PTR)(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (exportDirectory == 0)
	{
		//printf("导出表VirtualAddress错误了吧!\r\n");
		return false;
	}

	// 取得节数量
	dwNumberOfSections = pNt->FileHeader.NumberOfSections;

	// 先定位到NT头
	ULONG_PTR ulpSectionAddress = (ULONG_PTR)pNt;

	// 再算出nt头的大小
	ULONG nNtHeaderSize = sizeof(IMAGE_FILE_HEADER) + pNt->FileHeader.SizeOfOptionalHeader + 4;

	// 得到在内存中的起始地址
	ulpSectionAddress += nNtHeaderSize;

	// 导出表地址
	exportDirectory = RvaToFoa(exportDirectory, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	exportDirectory += (ULONG_PTR)pFile;
	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)exportDirectory;

	// 按名称导出的函数个数
	dwNumberOfNames = pExportDir->NumberOfNames;

	// 函数名称表(存储着函数名的Rva,单位为4字节)
	ULONG_PTR dwNameArrayOffset = RvaToFoa(pExportDir->AddressOfNames, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	dwNameArrayOffset += (ULONG_PTR)(pFile);

	// 函数序号表(存储着函数序号,单位为2字节)
	ULONG_PTR dwOrdinalsAryOffset = RvaToFoa(pExportDir->AddressOfNameOrdinals, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	dwOrdinalsAryOffset += (ULONG_PTR)(pFile);

	// 函数地址表(存储着函数地址Rva,单位为4字节)
	ULONG_PTR dwFunAddrArrayOffset = RvaToFoa(pExportDir->AddressOfFunctions, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	dwFunAddrArrayOffset += (ULONG_PTR)(pFile);

	char code[] = "\x4C\x8B\xD1\xB8"; // mov r10,rcx    mov rax,xxxx
	for (int i = 0; i < dwNumberOfNames; i++)
	{
		// 取得函数名地址
		char* pFunName = (char*)RvaToFoa(*(ULONG*)(dwNameArrayOffset + i * 4), (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
		pFunName = pFunName + (ULONG_PTR)pFile;
		//验证是否以Nt开头
		if (pFunName[0] == 'N' && pFunName[1] == 't')
		{
			int sort = *(USHORT*)(dwOrdinalsAryOffset + i * 2);
			ULONG_PTR address = RvaToFoa(*(ULONG*)(dwFunAddrArrayOffset + sort * 4), (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
			address += (ULONG_PTR)pFile;
			//判断是否以mov r10,rcx,mov eax,xx开头
			if (memcmp(code, (PVOID)address, strlen(code)) == 0)
			{
				if (strcmp(pFunName, szFunctionName) == 0)
				{
					ulCallNumber = *(ULONG*)(address + strlen(code));
					break;
				}
			}
		}
	}
	if (pFile != NULL)
	{
		UnmapViewOfFile(pFile);
	}
	return ulCallNumber;
}