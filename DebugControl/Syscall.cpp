#include "pch.h"
#include "Syscall.h"

/// <summary>
/// RvaתFoa
/// </summary>
/// <param name="dwRVA">Rva</param>
/// <param name="pSectionHeader">����ͷ</param>
/// <param name="dwNumberOfSections">��������</param>
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
/// ��ȡϵͳ���ú�
/// </summary>
/// <param name="szFunctionName">ϵͳ��������</param>
/// <returns>���ú�</returns>
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

	// �ж�DOSͷ�ǲ���MZ
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//printf("����һ����ЧPE�ļ�,DOSͷ����!\n");
		return false;
	}

	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((char*)pDos + pDos->e_lfanew);

	// �ж�PE��־
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		//printf("����һ����ЧPE�ļ�,NTͷ����\n");
		return false;
	}

	// ����Ҫ�ж�һ����û�е�����
	// ���������ڵ�һ��
	if (pNt->OptionalHeader.NumberOfRvaAndSizes < 1)
	{
		//printf("û�е�����!\r\n");
		return false;
	}

	// ȡ�õ������RVA��ַ
	ULONG_PTR exportDirectory = (ULONG_PTR)(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (exportDirectory == 0)
	{
		//printf("������VirtualAddress�����˰�!\r\n");
		return false;
	}

	// ȡ�ý�����
	dwNumberOfSections = pNt->FileHeader.NumberOfSections;

	// �ȶ�λ��NTͷ
	ULONG_PTR ulpSectionAddress = (ULONG_PTR)pNt;

	// �����ntͷ�Ĵ�С
	ULONG nNtHeaderSize = sizeof(IMAGE_FILE_HEADER) + pNt->FileHeader.SizeOfOptionalHeader + 4;

	// �õ����ڴ��е���ʼ��ַ
	ulpSectionAddress += nNtHeaderSize;

	// �������ַ
	exportDirectory = RvaToFoa(exportDirectory, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	exportDirectory += (ULONG_PTR)pFile;
	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)exportDirectory;

	// �����Ƶ����ĺ�������
	dwNumberOfNames = pExportDir->NumberOfNames;

	// �������Ʊ�(�洢�ź�������Rva,��λΪ4�ֽ�)
	ULONG_PTR dwNameArrayOffset = RvaToFoa(pExportDir->AddressOfNames, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	dwNameArrayOffset += (ULONG_PTR)(pFile);

	// ������ű�(�洢�ź������,��λΪ2�ֽ�)
	ULONG_PTR dwOrdinalsAryOffset = RvaToFoa(pExportDir->AddressOfNameOrdinals, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	dwOrdinalsAryOffset += (ULONG_PTR)(pFile);

	// ������ַ��(�洢�ź�����ַRva,��λΪ4�ֽ�)
	ULONG_PTR dwFunAddrArrayOffset = RvaToFoa(pExportDir->AddressOfFunctions, (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
	dwFunAddrArrayOffset += (ULONG_PTR)(pFile);

	char code[] = "\x4C\x8B\xD1\xB8"; // mov r10,rcx    mov rax,xxxx
	for (int i = 0; i < dwNumberOfNames; i++)
	{
		// ȡ�ú�������ַ
		char* pFunName = (char*)RvaToFoa(*(ULONG*)(dwNameArrayOffset + i * 4), (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
		pFunName = pFunName + (ULONG_PTR)pFile;
		//��֤�Ƿ���Nt��ͷ
		if (pFunName[0] == 'N' && pFunName[1] == 't')
		{
			int sort = *(USHORT*)(dwOrdinalsAryOffset + i * 2);
			ULONG_PTR address = RvaToFoa(*(ULONG*)(dwFunAddrArrayOffset + sort * 4), (IMAGE_SECTION_HEADER*)ulpSectionAddress, dwNumberOfSections);
			address += (ULONG_PTR)pFile;
			//�ж��Ƿ���mov r10,rcx,mov eax,xx��ͷ
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