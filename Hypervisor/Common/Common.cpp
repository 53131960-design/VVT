#include "Common.hpp"
#include "../Global/Global.hpp"

static unsigned MaxWait = 65536;

void Common::Sleep(ULONG delay)
{
	LARGE_INTEGER liTime;
	delay = delay * 10000;
	liTime = RtlConvertLongToLargeInteger(-(LONG)delay);
	KeDelayExecutionThread(KernelMode, TRUE, &liTime);
}

// 参数1 禁止分页 true 禁止分页 false 可以分页
PVOID Common::AllocateMemory(size_t size, bool)
{
	PPOOL_TABLE SinglePool = (PPOOL_TABLE)ExAllocatePool(NonPagedPool, sizeof(POOL_TABLE));
	if (!SinglePool)
		return nullptr;
	RtlZeroMemory(SinglePool, sizeof(POOL_TABLE));

	PVOID Address = Global::g_pSysRotineAddr.pfn_MmAllocateIndependentPages(size, 0);
	if (!Address)
		return nullptr;

	RtlZeroMemory(Address, size);

	SinglePool->Address = Address;
	SinglePool->Size = size;

	SpinlockLock(&Global::g_AllocatedPoolsLock);
	InsertTailList(&Global::AllocatedPoolsList, &SinglePool->PoolsList);
	SpinlockUnlock(&Global::g_AllocatedPoolsLock);
	return Address;
}

// 参数 1地址 参数2 禁止分页 true 禁止分页 false 可以分页
void Common::FreeMemory(PVOID Address, bool)
{
	Common::SpinlockLock(&Global::g_AllocatedPoolsLock);
	for (PLIST_ENTRY pListEntry = Global::AllocatedPoolsList.Flink; pListEntry != &Global::AllocatedPoolsList; pListEntry = pListEntry->Flink)
	{
		PPOOL_TABLE PoolTable = CONTAINING_RECORD(pListEntry, POOL_TABLE, PoolsList);
		if (PoolTable) {
			if (PoolTable->Address == Address)
			{
				Global::g_pSysRotineAddr.pfn_MmFreeIndependentPages(PoolTable->Address, PoolTable->Size);
				RemoveEntryList(&PoolTable->PoolsList);
				ExFreePoolWithTag(PoolTable, 0);
				break;
			}
		}
	}
	Common::SpinlockUnlock(&Global::g_AllocatedPoolsLock);
}

void* Common::PhysicalToVirtual(ULONG_PTR Physical)
{
	PHYSICAL_ADDRESS PA = {};
	PA.QuadPart = Physical;
	return MmGetVirtualForPhysical(PA);
}

PMMPTE Common::GetPTEForVA(IN ULONG64 pAddress)
{
	
	PMMPTE pPDE = (PMMPTE)(((((ULONG_PTR)pAddress >> PDI_SHIFT) << PTE_SHIFT) & 0x3FFFFFF8ull) + Global::g_pSysRotineAddr.DYN_PDE_BASE);
	if (pPDE->u.Hard.LargePage)
		return pPDE;

	return (PMMPTE)(((((ULONG_PTR)pAddress >> PTI_SHIFT) << PTE_SHIFT) & 0x7FFFFFFFF8ull) + Global::g_pSysRotineAddr.DYN_PTE_BASE);
	

}

uint64_t Common::GetProcessCr3(PEPROCESS pProcess)
{
	PUCHAR Process = (PUCHAR)pProcess;
	uint64_t ProcessDirbase = *(uint64_t*)(Process + 0x28);
	if (!ProcessDirbase)
	{
		ULONG UserDirOffset = Global::g_pSysRotineAddr.CR3Offset;
		uint64_t ProcessUserdirbase = *(uint64_t*)(Process + UserDirOffset);
		return ProcessUserdirbase;
	}
	return ProcessDirbase;
}

uint64_t Common::GetProcessCr32(PEPROCESS pProcess)
{
	PUCHAR Process = (PUCHAR)pProcess;
	uint64_t ProcessDirbase = *(uint64_t*)(Process + 0x28);
	return ProcessDirbase;
}

HANDLE Common::GetProcessIdByNameW(PCWSTR Process)
{
	HANDLE Pid = NULL;
	ULONG retusize = NULL;
	UNICODE_STRING FindName;

	RtlInitUnicodeString(&FindName, Process);
	ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &retusize);

	if (retusize)
	{
		PVOID AllocatePool = ExAllocatePool(NonPagedPool, retusize);
		NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, AllocatePool, (ULONG)retusize, &retusize);
		if (NT_SUCCESS(status))
		{
			PSYSTEM_PROCESS_INFORMATION	 ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)AllocatePool;
			while (ProcessInfo)
			{
				if (RtlEqualUnicodeString(&ProcessInfo->ImageName, &FindName, TRUE))
				{
					Pid = ProcessInfo->ProcessId;
				}

				if (!ProcessInfo->NextEntryOffset)
				{
					break;
				}
				ProcessInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONG64)ProcessInfo + ProcessInfo->NextEntryOffset);
			}
		}
		ExFreePoolWithTag(AllocatePool, 0);
	}
	return Pid;
}

PVOID Common::GetKernelBase(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(moduleList, 0);
		return address;
	}

	for (size_t i = 0; i < moduleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE module = moduleList->Modules[i];
		if (strstr(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}

	ExFreePoolWithTag(moduleList, 0);
	return address;
}

BOOLEAN Common::GetKernelBase2(CHAR* ModuleName, PMODULE_INFO info)
{
	BOOLEAN Isok = FALSE;
	RTL_PROCESS_MODULES* ProcessModules = NULL;
	ULONG ReturnLength = 0;
	RTL_PROCESS_MODULE_INFORMATION* ModuleInformation = NULL;
	ZwQuerySystemInformation(SystemModuleInformation, &ProcessModules, 4, &ReturnLength);
	if (ReturnLength)
	{
		ProcessModules = (PRTL_PROCESS_MODULES)ExAllocatePool((POOL_TYPE)SystemModuleInformation, 2i64 * ReturnLength);
		if (ProcessModules)
		{
			if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, ProcessModules, 2i64 * ReturnLength, NULL)))
			{
				ModuleInformation = (RTL_PROCESS_MODULE_INFORMATION*)(ProcessModules->Modules);
				for (size_t i = 0; i < ProcessModules->NumberOfModules; i++)
				{
					if (!_stricmp(ModuleName, (CHAR*)&ModuleInformation[i].FullPathName[ModuleInformation[i].OffsetToFileName]))
					{
						info->Base = (PUCHAR)ModuleInformation[i].ImageBase;
						info->Size = ModuleInformation[i].ImageSize - PAGE_SIZE;
						Isok = TRUE;
						break;
					}
				}
			}
			ExFreePoolWithTag(ProcessModules, 0);
		}
	}
	return Isok;
}

ULONG Common::GetNativeFunctionIndex(const char* lpFunctionName)
{
	HANDLE hSection, hFile;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS32 ntHeader;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	ULONG* arrayOfFunctionAddresses;
	ULONG* arrayOfFunctionNames;
	USHORT* arrayOfFunctionOrdinals;
	ULONG x;
	PUCHAR functionAddress = NULL;
	char* functionName = NULL;
	PVOID BaseAddress = NULL;
	SIZE_T Size = 0;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	ULONG uIndex = 0;
	UNICODE_STRING pDllName;

	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\SysWOW64\\ntdll.dll");

	InitializeObjectAttributes(&oa, &pDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (NT_SUCCESS(status))
	{
		oa.ObjectName = 0;
		status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_READONLY, 0x01000000, hFile);
		if (NT_SUCCESS(status))
		{
			BaseAddress = NULL;
			status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &Size, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);
			if (NT_SUCCESS(status))
			{
				dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
				ntHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + dosHeader->e_lfanew);
				pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)BaseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				arrayOfFunctionAddresses = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfFunctions);
				arrayOfFunctionNames = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfNames);
				arrayOfFunctionOrdinals = (USHORT*)((PUCHAR)BaseAddress + pExportTable->AddressOfNameOrdinals);

				for (x = 0; x < pExportTable->NumberOfFunctions; x++)
				{
					functionName = (char*)((unsigned char*)BaseAddress + arrayOfFunctionNames[x]);
					functionAddress = ((unsigned char*)BaseAddress + arrayOfFunctionAddresses[arrayOfFunctionOrdinals[x]]);
					if (!_stricmp(functionName, lpFunctionName))
					{
						uIndex = *(USHORT*)(functionAddress + 1);
						break;
					}
				}

				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
			}

			ZwClose(hSection);
		}
		ZwClose(hFile);
	}

	return uIndex;
}
NTSTATUS Common::RtlFindImageSection(PVOID ImageBase, CHAR* SectionName, OUT PVOID* SectionStart, OUT PVOID* SectionEnd)
{
	////DPRINT("ntoskrnl---0x%X\n", ImageBase);
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	PIMAGE_SECTION_HEADER NtSection = NULL;
	PIMAGE_SECTION_HEADER FoundSection = NULL;
	ULONG Index = NULL;
	ULONG Maximun = NULL;
	if (NtHeaders = RtlImageNtHeader(ImageBase))
	{
		FoundSection = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHeaders);
		Maximun = min(strlen(SectionName), 8);
		for (Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; Index++)
		{
			if (0 == _strnicmp((const char*)FoundSection[Index].Name, SectionName, Maximun))
			{
				if (FoundSection[Index].Name[strlen(SectionName)] == NULL) {
					NtSection = &FoundSection[Index];
					break;
				}
			}
		}
		if (NtSection != NULL)
		{
			*SectionStart = (PVOID)((ULONG64)ImageBase + NtSection->VirtualAddress);
			*SectionEnd = (PVOID)((ULONG64)*SectionStart + max(NtSection->SizeOfRawData, NtSection->Misc.VirtualSize));
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_IMAGE_FORMAT;
}
NTSTATUS Common::BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PUCHAR* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS Common::BBScanSection(IN PVOID Base, IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(Base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2, s3, s4;
		RtlInitAnsiString(&s1, "PAGE");
		RtlInitAnsiString(&s2, ".text");
		RtlInitAnsiString(&s3, "PAGELK");
		RtlInitAnsiString(&s4, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s4, TRUE) == 0 || RtlCompareString(&s2, &s4, TRUE) == 0 || RtlCompareString(&s3, &s4, TRUE) == 0)
		{
			PUCHAR Result = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len - 1, (PUCHAR)Base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &Result);
			if (NT_SUCCESS(status))
			{
				*(PULONG_PTR)ppFound = (ULONG_PTR)Result;
				return status;
			}
		}
	}

	return STATUS_NOT_FOUND;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE Common::GetSSDTBase()
{
	PVOID ntoskrnl = GetKernelBase("ntoskrnl.exe");

	PUCHAR FindResult = NULL;

	UCHAR KiSystemServiceRepeatSign[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

	if (!NT_SUCCESS(BBScanSection(ntoskrnl, KiSystemServiceRepeatSign, 0xCC, sizeof(KiSystemServiceRepeatSign) - 1, (PVOID*)&FindResult)))
	{
		return NULL;
	}
	FindResult = FindResult + 3;
	return (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)(FindResult + *(PLONG)(FindResult)+0x4);
}

PVOID Common::GetSSDTEntry(IN ULONG index)
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow = GetSSDTBase();

	if (KeServiceDescriptorTableShadow)
	{
		if (index > KeServiceDescriptorTableShadow->NumberOfServices)
			return NULL;

		return (PUCHAR)KeServiceDescriptorTableShadow->ServiceTableBase + (((PLONG)KeServiceDescriptorTableShadow->ServiceTableBase)[index] >> 4);
	}
	return NULL;
}

PVOID Common::GetSystemRoutineAddress(LPCWSTR name)
{
	UNICODE_STRING unicodeName;
	RtlInitUnicodeString(&unicodeName, name);
	return MmGetSystemRoutineAddress(&unicodeName);
}

void Common::SpinlockUnlock(volatile LONG* Lock)
{
	*Lock = 0;
}

bool SpinlockTryLock(volatile LONG* Lock)
{
	return (!(*Lock) && !_interlockedbittestandset(Lock, 0));
}

void Common::SpinlockLock(volatile LONG* Lock)
{
	unsigned wait = 1;
	while (!SpinlockTryLock(Lock))
	{
		for (unsigned i = 0; i < wait; ++i)
		{
			_mm_pause();
		}
		if (wait * 2 > MaxWait)
		{
			wait = MaxWait;
		}
		else
		{
			wait = wait * 2;
		}
	}
}