#pragma once
#include "../Global/SysDefine.hpp"

//#define Log( format, ... ) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ VMX ] " format "\n", ##__VA_ARGS__ )

typedef struct _POOL_TABLE
{
	LIST_ENTRY               PoolsList;
	PVOID                    Address;
	PVOID                    MaxAddress;
	SIZE_T                   Size;
} POOL_TABLE, * PPOOL_TABLE;

namespace Common {
	void Sleep(ULONG delay);
	PVOID AllocateMemory(size_t size, bool DisablePaging);
	void FreeMemory(PVOID Address, bool DisablePaging);
	HANDLE GetProcessIdByNameW(PCWSTR Process);
	PVOID GetKernelBase(const char* moduleName);
	ULONG GetNativeFunctionIndex(const char* lpFunctionName);
	NTSTATUS RtlFindImageSection(PVOID ImageBase, CHAR* SectionName, OUT PVOID* SectionStart, OUT PVOID* SectionEnd);
	NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PUCHAR* ppFound);
	NTSTATUS BBScanSection(IN PVOID Base, IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase();
	PVOID GetSSDTEntry(IN ULONG index);
	void* PhysicalToVirtual(ULONG_PTR Physical);
	PMMPTE GetPTEForVA(IN ULONG64 pAddress);
	uint64_t GetProcessCr3(PEPROCESS pProcess);
	uint64_t GetProcessCr32(PEPROCESS pProcess);
	PVOID GetSystemRoutineAddress(LPCWSTR name);
	void SpinlockLock(volatile LONG* Lock);
	void SpinlockUnlock(volatile LONG* Lock);
	BOOLEAN GetKernelBase2(CHAR* ModuleName, PMODULE_INFO info);
};