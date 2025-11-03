#pragma once
#include <ntifs.h>
#include "ia32.hpp"

#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (_VAR_ & 0xFFFULL)
#define PAGE_OFFSET(Va) ((PVOID)((ULONG_PTR)(Va) & (PAGE_SIZE - 1)))

typedef struct _EPT_HOOKED_PAGE_DETAIL
{
	LIST_ENTRY PageHookList;
	DECLSPEC_ALIGN(PAGE_SIZE)UCHAR FakePageContents[PAGE_SIZE];
	PVOID VirtualAddress;
	SIZE_T PhysicalBaseAddress;
	EPTE* EntryAddress;
	EPTE OriginalEntry;
	EPTE ChangedEntry;
	PUCHAR Trampoline;
	PEPROCESS Process;
	BOOLEAN IsKernel;
} EPT_HOOKED_PAGE_DETAIL, * PEPT_HOOKED_PAGE_DETAIL;

bool EPTHandlePageHookExit(ULONG_PTR PhysicalAddress);
bool EPTHookPerformPageHook(PVOID TargetAddress, PVOID HookFunction, PVOID* pTrampoline, BOOLEAN IsKernel);
void EPTCleanInvalidHook(PEPROCESS ExitProcess, bool kernel);