#include <intrin.h>
#include "Hook.hpp"
#include "EPT.hpp"
#include "../Global/Global.hpp"
#include "../hde/hde64.h"
#include "../Common/Common.hpp"

void EPTHookWriteAbsoluteJump(PUCHAR TargetBuffer, SIZE_T TargetAddress)
{
	TargetBuffer[0] = 0x68;
	*((PUINT32)&TargetBuffer[1]) = (UINT32)TargetAddress;
	TargetBuffer[5] = 0xC7;
	TargetBuffer[6] = 0x44;
	TargetBuffer[7] = 0x24;
	TargetBuffer[8] = 0x04;
	*((PUINT32)&TargetBuffer[9]) = (UINT32)(TargetAddress >> 32);
	TargetBuffer[13] = 0xC3;
}

void PushInstructionPool(PVOID Address, size_t Size)
{
	PPOOL_TABLE SinglePool = (PPOOL_TABLE)ExAllocatePool(NonPagedPool, sizeof(POOL_TABLE));

	if (!SinglePool)
		return;
	RtlZeroMemory(SinglePool, sizeof(POOL_TABLE));
	SinglePool->Address = Address;
	SinglePool->MaxAddress = (PUCHAR)Address + Size;
	SinglePool->Size = Size;
	Common::SpinlockLock(&Global::g_InstructionPoolsListLock);
	InsertTailList(&Global::InstructionPoolsList, &SinglePool->PoolsList);
	Common::SpinlockUnlock(&Global::g_InstructionPoolsListLock);
}

bool EPTHookInstructionMemory(PEPT_HOOKED_PAGE_DETAIL Hook, PVOID TargetFunction, PUCHAR TargetFunctionInSafeMemory, PVOID HookFunction, PVOID* pTrampoline)
{
	hde64s                       hs;
	SIZE_T                       SizeOfHookedInstructions;
	SIZE_T                       OffsetIntoPage;
	OffsetIntoPage = ADDRMASK_EPT_PML1_OFFSET((SIZE_T)TargetFunction);
	if ((OffsetIntoPage + 14) > PAGE_SIZE - 1)
		return false;
	for (SizeOfHookedInstructions = 0; SizeOfHookedInstructions < 14; SizeOfHookedInstructions += hde64_disasm(TargetFunctionInSafeMemory + SizeOfHookedInstructions, &hs)) {}
	if (pTrampoline)
	{
		ULONG Size = 64;
		Hook->Trampoline = (PUCHAR)ExAllocatePool(NonPagedPool, Size);
		if (!Hook->Trampoline)
			return false;

		PushInstructionPool(Hook->Trampoline, Size);

		RtlCopyMemory(Hook->Trampoline, TargetFunctionInSafeMemory, SizeOfHookedInstructions);
		EPTHookWriteAbsoluteJump(&Hook->Trampoline[SizeOfHookedInstructions], (SIZE_T)TargetFunction + SizeOfHookedInstructions);
		*pTrampoline = Hook->Trampoline;
	}
	EPTHookWriteAbsoluteJump(&Hook->FakePageContents[OffsetIntoPage], (SIZE_T)HookFunction);
	return true;
}

bool EPTHookPerformPageHook(PVOID TargetAddress, PVOID HookFunction, PVOID* pTrampoline, BOOLEAN IsKernel)
{
	SIZE_T                  PhysicalBaseAddress;
	PVOID                   VirtualTarget;
	UINT64                  TargetAddressInSafeMemory;
	UINT64                  PageOffset;
	EPTE* TargetPage;

	VirtualTarget = PAGE_ALIGN(TargetAddress);
	PhysicalBaseAddress = (SIZE_T)MmGetPhysicalAddress(VirtualTarget).QuadPart;

	if (!PhysicalBaseAddress)
		return false;

	PLIST_ENTRY HookPagesListHead = IsKernel ? &Global::HookedKernelPagesList : &Global::HookedUserPagesList;
	for (PLIST_ENTRY pListEntry = HookPagesListHead->Flink; pListEntry != HookPagesListHead; pListEntry = pListEntry->Flink)
	{
		PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(pListEntry, EPT_HOOKED_PAGE_DETAIL, PageHookList);
		if (HookedEntry->PhysicalBaseAddress == PhysicalBaseAddress)
		{
			TargetAddressInSafeMemory = (UINT64)&HookedEntry->FakePageContents;
			TargetAddressInSafeMemory = (UINT64)PAGE_ALIGN(TargetAddressInSafeMemory);
			PageOffset = (UINT64)PAGE_OFFSET(TargetAddress);
			TargetAddressInSafeMemory = TargetAddressInSafeMemory + PageOffset;
			if (!EPTHookInstructionMemory(HookedEntry, TargetAddress, (PUCHAR)TargetAddressInSafeMemory, HookFunction, pTrampoline))
				return false;
			return true;
		}
	}

	TargetPage = EPT::EPTConstructTables(EPT::g_EPTData.EPT_PML4, 4, PhysicalBaseAddress, &EPT::g_EPTData);

	if (!TargetPage)
		return false;

	PEPT_HOOKED_PAGE_DETAIL HookedPage = (PEPT_HOOKED_PAGE_DETAIL)Common::AllocateMemory(sizeof(EPT_HOOKED_PAGE_DETAIL), false);

	if (!HookedPage)
		return false;

	memset(HookedPage, 0, sizeof(EPT_HOOKED_PAGE_DETAIL));
	HookedPage->IsKernel = IsKernel;
	HookedPage->Process = PsGetCurrentProcess();

	HookedPage->VirtualAddress = TargetAddress;
	HookedPage->PhysicalBaseAddress = PhysicalBaseAddress;
	HookedPage->EntryAddress = TargetPage;

	HookedPage->ChangedEntry.Flags = TargetPage->Flags;
	HookedPage->ChangedEntry.ReadAccess = false;
	HookedPage->ChangedEntry.WriteAccess = false;
	HookedPage->ChangedEntry.ExecuteAccess = true;
	HookedPage->ChangedEntry.PageFrameNumber = (SIZE_T)MmGetPhysicalAddress(&HookedPage->FakePageContents[0]).QuadPart / PAGE_SIZE;

	HookedPage->OriginalEntry.Flags = TargetPage->Flags;
	HookedPage->OriginalEntry.ReadAccess = true;
	HookedPage->OriginalEntry.WriteAccess = true;
	HookedPage->OriginalEntry.ExecuteAccess = false;

	RtlCopyBytes(&HookedPage->FakePageContents, VirtualTarget, PAGE_SIZE);

	TargetAddressInSafeMemory = (UINT64)&HookedPage->FakePageContents;
	TargetAddressInSafeMemory = (UINT64)PAGE_ALIGN(TargetAddressInSafeMemory);
	PageOffset = (UINT64)PAGE_OFFSET(TargetAddress);
	TargetAddressInSafeMemory = TargetAddressInSafeMemory + PageOffset;

	if (!EPTHookInstructionMemory(HookedPage, TargetAddress, (PUCHAR)TargetAddressInSafeMemory, HookFunction, pTrampoline))
		return false;

	Common::SpinlockLock(&Global::g_HookPagesListLock);
	InsertTailList(HookPagesListHead, &HookedPage->PageHookList);
	Common::SpinlockUnlock(&Global::g_HookPagesListLock);

	HookedPage->EntryAddress->Flags = HookedPage->ChangedEntry.Flags;
	__invlpg(TargetAddress);

	return true;
}

void EPTCleanInvalidHook(PEPROCESS ExitProcess, bool IsKernel)
{
	Common::SpinlockLock(&Global::g_HookPagesListLock);

	PLIST_ENTRY HookPagesListHead = IsKernel ? &Global::HookedKernelPagesList : &Global::HookedUserPagesList;

	for (PLIST_ENTRY pListEntry = HookPagesListHead->Flink; pListEntry != HookPagesListHead; pListEntry = pListEntry->Flink)
	{
		PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(pListEntry, EPT_HOOKED_PAGE_DETAIL, PageHookList);
		if (HookedEntry->IsKernel)
		{
			if (!MmIsAddressValid(HookedEntry->VirtualAddress))
			{
				if (HookedEntry->Trampoline)
				{
					Common::SpinlockLock(&Global::g_InstructionPoolsListLock);
					for (PLIST_ENTRY pInstructionListEntry = Global::InstructionPoolsList.Flink; pInstructionListEntry != &Global::InstructionPoolsList; pInstructionListEntry = pInstructionListEntry->Flink)
					{
						PPOOL_TABLE PoolTable = CONTAINING_RECORD(pInstructionListEntry, POOL_TABLE, PoolsList);
						if (PoolTable) {
							if (HookedEntry->Trampoline == PoolTable->Address)
							{
								RemoveEntryList(&PoolTable->PoolsList);
								ExFreePoolWithTag(HookedEntry->Trampoline, 0);
								break;
							}
						}
					}
					Common::SpinlockUnlock(&Global::g_InstructionPoolsListLock);
				}
				RemoveEntryList(&HookedEntry->PageHookList);
				//Common::FreeMemory(HookedEntry, false);
			}
		}
		else if (ExitProcess == HookedEntry->Process)
		{
			HookedEntry->EntryAddress->Flags = HookedEntry->OriginalEntry.Flags;
			RemoveEntryList(&HookedEntry->PageHookList);
			//Common::FreeMemory(HookedEntry, false);
		}
	}
	Common::SpinlockUnlock(&Global::g_HookPagesListLock);
}

bool EPTHandlePageHookExit(ULONG_PTR PhysicalAddress)
{
	VMX_EXIT_QUALIFICATION_EPT_VIOLATION ExitQualification = { 0 };
	__vmx_vmread(VMCS_EXIT_QUALIFICATION, (size_t*)&ExitQualification.Flags);

	if (!ExitQualification.CausedByTranslation)
		return false;

	ULONG_PTR VirtualAddress;
	__vmx_vmread(VMCS_EXIT_GUEST_LINEAR_ADDRESS, &VirtualAddress);

	PLIST_ENTRY HookPagesListHead = (VirtualAddress > MmUserProbeAddress) ? &Global::HookedKernelPagesList : &Global::HookedUserPagesList;

	for (PLIST_ENTRY pListEntry = HookPagesListHead->Flink; pListEntry != HookPagesListHead; pListEntry = pListEntry->Flink)
	{
		PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(pListEntry, EPT_HOOKED_PAGE_DETAIL, PageHookList);
		if (PAGE_ALIGN(HookedEntry->PhysicalBaseAddress) == PAGE_ALIGN(PhysicalAddress))
		{
			bool ReadFailure = ExitQualification.ReadAccess && !ExitQualification.EptReadable;
			bool WriteFailure = ExitQualification.WriteAccess && !ExitQualification.EptWriteable;
			bool ExecuteFailure = ExitQualification.ExecuteAccess && !ExitQualification.EptExecutable;
			if (ReadFailure || WriteFailure)
			{
				HookedEntry->EntryAddress->Flags = HookedEntry->OriginalEntry.Flags;
				return true;
			}
			else if (ExecuteFailure)
			{
				HookedEntry->EntryAddress->Flags = HookedEntry->ChangedEntry.Flags;
				return true;
			}
			break;
		}
	}
	return false;
}