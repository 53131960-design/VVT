#include <intrin.h>
#include "EPT.hpp"
#include "VMExit.hpp"
#include "../Common/Common.hpp"

MTRRData						EPT::g_MTRREntries[MTRREntrieCount] = { 0 };
ULONG							EPT::g_MRTTDefaultType = 0;
CPUEPT							EPT::g_EPTData = { 0 };
PhysicalMemoryDescriptor*		EPT::g_PhysicalMemoryRanges = nullptr;

void EPT::EPTInitializeMTRREntries() {
	ULONG Index = 0;
	MTRRData* MTRREntries = g_MTRREntries;

	IA32_MTRR_DEF_TYPE_REGISTER DefaultType = { 0 };
	DefaultType.Flags = __readmsr(IA32_MTRR_DEF_TYPE);

	g_MRTTDefaultType = DefaultType.DefaultMemoryType;

	IA32_MTRR_CAPABILITIES_REGISTER MTRRCapabilities = { 0 };
	MTRRCapabilities.Flags = __readmsr(IA32_MTRR_CAPABILITIES);

	if (MTRRCapabilities.FixedRangeSupported && DefaultType.FixedRangeMtrrEnable) {
		IA32_MTRR_FixedRange FixedRange = { 0 };
		FixedRange.all = __readmsr(IA32_MTRR_FIX64K_00000);
		ULONG_PTR Offset = 0;
		for (size_t i = 0; i < 8ull; i++)
		{
			ULONG_PTR Base = 0 + Offset;
			Offset += 0x10000;
			MTRREntries[Index].Enabled = true;
			MTRREntries[Index].FixedMTRR = true;
			MTRREntries[Index].Type = FixedRange.fields.Types[i];
			MTRREntries[Index].RangeBase = Base;
			MTRREntries[Index].RangeEnd = Base + 0x10000 - 1;
			Index++;
		}
		Offset = 0;
		for (ULONG MSR = IA32_MTRR_FIX16K_80000; MSR <= IA32_MTRR_FIX16K_A0000; MSR++)
		{
			FixedRange.all = __readmsr(MSR);
			for (size_t i = 0; i < 8ull; i++)
			{
				ULONG_PTR Base = 0x80000 + Offset;
				Offset += 0x4000;
				MTRREntries[Index].Enabled = true;
				MTRREntries[Index].FixedMTRR = true;
				MTRREntries[Index].Type = FixedRange.fields.Types[i];
				MTRREntries[Index].RangeBase = Base;
				MTRREntries[Index].RangeEnd = Base + 0x4000 - 1;
				Index++;
			}
		}
		Offset = 0;
		for (ULONG MSR = IA32_MTRR_FIX4K_C0000; MSR <= IA32_MTRR_FIX4K_F8000; MSR++)
		{
			FixedRange.all = __readmsr(MSR);
			for (size_t i = 0; i < 8ull; i++)
			{
				ULONG_PTR Base = 0xC0000 + Offset;
				Offset += 0x1000;
				MTRREntries[Index].Enabled = true;
				MTRREntries[Index].FixedMTRR = true;
				MTRREntries[Index].Type = FixedRange.fields.Types[i];
				MTRREntries[Index].RangeBase = Base;
				MTRREntries[Index].RangeEnd = Base + 0x1000 - 1;
				Index++;
			}
		}
	}

	for (ULONG i = 0; i < MTRRCapabilities.VariableRangeCount; i++)
	{
		ULONG PhyMask = IA32_MTRR_PHYSMASK0 + i * 2;
		IA32_MTRR_PHYSMASK_REGISTER MTRRMask = { 0 };
		MTRRMask.Flags = __readmsr(PhyMask);

		if (!MTRRMask.Valid)
			continue;

		ULONG Length;
		_BitScanForward64(&Length, MTRRMask.PageFrameNumber * PAGE_SIZE);

		ULONG PhyBase = IA32_MTRR_PHYSBASE0 + i * 2;
		IA32_MTRR_PHYSBASE_REGISTER MTRRBase = { 0 };
		MTRRBase.Flags = __readmsr(PhyBase);
		ULONG_PTR Base = MTRRBase.PageFrameNumber * PAGE_SIZE;
		ULONG_PTR End = Base + (1ull << Length) - 1;
		MTRREntries[Index].Enabled = true;
		MTRREntries[Index].FixedMTRR = false;
		MTRREntries[Index].Type = MTRRBase.Type;
		MTRREntries[Index].RangeBase = Base;
		MTRREntries[Index].RangeEnd = End;
		Index++;
	}
}

ULONG EPT::EPTGetMemoryType(ULONG_PTR PhysicalAddress) {
	UCHAR ResultType = MAXUCHAR;
	for (size_t i = 0; i < MTRREntrieCount; i++)
	{
		MTRRData MTRREntries = g_MTRREntries[i];
		if (!MTRREntries.Enabled)
			break;

		if (!((MTRREntries.RangeBase <= PhysicalAddress) && (PhysicalAddress <= MTRREntries.RangeEnd)))
			continue;

		if (MTRREntries.FixedMTRR)
		{
			ResultType = MTRREntries.Type;
			break;
		}

		if (MTRREntries.Type == MEMORY_TYPE_UNCACHEABLE)
		{
			ResultType = MTRREntries.Type;
			break;
		}

		if (ResultType == MEMORY_TYPE_WRITE_THROUGH || MTRREntries.Type == MEMORY_TYPE_WRITE_THROUGH)
		{
			if (ResultType == MEMORY_TYPE_WRITE_BACK)
			{
				ResultType = MEMORY_TYPE_WRITE_THROUGH;
				continue;
			}
		}

		ResultType = MTRREntries.Type;
	}

	if (ResultType == MAXUCHAR)
		ResultType = (UCHAR)g_MRTTDefaultType;

	return ResultType;
}

PhysicalMemoryDescriptor* EPT::BuildPhysicalMemoryRanges()
{
	PPHYSICAL_MEMORY_RANGE PhysicalMemoryRanges = MmGetPhysicalMemoryRanges();
	if (!PhysicalMemoryRanges)
		return nullptr;

	PFN_COUNT NumberRuns = 0;
	PFN_NUMBER NumberPages = 0;
	for (;; ++NumberRuns)
	{
		PPHYSICAL_MEMORY_RANGE Range = &PhysicalMemoryRanges[NumberRuns];
		if (!Range->BaseAddress.QuadPart && !Range->NumberOfBytes.QuadPart)
			break;
		NumberPages += (PFN_NUMBER)BYTES_TO_PAGES(Range->NumberOfBytes.QuadPart);
	}
	if (!NumberPages)
	{
		ExFreePoolWithTag(PhysicalMemoryRanges, 'hPmM');
		return nullptr;
	}

	ULONG_PTR MemoryBlockSize = sizeof(PhysicalMemoryDescriptor) + sizeof(PhysicalMemoryRun) * (NumberRuns - 1);

	PhysicalMemoryDescriptor* PhysicalMemoryBlock = (PhysicalMemoryDescriptor*)Common::AllocateMemory(MemoryBlockSize, false);

	if (!PhysicalMemoryBlock)
	{
		ExFreePoolWithTag(PhysicalMemoryRanges, 'hPmM');
		return nullptr;
	}

	RtlZeroMemory(PhysicalMemoryBlock, MemoryBlockSize);

	PhysicalMemoryBlock->NumberOfRuns = NumberRuns;
	PhysicalMemoryBlock->NumberOfPages = NumberPages;

	for (ULONG RunIndex = 0ul; RunIndex < NumberRuns; RunIndex++)
	{
		PhysicalMemoryRun* CurrentRun = &PhysicalMemoryBlock->Run[RunIndex];
		PPHYSICAL_MEMORY_RANGE CurrentBlock = &PhysicalMemoryRanges[RunIndex];
		CurrentRun->BasePage = (ULONG_PTR)(CurrentBlock->BaseAddress.QuadPart >> PAGE_SHIFT);
		CurrentRun->PageCount = (ULONG_PTR)(BYTES_TO_PAGES(CurrentBlock->NumberOfBytes.QuadPart));
	}

	ExFreePoolWithTag(PhysicalMemoryRanges, 'hPmM');

	return PhysicalMemoryBlock;
}

EPTE* AllocateEPTEntryFromPreAllocated(CPUEPT* CPU_EPT)
{
	LONG Count = InterlockedIncrement(&CPU_EPT->PreallocatedEntriesCount);
	if (Count > EPTNumberOfPreallocatedEntries)
		KeBugCheck(0xDEADBEEF);
	return CPU_EPT->PreallocatedEntries[Count - 1];
}

EPTE* AllocateEPTEntryFromPool()
{
	ULONG_PTR AllocSize = 512 * sizeof(EPTE);
	EPTE* Entry = (EPTE*)Common::AllocateMemory(AllocSize, false);
	if (!Entry)
		return Entry;
	RtlZeroMemory(Entry, AllocSize);
	return Entry;
}

EPTE* AllocateEPTEntry(CPUEPT* CPU_EPT)
{
	if (CPU_EPT)
		return AllocateEPTEntryFromPreAllocated(CPU_EPT);
	else
		return AllocateEPTEntryFromPool();
}

void EPT::FreeUnusedPreAllocatedEntries(EPTE** PreallocatedEntries, LONG UsedCount) {
	for (LONG i = UsedCount; i < EPTNumberOfPreallocatedEntries; ++i) {
		if (!PreallocatedEntries[i])
			break;
		Common::FreeMemory(PreallocatedEntries[i], false);
	}
	Common::FreeMemory(PreallocatedEntries, false);
}

void EPTInitTableEntry(EPTE* Entry, ULONG TableLevel, ULONG64 PhysicalAddress) {
	Entry->ReadAccess = true;
	Entry->WriteAccess = true;
	Entry->ExecuteAccess = true;
	Entry->PageFrameNumber = PhysicalAddress >> PAGE_SHIFT;
	if (TableLevel == 1)
		Entry->MemoryType = EPT::EPTGetMemoryType(PhysicalAddress);
}

EPTE* EPT::EPTGetPTEntry(EPTE* Table, ULONG TableLevel, ULONG64 PhysicalAddress)
{
	if (!Table)
		return nullptr;

	switch (TableLevel) {
	case 4: {
		ULONG_PTR PxeIndex = ((PhysicalAddress >> 39ull) & 0x1FFull);
		EPTE* EPTPML4Entry = &Table[PxeIndex];
		if (!EPTPML4Entry->Flags) {
			return nullptr;
		}
		return EPTGetPTEntry((EPTE*)Common::PhysicalToVirtual(EPTPML4Entry->PageFrameNumber << PAGE_SHIFT), TableLevel - 1, PhysicalAddress);
	}
	case 3: {
		ULONG_PTR PpeIndex = ((PhysicalAddress >> 30ull) & 0x1FFull);
		EPTE* EPTPDPTEntry = &Table[PpeIndex];
		if (!EPTPDPTEntry->Flags) {
			return nullptr;
		}
		return EPTGetPTEntry((EPTE*)Common::PhysicalToVirtual(EPTPDPTEntry->PageFrameNumber << PAGE_SHIFT), TableLevel - 1, PhysicalAddress);
	}
	case 2: {
		ULONG_PTR PdeIndex = ((PhysicalAddress >> 21ull) & 0x1FFull);
		EPTE* EPTPDTEntry = &Table[PdeIndex];
		if (!EPTPDTEntry->Flags) {
			return nullptr;
		}
		return EPTGetPTEntry((EPTE*)Common::PhysicalToVirtual(EPTPDTEntry->PageFrameNumber << PAGE_SHIFT), TableLevel - 1, PhysicalAddress);
	}
	case 1: {
		ULONG_PTR PteIndex = ((PhysicalAddress >> 12ull) & 0x1FFull);
		EPTE* EPTPTEntry = &Table[PteIndex];
		return EPTPTEntry;
	}
	default:
		return nullptr;
	}
}

EPTE* EPT::EPTConstructTables(EPTE* Table, ULONG TableLevel, ULONG64 PhysicalAddress, CPUEPT* CPU_EPT)
{
	switch (TableLevel) {
	case 4: {
		ULONG_PTR PxeIndex = ((PhysicalAddress >> 39ull) & 0x1FFull);
		EPTE* EPTPML4Entry = &Table[PxeIndex];
		if (!EPTPML4Entry->Flags) {
			EPTE* EPTPDPT = AllocateEPTEntry(CPU_EPT);
			if (!EPTPDPT)
				return nullptr;
			EPTInitTableEntry(EPTPML4Entry, TableLevel, MmGetPhysicalAddress(EPTPDPT).QuadPart);
		}
		return EPTConstructTables((EPTE*)Common::PhysicalToVirtual(EPTPML4Entry->PageFrameNumber << PAGE_SHIFT), TableLevel - 1, PhysicalAddress, CPU_EPT);
	}
	case 3: {
		ULONG_PTR PpeIndex = ((PhysicalAddress >> 30ull) & 0x1FFull);
		EPTE* EPTPDPTEntry = &Table[PpeIndex];
		if (!EPTPDPTEntry->Flags) {
			EPTE* EPTPDT = AllocateEPTEntry(CPU_EPT);
			if (!EPTPDT)
				return nullptr;
			EPTInitTableEntry(EPTPDPTEntry, TableLevel, MmGetPhysicalAddress(EPTPDT).QuadPart);
		}
		return EPTConstructTables((EPTE*)Common::PhysicalToVirtual(EPTPDPTEntry->PageFrameNumber << PAGE_SHIFT), TableLevel - 1, PhysicalAddress, CPU_EPT);
	}
	case 2: {
		ULONG_PTR PdeIndex = ((PhysicalAddress >> 21ull) & 0x1FFull);
		EPTE* EPTPDTEntry = &Table[PdeIndex];
		if (!EPTPDTEntry->Flags) {
			EPTE* EPTPT = AllocateEPTEntry(CPU_EPT);
			if (!EPTPT)
				return nullptr;
			EPTInitTableEntry(EPTPDTEntry, TableLevel, MmGetPhysicalAddress(EPTPT).QuadPart);
		}
		return EPTConstructTables((EPTE*)Common::PhysicalToVirtual(EPTPDTEntry->PageFrameNumber << PAGE_SHIFT), TableLevel - 1, PhysicalAddress, CPU_EPT);
	}
	case 1: {
		ULONG_PTR PteIndex = ((PhysicalAddress >> 12ull) & 0x1FFull);
		EPTE* EPTPTEntry = &Table[PteIndex];
		EPTInitTableEntry(EPTPTEntry, TableLevel, PhysicalAddress);
		return EPTPTEntry;
	}
	default:
		return nullptr;
	}
}

void EPT::EPTDestructTables(EPTE* Table, ULONG TableLevel)
{
	for (ULONG i = 0; i < 512; ++i)
	{
		EPTE Entry = Table[i];
		if (Entry.PageFrameNumber)
		{
			EPTE* SubTable = (EPTE*)Common::PhysicalToVirtual(Entry.PageFrameNumber << PAGE_SHIFT);
			if (TableLevel == 3)
				EPTDestructTables(SubTable, TableLevel - 1);
			else if (TableLevel == 2)
				Common::FreeMemory(SubTable, false);
		}
	}
	Common::FreeMemory(Table, false);
}

void NTAPI VmpSetLockBitCallback(_In_ struct _KDPC* Dpc, _In_opt_ PVOID context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	IA32_FEATURE_CONTROL_REGISTER FeatureControl = { 0 };
	FeatureControl.Flags = __readmsr(IA32_FEATURE_CONTROL);
	if (!FeatureControl.LockBit)
	{
		FeatureControl.LockBit = true;
		__writemsr(IA32_FEATURE_CONTROL, FeatureControl.Flags);
		FeatureControl.Flags = __readmsr(IA32_FEATURE_CONTROL);
	}

	if (SystemArgument2) 
		KeSignalCallDpcSynchronize(SystemArgument2);
	if (SystemArgument1) 
		KeSignalCallDpcDone(SystemArgument1);
}

CPUEPT EPT::EPTInitialization()
{
	CPUEPT Result = { 0 };

	EPTE* EPTPML4 = (EPTE*)Common::AllocateMemory(PAGE_SIZE, false);

	if (!EPTPML4)
		return Result;

	IA32_FEATURE_CONTROL_REGISTER FeatureControl = { 0 };
	FeatureControl.Flags = __readmsr(IA32_FEATURE_CONTROL);
	if (!FeatureControl.LockBit)
		KeGenericCallDpc(VmpSetLockBitCallback, (PVOID)nullptr);

	RtlZeroMemory(EPTPML4, PAGE_SIZE);

	Result.EPTPointer.Flags = 0;
	Result.EPTPointer.EnableAccessAndDirtyFlags = false;
	Result.EPTPointer.MemoryType = (ULONG_PTR)EPTGetMemoryType(MmGetPhysicalAddress(EPTPML4).QuadPart);
	Result.EPTPointer.PageWalkLength = 3;
	Result.EPTPointer.PageFrameNumber = MmGetPhysicalAddress(EPTPML4).QuadPart >> PAGE_SHIFT;
	PhysicalMemoryDescriptor* PhysicalMemoryRanges = g_PhysicalMemoryRanges;
	for (ULONG RunIndex = 0ul; RunIndex < PhysicalMemoryRanges->NumberOfRuns; ++RunIndex)
	{
		PhysicalMemoryRun* Run = &PhysicalMemoryRanges->Run[RunIndex];
		ULONG_PTR BaseAddress = Run->BasePage * PAGE_SIZE;
		for (ULONG_PTR PageIndex = 0ull; PageIndex < Run->PageCount; ++PageIndex)
		{
			ULONG_PTR IndexAddress = BaseAddress + PageIndex * PAGE_SIZE;

			EPTE* EPTPTEntry = EPTConstructTables(EPTPML4, 4, IndexAddress, nullptr);
			if (!EPTPTEntry) {
				EPTDestructTables(EPTPML4, 4);
				return Result;
			}
		}
	}

	IA32_APIC_BASE_REGISTER ACPIBase = { 0 };
	ACPIBase.Flags = __readmsr(IA32_APIC_BASE);

	if (!EPTConstructTables(EPTPML4, 4, ACPIBase.ApicBase * PAGE_SIZE, nullptr))
	{
		EPTDestructTables(EPTPML4, 4);
		return Result;
	}

	ULONG_PTR PreallocatedEntriesSize = sizeof(EPTE*) * EPTNumberOfPreallocatedEntries;
	EPTE** PreallocatedEntries = (EPTE**)Common::AllocateMemory(PreallocatedEntriesSize, false);
	if (!PreallocatedEntries) {
		EPTDestructTables(EPTPML4, 4);
		return Result;
	}

	RtlZeroMemory(PreallocatedEntries, PreallocatedEntriesSize);

	for (ULONG i = 0ul; i < EPTNumberOfPreallocatedEntries; ++i)
	{
		EPTE* EPTEntry = AllocateEPTEntry(nullptr);
		if (!EPTEntry) {
			FreeUnusedPreAllocatedEntries(PreallocatedEntries, 0);
			EPTDestructTables(EPTPML4, 4);
			return Result;
		}
		PreallocatedEntries[i] = EPTEntry;
	}
	Result.EPT_PML4 = EPTPML4;
	Result.PreallocatedEntries = PreallocatedEntries;
	Result.PreallocatedEntriesCount = 0;
	return Result;
}
