#pragma once
#include <ntifs.h>
#include "ia32.hpp"

#define MTRREntrieCount                   343  
#define EPTNumberOfPreallocatedEntries    128

typedef struct _MTRRData {
	bool Enabled;
	bool FixedMTRR;
	UCHAR Type;
	ULONG_PTR RangeBase;
	ULONG_PTR RangeEnd;
}MTRRData, * pMTRRData;

union IA32_MTRR_FixedRange {
	ULONG64 all;
	struct {
		UCHAR Types[8];
	} fields;
};

typedef struct _CPUEPT {
	EPT_POINTER   EPTPointer;
	EPTE*         EPT_PML4;
	EPTE**        PreallocatedEntries;
	volatile long PreallocatedEntriesCount;
}CPUEPT, * pCPUEPT;

typedef struct _PhysicalMemoryRun {
	ULONG_PTR BasePage;
	ULONG_PTR PageCount;
}PhysicalMemoryRun, * pPhysicalMemoryRun;

typedef struct _PhysicalMemoryDescriptor {
	PFN_COUNT NumberOfRuns;
	PFN_NUMBER NumberOfPages;
	PhysicalMemoryRun Run[1];
}PhysicalMemoryDescriptor, * pPhysicalMemoryDescriptor;

namespace EPT {
	extern MTRRData							g_MTRREntries[MTRREntrieCount];
	extern ULONG							g_MRTTDefaultType;
	extern CPUEPT							g_EPTData;
	extern PhysicalMemoryDescriptor*		g_PhysicalMemoryRanges;

	void EPTInitializeMTRREntries();
	ULONG EPTGetMemoryType(ULONG_PTR PhysicalAddress);
	PhysicalMemoryDescriptor* BuildPhysicalMemoryRanges();
	CPUEPT EPTInitialization();
	void EPTDestructTables(EPTE* Table, ULONG TableLevel);
	void FreeUnusedPreAllocatedEntries(EPTE** PreallocatedEntries, LONG UsedCount);
	EPTE* EPTConstructTables(EPTE* Table, ULONG TableLevel, ULONG64 PhysicalAddress, CPUEPT* CPU_EPT);
	EPTE* EPTGetPTEntry(EPTE* Table, ULONG TableLevel, ULONG64 PhysicalAddress);
};