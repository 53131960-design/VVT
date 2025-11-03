#include <ntifs.h>
#include <intrin.h>
#include "Memory.hpp"
#include "EPT.hpp"
#include "../Common/Common.hpp"

#define PAGE_4KB_OFFSET ((UINT64)(1 << 12) - 1)
#define PAGE_2MB_OFFSET ((UINT64)(1 << 21) - 1)
#define PAGE_4MB_OFFSET ((UINT64)(1 << 22) - 1)
#define PAGE_1GB_OFFSET ((UINT64)(1 << 30) - 1)
#define PAGE_OFFSET_SIZE 12

static const ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;

MEMORY_MAPPER_ADDRESSES MemoryMapper = { 0 };

void InitMemory()
{
	MemoryMapper.VirualAddress = (ULONG64)Common::AllocateMemory(PAGE_SIZE * 2, false);
	MemoryMapper.PhysicsAddress = MmGetPhysicalAddress((PVOID)MemoryMapper.VirualAddress).QuadPart;
	MemoryMapper.EPT = EPT::EPTConstructTables(EPT::g_EPTData.EPT_PML4, 4, MemoryMapper.PhysicsAddress, &EPT::g_EPTData);
}

NTSTATUS ReadPhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MemoryMapper.EPT->PageFrameNumber = TargetAddress >> PAGE_SHIFT;
	MemoryMapper.EPT->WriteAccess = true;
	MemoryMapper.EPT->ReadAccess = true;
	__invlpg((PVOID)MemoryMapper.VirualAddress);
	PVOID NewAddress = (PVOID)(MemoryMapper.VirualAddress + (PAGE_4KB_OFFSET & (TargetAddress)));
	memcpy(lpBuffer, NewAddress, Size);
	*BytesRead = Size;
	return STATUS_SUCCESS;
}

NTSTATUS WritePhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	MemoryMapper.EPT->PageFrameNumber = TargetAddress >> PAGE_SHIFT;
	MemoryMapper.EPT->WriteAccess = true;
	MemoryMapper.EPT->ReadAccess = true;
	__invlpg((PVOID)MemoryMapper.VirualAddress);
	PVOID	NewAddress = (PVOID)(MemoryMapper.VirualAddress + (PAGE_4KB_OFFSET & (TargetAddress)));
	memcpy(NewAddress, lpBuffer, Size);
	*BytesWritten = Size;
	return STATUS_SUCCESS;
}

ULONG64 TranslateLinearAddress(ULONG64 directoryTableBase, ULONG64 virtualAddress) {
	directoryTableBase &= ~0xf;

	ULONG64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	ULONG64 pte = ((virtualAddress >> 12) & (0x1ffll));
	ULONG64 pt = ((virtualAddress >> 21) & (0x1ffll));
	ULONG64 pd = ((virtualAddress >> 30) & (0x1ffll));
	ULONG64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	ULONG64 pdpe = 0;
	ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	ULONG64 pde = 0;
	ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	ULONG64 pteAddr = 0;
	ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

NTSTATUS ReadProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess = NULL;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		ObfDereferenceObject(pProcess);
		ULONG_PTR ProcessDirbase = Common::GetProcessCr3(pProcess);
		SIZE_T CurOffset = 0, TotalSize = size;
		while (TotalSize)
		{
			ULONG_PTR CurrentPhysAddress = TranslateLinearAddress(ProcessDirbase, (ULONG_PTR)Address + CurOffset);
			if (!CurrentPhysAddress) 
				return STATUS_UNSUCCESSFUL;
			ULONG_PTR ReadSize = min(PAGE_SIZE - (CurrentPhysAddress & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			status = ReadPhysicalAddress(CurrentPhysAddress, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			if (!NT_SUCCESS(status))
				break;
			if (!BytesRead) 
				break;
		}
		*read = CurOffset;
	}
	return status;
}

NTSTATUS WriteProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess = NULL;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		ObfDereferenceObject(pProcess);
		ULONG_PTR ProcessDirbase = Common::GetProcessCr3(pProcess);
		SIZE_T CurOffset = 0, TotalSize = size;
		while (TotalSize)
		{
			ULONG_PTR CurrentPhysAddress = TranslateLinearAddress(ProcessDirbase, (ULONG_PTR)Address + CurOffset);
			if (!CurrentPhysAddress)
				return STATUS_UNSUCCESSFUL;
			ULONG64 WriteSize = min(PAGE_SIZE - (CurrentPhysAddress & 0xFFF), TotalSize);
			SIZE_T BytesWritten = 0;
			status = WritePhysicalAddress(CurrentPhysAddress, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			if (!NT_SUCCESS(status))
				break;
			if (!BytesWritten)
				break;
		}
		*written = CurOffset;
	}
	return status;
}