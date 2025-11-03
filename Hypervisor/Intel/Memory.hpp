#pragma once
#include "ia32.hpp"

typedef struct _MEMORY_MAPPER_ADDRESSES
{
	ULONG64 VirualAddress;
	ULONG64 PhysicsAddress;
	EPTE* EPT;
} MEMORY_MAPPER_ADDRESSES, * PMEMORY_MAPPER_ADDRESSES;

void InitMemory();
NTSTATUS ReadProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
NTSTATUS WriteProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);