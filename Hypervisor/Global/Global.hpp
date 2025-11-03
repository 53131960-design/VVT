#pragma once
#include "SysDefine.hpp"

namespace Global {
	extern pIntelVmx g_IntelVmx;
	extern SYSTEM_ROUTINE_ADDRESS g_pSysRotineAddr;
	extern LIST_ENTRY HookedKernelPagesList;
	extern LIST_ENTRY HookedUserPagesList;
	extern LIST_ENTRY AllocatedPoolsList;
	extern LIST_ENTRY ProtectPoolsList;
	extern LIST_ENTRY InstructionPoolsList;

	extern ULONG_PTR g_CPUIDRip;

	extern LONG g_ProtectPoolLock;
	extern LONG g_AllocatedPoolsLock;
	extern LONG g_HookPagesListLock;
	extern LONG g_InstructionPoolsListLock;

	extern UCHAR g_HackCard[0x256];
};