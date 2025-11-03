#include "Global.hpp"

pIntelVmx Global::g_IntelVmx = NULL;
SYSTEM_ROUTINE_ADDRESS Global::g_pSysRotineAddr = { 0 };
LIST_ENTRY Global::HookedKernelPagesList = { 0 };
LIST_ENTRY Global::HookedUserPagesList = { 0 };
LIST_ENTRY Global::AllocatedPoolsList = { 0 };
LIST_ENTRY Global::ProtectPoolsList = { 0 };
LIST_ENTRY Global::InstructionPoolsList = { 0 };

LONG Global::g_ProtectPoolLock = { 0 };
LONG Global::g_AllocatedPoolsLock = { 0 };
LONG Global::g_HookPagesListLock = { 0 };
LONG Global::g_InstructionPoolsListLock = { 0 };

ULONG_PTR Global::g_CPUIDRip = 0;
UCHAR Global::g_HackCard[0x256] = { 0 };