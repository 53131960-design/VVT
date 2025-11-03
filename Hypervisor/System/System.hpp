#pragma once
#include "../Global/SysDefine.hpp"

IopLoadDriver GetPnpDiagnosticTraceObject();
PUCHAR GetPspGetContext();
PUCHAR GetMmAllocateIndependentPages();
PUCHAR GetMmFreeIndependentPages();
PUCHAR GetPspExitProcess();
PUCHAR GetMmQueryVirtualMemory();
PUCHAR GetRtlWalkFrameChain();
PUCHAR GetInstrumentationCallback();