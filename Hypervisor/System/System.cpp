#include "System.hpp"
#include "../Common/Common.hpp"
#include "../hde/hde64.h"


IopLoadDriver GetPnpDiagnosticTraceObject()
{
	IopLoadDriver ReturnObject = IopLoadDriver{};
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber == 10586)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x49\x8B\xD6\x48\x8B\xCE\xFF\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x44\x8B\xC7\x48";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 14393)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x49\x8B\xD6\x48\x8B\xCE\xFF\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x44\x8B\xC7\x48";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 15063)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xCC\xCC\x49\x8B\xD6\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 16299)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xCC\xCC\x49\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 17134)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xCC\xCC\x49\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 17763)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xCC\xCC\x49\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xCC\xCC\x49\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x78\xCC\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x48\x8B\xCE\xE8\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 19041 || Version.dwBuildNumber == 19042 || Version.dwBuildNumber == 19043 || Version.dwBuildNumber == 19044)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x49\x8B\xCF\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x49\x8B\xCF\xE8\xCC\xCC\xCC\xCC\x44\x8B\xF0\x85\xC0\x78\xCC\x49\x8B\xCF\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x49";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 22000)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x49\x8B\xCF\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x49\x8B\xCF\xE8\xCC\xCC\xCC\xCC\x44\x8B\xF0\x85\xC0\x78\xCC\x49\x8B\xCF\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x49";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	if (Version.dwBuildNumber == 22454)
	{
		UCHAR PnpDiagnosticTraceObjectSign[] = "\xE8\xCC\xCC\xCC\xCC\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x8B\xF0\x85\xC0\x78\xCC\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4C\x8D\xCC\xCC\xCC\x49\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PnpDiagnosticTraceObjectSign, 0xCC, sizeof(PnpDiagnosticTraceObjectSign) - 1, (PVOID*)&Result)))
			return ReturnObject;
		ReturnObject.ReturnAddress = reinterpret_cast<ULONG_PTR>(Result + 5);
		Result = Result + 1;
		Result = Result + *(PLONG)(Result)+0x4;
		ReturnObject.HookAddress = (ULONG_PTR)Result;
	}
	return ReturnObject;
}

PUCHAR GetPspGetContext()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber == 7600 || Version.dwBuildNumber == 7601)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x48\x8B\xD6\x48\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x83\x63\xCC\xCC\x44\x84\xCC\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x49\xCC\xCC\xCC\x41\x8A\xC5\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 9200)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x48\x8B\xD6\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x83\x63\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xBE\xCC\xCC\xCC\xCC\x40\x84\xCC\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x49\xCC\xCC\xCC\x41\x8A\xC7\x48\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 9600)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x48\x8B\xD6\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x83\x63\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xBE\xCC\xCC\xCC\xCC\x40\x84\xCC\xCC\x74\xCC\x48\x8D\xCC\xCC\x49\x89\x00\x41\x8A\xC7\x48\x8B\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 10240)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x48\x8B\xD3\x49\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x89\x77\xCC\x0F\xB6\xCC\xCC\xA8\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x49\x89\x34\x24\x41\x0F\xB6\xC7\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 10586)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x48\x8B\xD7\x49\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x44\x89\xCC\xCC\x0F\xB6\xCC\xCC\xA8\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x4D\x89\x34\x24\x41\x0F\xB6\xC7\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 14393)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x48\x8B\xD7\x49\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x44\x89\xCC\xCC\x0F\xB6\xCC\xCC\xA8\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x4D\x89\x27\x0F\xB6\xC3\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 15063)
	{
		UCHAR PspGetContextSign[] = "\x4D\x8B\xCC\xCC\x49\x8B\xD6\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x45\x89\xCC\xCC\x41\x0F\xCC\xCC\xCC\xA8\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x4C\x89\x27\x0F\xB6\xC3\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 16299)
	{
		UCHAR PspGetContextSign[] = "\x4D\x8B\xCC\xCC\x49\x8B\xD6\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x45\x89\xCC\xCC\x44\x0F\xCC\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\x41\x0F\xCC\xCC\xCC\xA8\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x4D\x89\x20\x41\x0F";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 17134)
	{
		UCHAR PspGetContextSign[] = "\x4D\x8B\xCC\xCC\x48\x8B\xD6\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x32\xDB\x45\x89\xCC\xCC\x48\x8B\xCC\xCC\xCC\x49\x8B\xD7\x41\xF6\xCC\xCC\xCC\x48\x8D\xCC\xCC\x49\x0F\x44\xCC\x48\x89\x08\x0F\xB6\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 17763)
	{
		UCHAR PspGetContextSign[] = "\x4D\x8B\xCC\xCC\x48\x8B\xD6\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x32\xDB\x45\x89\xCC\xCC\x48\x8B\xCC\xCC\xCC\x49\x8B\xD7\x41\xF6\xCC\xCC\xCC\x48\x8D\xCC\xCC\x49\x0F\x44\xCC\x48\x89\x08\x0F\xB6\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363)
	{
		UCHAR PspGetContextSign[] = "\x4D\x8B\xCC\xCC\x49\x8B\xD6\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x45\x89\xCC\xCC\x44\x0F\xCC\xCC\xCC\xCC\x41\x0F\xCC\xCC\xCC\xA8\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x4C\x89\x23\x41\x0F\xB6\xC1\x48\x8B\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 19041 || Version.dwBuildNumber == 19042 || Version.dwBuildNumber == 19043 || Version.dwBuildNumber == 19044)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xCC\xCC\x49\x8B\xD7\x49\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x89\x73\xCC\xE9\xCC\xCC\xCC\xCC\x40\xCC\xCC\xCC\xCC\xCC\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x40\xCC\xCC\xCC\xCC\xCC\xCC\x0F\xCC\xCC\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	if (Version.dwBuildNumber == 22000 || Version.dwBuildNumber == 22454)
	{
		UCHAR PspGetContextSign[] = "\x4C\x8B\xC3\x49\x8B\xD6\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x41\xF6\xCC\xCC\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xCC\xCC\xCC\xCC\xCC\x8B\x53\xCC\x48\x8B\xCB\xE8\xCC\xCC\xCC\xCC\x90\xE9\xCC\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspGetContextSign, 0xCC, sizeof(PspGetContextSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 10;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	return Result;
}

PUCHAR GetPspExitProcess()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber == 7600 || Version.dwBuildNumber == 7601)
	{
		UCHAR PspExitProcessSign[] = "\x49\x8B\xCC\x41\x8A\xCC\xE8\xCC\xCC\xCC\xCC\x49\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspExitProcessSign, 0xCC, sizeof(PspExitProcessSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 7;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 9200 || Version.dwBuildNumber == 10240 || Version.dwBuildNumber == 10586 || Version.dwBuildNumber == 14393 || Version.dwBuildNumber == 15063)
	{
		UCHAR PspExitProcessSign[] = "\x49\x8B\xCC\xB1\xCC\xE8\xCC\xCC\xCC\xCC\x49\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspExitProcessSign, 0xCC, sizeof(PspExitProcessSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 6;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 9600 || Version.dwBuildNumber == 16299 || Version.dwBuildNumber == 17134 || Version.dwBuildNumber == 17763 || Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363 || Version.dwBuildNumber == 19041 || Version.dwBuildNumber == 19042 || Version.dwBuildNumber == 19043 || Version.dwBuildNumber == 19044)
	{
		UCHAR PspExitProcessSign[] = "\x49\x8B\xCC\x41\x8A\xCC\xE8\xCC\xCC\xCC\xCC\x49\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspExitProcessSign, 0xCC, sizeof(PspExitProcessSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 7;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 22000 || Version.dwBuildNumber == 22454)
	{
		UCHAR PspExitProcessSign[] = "\x49\x8B\xD6\x41\x8A\xCF\xE8\xCC\xCC\xCC\xCC\xBA\xCC\xCC\xCC\xCC\x49\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, PspExitProcessSign, 0xCC, sizeof(PspExitProcessSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 7;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	return Result;
}

PUCHAR GetMmQueryVirtualMemory()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber == 9200) {
		UCHAR MmQueryVirtualMemorySign[] = "\xFF\xF3\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xF9\x4C\x89\xCC\xCC\xCC\xCC\xCC\xCC\x45\x8B\xF0\x44\x89\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 9600) {
		UCHAR MmQueryVirtualMemorySign[] = "\x48\x89\xCC\xCC\xCC\x56\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x49\x8B\xF1\x45\x8B\xC8\x44\x89\xCC\xCC\xCC\x4C\x8B\xE2\x48\x89\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 10240) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xE9\x4D\x63\xF8\x48\x89\xCC\xCC\xCC\x48\x8B\xF9\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x45\x33";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 10586) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xE9\x4D\x63\xF8\x48\x89\xCC\xCC\xCC\x48\x8B\xF9\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x45\x33\xF6";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 14393) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xE1\x4C\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x63\xE8\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x48\x89\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x33\xF6";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 15063) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xE1\x4D\x63\xE8\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x48\x89\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x45\x33\xD2";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 16299) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xF1\x4C\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x63\xE8\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x45\x33\xE4";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 17134) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xF1\x4C\x89\xCC\xCC\xCC\x4D\x63\xE8\x4C\x8B\xE2\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x33\xFF";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 17763) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xF9\x4C\x89\xCC\xCC\xCC\x45\x8B\xE8\x4C\x8B\xF2\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x33\xFF";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363) {
		UCHAR MmQueryVirtualMemorySign[] = "\x40\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xF9\x4C\x89\xCC\xCC\xCC\x45\x8B\xF0\x4C\x8B\xEA\x48\x89\xCC\xCC\xCC\x48\x8B\xD9\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x33\xD2";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 19041 || Version.dwBuildNumber == 19042 || Version.dwBuildNumber == 19043 || Version.dwBuildNumber == 19044) {
		UCHAR MmQueryVirtualMemorySign[] = "\x4C\x8B\xDC\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xE1\x4C\x89\xCC\xCC\xCC\xCC\xCC\xCC\x45\x8B\xF0\x44\x89\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x48\x8B\xF9\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x33\xC9";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 22000) {
		UCHAR MmQueryVirtualMemorySign[] = "\x4C\x8B\xDC\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xE9\x45\x8B\xF0\x48\x89\xCC\xCC\xCC\x48\x8B\xF1\x48\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x33\xC9\x89\x4C\xCC\xCC\x48\x89\xCC\xCC\xCC\x49\x89\xCC\xCC\xCC\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	else if (Version.dwBuildNumber == 22454) {
		UCHAR MmQueryVirtualMemorySign[] = "\x4C\x8B\xDC\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\xCC\xCC\xCC\xCC\xCC\xCC\x4D\x8B\xF1\x49\x63\xF0\x89\x74\xCC\xCC\x48\x89\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x4C\x8B\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x89\xCC\xCC\xCC\x45\x33\xE4\x44\x89\xCC\xCC\xCC\x4C\x89\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmQueryVirtualMemorySign, 0xCC, sizeof(MmQueryVirtualMemorySign) - 1, (PVOID*)&Result)))
			return NULL;
	}
	return Result;
}


PUCHAR GetMmAllocateIndependentPages()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	//DPRINT("dwBuildNumber:%d", Version.dwBuildNumber);
	if (Version.dwBuildNumber == 7600 || Version.dwBuildNumber == 7601)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\xB9\xCC\xCC\xCC\xCC\x0F\xB7\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\xE8\x48\x85\xC0";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 10;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 9200 || Version.dwBuildNumber == 9600 || Version.dwBuildNumber == 10240)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x48\x8D\x0C\x80\x48\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\xCC\x48\xCC\xCC\xCC\xCC";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 10586)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 14393)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 15063)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 16299)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 17134)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 17763)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x19\x48\x8B\xF9\x48\x85\xDB\x75\x3C\x0F\xB7\xD2\xB9\x00\x70\x00\x00\xE8";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 30;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x19\x48\x8B\xF9\x48\x85\xDB\x75\x39\xB9\x00\x70\x00\x00\xE8";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 27;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber > 18363 && Version.dwBuildNumber < 22000)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 22000 || Version.dwBuildNumber > 22454)
	{
		UCHAR MmAllocateIndependentPagesSign[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x74\x2C\xBE\x0C\x00\x00\x00";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign, 0xCC, sizeof(MmAllocateIndependentPagesSign) - 1, (PVOID*)&Result)))
		{
			UCHAR MmAllocateIndependentPagesSign2[] = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x0F\x84";
			Result = 0;
			if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmAllocateIndependentPagesSign2, 0xCC, sizeof(MmAllocateIndependentPagesSign2) - 1, (PVOID*)&Result)))
			{
				return NULL;
			}
		}

		Result = Result + 9;
		Result = Result + *(PLONG)(Result)+0x4;

	}
	return Result;
}

PUCHAR GetMmFreeIndependentPages()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber == 7600 || Version.dwBuildNumber == 7601 || Version.dwBuildNumber == 9200 || Version.dwBuildNumber == 9600 || Version.dwBuildNumber == 10240)
	{
		UCHAR MmFreeIndependentPagesSign[] = "\x4B\xCC\xCC\xCC\xCC\x0F\xB6\xC0\x44\xCC\xCC\xCC\xE9";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmFreeIndependentPagesSign, 0xCC, sizeof(MmFreeIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 13;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 10586 || Version.dwBuildNumber == 14393 || Version.dwBuildNumber == 15063 || Version.dwBuildNumber == 16299)
	{
		UCHAR MmFreeIndependentPagesSign[] = "\x8B\xD7\x49\x8B\xCC\xE8\xCC\xCC\xCC\xCC\x4D\x85\xCC\x74\x0A\x33\xD2\x49\x8B\xCC\xE8\xCC\xCC\xCC\xCC\x4D\x85\xCC\x74\x0A\x33\xD2\x49\x8B\xCC\xE8";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmFreeIndependentPagesSign, 0xCC, sizeof(MmFreeIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 6;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 17134 || Version.dwBuildNumber == 17763)
	{
		UCHAR MmFreeIndependentPagesSign[] = "\x8B\xD7\x49\x8B\xCC\xE8\xCC\xCC\xCC\xCC\x4D\x85\xCC\x74\x0A\x33\xD2\x49\x8B\xCC\xE8\xCC\xCC\xCC\xCC\x4D\x85\xCC\x74\x0A\x33\xD2\x49\x8B\xCC\xE8";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmFreeIndependentPagesSign, 0xCC, sizeof(MmFreeIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 6;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363)
	{
		UCHAR MmFreeIndependentPagesSign[] = "\x41\x8B\xD6\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x4D\x85\xED\x74\x0A\x33\xD2\x49\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x4D\x85\xE4\x74\x0A\x33\xD2\x49\x8B\xCC\xE8";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmFreeIndependentPagesSign, 0xCC, sizeof(MmFreeIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 7;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 19041 || Version.dwBuildNumber == 19042 || Version.dwBuildNumber == 19043 || Version.dwBuildNumber == 19044)
	{
		UCHAR MmFreeIndependentPagesSign[] = "\x41\x8B\xD5\x49\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x48\x8B\xCC\xCC\x48\x85\xC0\x74\x0A\x33\xD2\x48\x8B\xC8\xE8\xCC\xCC\xCC\xCC\x4D\x85\xFF\x74\x0A\x33\xD2";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmFreeIndependentPagesSign, 0xCC, sizeof(MmFreeIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 7;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	else if (Version.dwBuildNumber == 22000 || Version.dwBuildNumber >= 22454)
	{
		UCHAR MmFreeIndependentPagesSign[] = "\x40\x53\x48\xCC\xCC\xCC\x48\x8D\xCC\xCC\xCC\xCC\xCC\xBA\xCC\xCC\xCC\xCC\x48\x8B\xCB\xE8\xCC\xCC\xCC\xCC\x48\x8D\xCC\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD0\x48\xCC\xCC\xCC\xCC\xCC\xCC\x41\xCC\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\xCC\xCC\xCC\x5B\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, MmFreeIndependentPagesSign, 0xCC, sizeof(MmFreeIndependentPagesSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 22;
		Result = Result + *(PLONG)(Result)+0x4;
	}
	return Result;
}
PUCHAR GetRtlWalkFrameChain()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	RTL_OSVERSIONINFOW Version = { 0 };
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber == 7600 || Version.dwBuildNumber == 7601)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\xFF\xC8\xEB\xCC\x33\xC0\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x5F\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 15;
	}
	if (Version.dwBuildNumber == 9200)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\xFF\xC8\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x5F\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 9600)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5F\x41\x5E\x5F\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 10240)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\x5F\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 10586)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\x5F\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 14393)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\x5F\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 15063)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 16299)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC6\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 17134)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC6\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 17763)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC6\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 18362 || Version.dwBuildNumber == 18363)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC6\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5E\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 19041 || Version.dwBuildNumber == 19042 || Version.dwBuildNumber == 19043 || Version.dwBuildNumber == 19044)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5F\x41\x5E\x5F\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	if (Version.dwBuildNumber == 22000 || Version.dwBuildNumber == 22454)
	{
		UCHAR RtlWalkFrameChainSign[] = "\xE8\xCC\xCC\xCC\xCC\x85\xC0\x74\xCC\x2B\xC5\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\x8B\xCC\xCC\xCC\x48\xCC\xCC\xCC\x41\x5F\x41\x5E\x5F\xC3";
		if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, RtlWalkFrameChainSign, 0xCC, sizeof(RtlWalkFrameChainSign) - 1, (PVOID*)&Result)))
			return NULL;
		Result = Result + 11;
	}
	return Result;
}

PUCHAR GetInstrumentationCallback()
{
	PVOID ntoskrnl = Common::GetKernelBase("ntoskrnl.exe");
	PUCHAR Result = NULL;
	UCHAR InstrumentationCallbackSign[] = "\x4C\x8B\x95\xE8\x00\x00\x00\x48\x89\x85\xE8\x00\x00\x00";
	if (!NT_SUCCESS(Common::BBScanSection(ntoskrnl, InstrumentationCallbackSign, 0xCC, sizeof(InstrumentationCallbackSign) - 1, (PVOID*)&Result)))
		return NULL;
	return Result;
}
