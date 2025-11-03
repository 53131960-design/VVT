#include "Global/Global.hpp"
#include "Intel/VMX.hpp"
#include "Common/Common.hpp"
#include "System/System.hpp"
#include "Intel/Hook.hpp"
#include "AntiCheat/AntiCheat.hpp"
#include <intrin.h>

KDDEBUGGER_DATA64 KdDebuggerDataBlock;


//void DriverUnload(PDRIVER_OBJECT)
//{
//	IntelVMX::UninstallVmx();
//}
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING  RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	//DriverObject->DriverUnload = DriverUnload;

	if (true)
	{
		RTL_OSVERSIONINFOEXW verInfo = { 0 };
		verInfo.dwOSVersionInfoSize = sizeof(verInfo);
		RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

		Global::g_pSysRotineAddr.buildNo = verInfo.dwBuildNumber;
	
		if (Global::g_pSysRotineAddr.buildNo >= 14393)
		{
			CONTEXT context = { 0 };
			context.ContextFlags = CONTEXT_FULL;
			RtlCaptureContext(&context);

			PDUMP_HEADER dumpHeader = (PDUMP_HEADER)ExAllocatePool(NonPagedPool, DUMP_BLOCK_SIZE);

			if (!dumpHeader)
				return STATUS_UNSUCCESSFUL;

			KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);

			RtlCopyMemory(&KdDebuggerDataBlock, (PUCHAR)dumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(KdDebuggerDataBlock));

			ExFreePoolWithTag(dumpHeader, 0);

			Global::g_pSysRotineAddr.DYN_PTE_BASE = (ULONG_PTR)KdDebuggerDataBlock.PteBase;
			Global::g_pSysRotineAddr.DYN_PDE_BASE = Global::g_pSysRotineAddr.DYN_PTE_BASE | (((Global::g_pSysRotineAddr.DYN_PTE_BASE >> 39ull) & 0x1FFull) << 30ull);
			Global::g_pSysRotineAddr.DYN_PPE_BASE = Global::g_pSysRotineAddr.DYN_PDE_BASE | (((Global::g_pSysRotineAddr.DYN_PTE_BASE >> 39ull) & 0x1FFull) << 21ull);
			Global::g_pSysRotineAddr.DYN_PXE_BASE = Global::g_pSysRotineAddr.DYN_PPE_BASE | (((Global::g_pSysRotineAddr.DYN_PTE_BASE >> 39ull) & 0x1FFull) << 12ull);
		}
		
		switch (Global::g_pSysRotineAddr.buildNo)
		{
		case 15063:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x2E0;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x2E8;
			break;
		case 16299:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x2E0;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x2E8;
			break;
		case 17134:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x278;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x2E0;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x2E8;
			break;
		case 17763:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x278;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x2E0;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x2E8;
			break;
		case 18362:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x280;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x2E8;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x2F0;
			break;
		case 18363:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x280;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x2E8;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x2F0;
			break;
		case 19041:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x388;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x440;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x448;
			break;
		case 19042:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x388;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x440;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x448;
			break;
		case 19043:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x388;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x440;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x448;
			break;
		case 19044:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x388;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x440;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x448;
			break;
		case 22000:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x388;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x440;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x448;
			break;
		case 22454:
			Global::g_pSysRotineAddr.PrevMode = 0x232;
			Global::g_pSysRotineAddr.CR3Offset = 0x388;
			Global::g_pSysRotineAddr.PmiscFlag = 0x74;
			Global::g_pSysRotineAddr.UniqueProcessId = 0x440;
			Global::g_pSysRotineAddr.ActiveProcessLinks = 0x448;
			break;
		}

		if (Global::g_pSysRotineAddr.buildNo >= 10240)
		{
			KAPC_STATE ApcState;
			PEPROCESS Process = NULL;

			HANDLE ProcessId = Common::GetProcessIdByNameW(L"explorer.exe");
			NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
			if (NT_SUCCESS(status))
			{
				KeStackAttachProcess(Process, &ApcState);
				typedef void* RtlFindExportedRoutineByNameDef(void*, const char*);
				RtlFindExportedRoutineByNameDef* RtlFindExportedRoutineByNameFn = (RtlFindExportedRoutineByNameDef*)(Common::GetSystemRoutineAddress(L"RtlFindExportedRoutineByName"));
				Global::g_pSysRotineAddr.pfn_ValidateHwnd = (fn_ValidateHwnd)RtlFindExportedRoutineByNameFn(Common::GetKernelBase("win32kbase.sys"), "ValidateHwnd");
				KeUnstackDetachProcess(&ApcState);
				ObfDereferenceObject(Process);
			}
		}

		PEPROCESS Process = NULL;
		HANDLE ProcessId = Common::GetProcessIdByNameW(L"csrss.exe");
		NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
		if (NT_SUCCESS(status))
		{
			Global::g_pSysRotineAddr.CsrssCR3 = __readcr3();// Common::GetProcessCr32(Process);//
			ObfDereferenceObject(Process);
		}

		Global::g_pSysRotineAddr.pfn_MmCopyVirtualMemory = (fn_MmCopyVirtualMemory)Common::GetSystemRoutineAddress(L"MmCopyVirtualMemory");

		Global::g_pSysRotineAddr.pfn_MmFreeIndependentPages = (fn_MmFreeIndependentPages)GetMmFreeIndependentPages();

		Global::g_pSysRotineAddr.pfn_MmAllocateIndependentPages = (fn_MmAllocateIndependentPages)GetMmAllocateIndependentPages();

	/*	Global::g_pSysRotineAddr.PnpDiagnosticTraceObject = GetPnpDiagnosticTraceObject();

		Global::g_pSysRotineAddr.PspGetContext = (ULONG_PTR)GetPspGetContext();

		Global::g_pSysRotineAddr.MmCopyMemory = (ULONG_PTR)Common::GetSystemRoutineAddress(L"MmCopyMemory");

		Global::g_pSysRotineAddr.PspExitProcess = (ULONG_PTR)GetPspExitProcess();

		Global::g_pSysRotineAddr.MmQueryVirtualMemory = (ULONG_PTR)GetMmQueryVirtualMemory();

		Global::g_pSysRotineAddr.RtlWalkFrameChain = (ULONG_PTR)GetRtlWalkFrameChain();

		Global::g_pSysRotineAddr.InstrumentationCallback = (ULONG_PTR)GetInstrumentationCallback();*/

		InitializeListHead(&Global::AllocatedPoolsList);
		InitializeListHead(&Global::HookedUserPagesList);
		InitializeListHead(&Global::HookedKernelPagesList);
		InitializeListHead(&Global::ProtectPoolsList);
		InitializeListHead(&Global::InstructionPoolsList);

		if (!IntelVMX::InstallVmx())
			return STATUS_UNSUCCESSFUL;
		//MonitoringStart(DriverObject->DriverStart, DriverObject->DriverSize);
	}
	return STATUS_SUCCESS;
}