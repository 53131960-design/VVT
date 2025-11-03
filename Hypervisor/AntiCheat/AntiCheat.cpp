#include <intrin.h>
#include "AntiCheat.hpp"
#include "../Intel/Hook.hpp"
#include "../Common/Common.hpp"
#include "../Global/Global.hpp"
#include "../Intel/Memory.hpp"
#include "../hde/hde64.h"

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
typedef NTSTATUS(__fastcall* fn_PnpDiagnosticTraceObject)(PCEVENT_DESCRIPTOR EventDescriptor, unsigned __int16* a2);
typedef ULONG(NTAPI* fn_RtlWalkFrameChain)(PVOID* Callers, ULONG Count, ULONG Flags);
typedef NTSTATUS(NTAPI* fn_MmQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength, SIZE_T p);
typedef unsigned int(NTAPI* fn_PspGetContext)(__int64 a1, __int64 a2, __int64 a3);
typedef NTSTATUS(NTAPI* fn_MmCopyMemory)(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);
typedef void(NTAPI* fn_PspExitProcess)(IN BOOLEAN LastThreadExit, IN PEPROCESS Process);
typedef __int64(__fastcall* fn_NtAlpcCreateResourceReserve)(HANDLE Handle, int a2, __int64 a3, ULONG* a4);
typedef ULONG_PTR(__stdcall* fn_InstructionTimeCheck)(ULONG_PTR a1);
typedef NTSTATUS(__stdcall* fn_NtSetInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSTATUS(*FNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef PHYSICAL_ADDRESS(__fastcall* fn_MmGetPhysicalAddress)(PVOID BaseAddress);
typedef PMDL(__fastcall* fn_IoAllocateMdl)(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
typedef PVOID(__fastcall* fn_MmGetVirtualForPhysical)(PHYSICAL_ADDRESS PhysicalAddress);
typedef char(__fastcall* fn_MmIsAddressValid)(ULONG64 VirtualAddress);
typedef PMDL(__fastcall* fn_MmCreateMdl)(PMDL MemoryDescriptorList, PVOID Base, SIZE_T Length);
fn_MmCreateMdl					  pfn_MmCreateMdl = nullptr;
fn_MmIsAddressValid				  pfn_MmIsAddressValid = nullptr;
fn_MmGetVirtualForPhysical		  pfn_MmGetVirtualForPhysical = nullptr;
fn_IoAllocateMdl				  pfn_IoAllocateMdl = nullptr;
fn_MmGetPhysicalAddress			  pfn_MmGetPhysicalAddress = nullptr;
FNtCreateFile					  g_NtCreateFile = nullptr;
fn_PnpDiagnosticTraceObject		  pfn_PnpDiagnosticTraceObject = nullptr;
fn_RtlWalkFrameChain			  pfn_RtlWalkFrameChain = nullptr;
fn_MmQueryVirtualMemory			  pfn_MmQueryVirtualMemory = nullptr;
fn_PspGetContext				  pfn_PspGetContext = nullptr;
fn_MmCopyMemory					  pfn_MmCopyMemory = nullptr;
fn_MmCopyVirtualMemory			  pfn_MmCopyVirtualMemory = nullptr;
fn_PspExitProcess				  pfn_PspExitProcess = nullptr;
fn_NtAlpcCreateResourceReserve    pfn_NtAlpcCreateResourceReserve = nullptr;
fn_InstructionTimeCheck			  pfn_InstructionTimeCheck = nullptr;
fn_NtSetInformationProcess		  pfn_NtSetInformationProcess = nullptr;
HANDLE                            g_ProcessId = 0;
ULONG_PTR                         g_Rip = 0;
MODULE_INFO                       g_Driver = { 0 };
wchar_t* initname;
ULONG64 BlankAddress = 0;
PHYSICAL_ADDRESS QuadPart;
extern "C" void __redirect_22xxx();
extern "C" void __redirect_1904x();
extern "C" void __redirect_1836x();
extern "C" void __redirect_17763();
extern "C" void __redirect_17134();
extern "C" void __redirect_16299();
extern "C" void __redirect_15063();


extern "C" void __InstrumentationCallback();

extern "C" uint64_t KMPnPEvt_DriverInit_Start = 0;
extern "C" uint64_t EtwEventEnabledBackAddress = 0;


ULONG GetRealRandNumBetween(int min, int max)
{
	UINT64 rand_val;
	_rdrand64_step(&rand_val);
	return (rand_val % (max - min + 1LL)) + min;
}

void PushProtectPool(PVOID Address, size_t Size)
{
	PPOOL_TABLE SinglePool = (PPOOL_TABLE)ExAllocatePool(NonPagedPool, sizeof(POOL_TABLE));

	if (!SinglePool)
		return;

	RtlZeroMemory(SinglePool, sizeof(POOL_TABLE));

	SinglePool->Address = Address;
	SinglePool->MaxAddress = (PUCHAR)Address + Size;
	SinglePool->Size = Size;
	Common::SpinlockLock(&Global::g_ProtectPoolLock);
	InsertTailList(&Global::ProtectPoolsList, &SinglePool->PoolsList);
	Common::SpinlockUnlock(&Global::g_ProtectPoolLock);
}

void CleanProtectRegion()
{
	g_Rip = 0; g_ProcessId = 0;
	Common::SpinlockLock(&Global::g_ProtectPoolLock);
	while (!IsListEmpty(&Global::ProtectPoolsList))
	{
		PPOOL_TABLE PoolTable = CONTAINING_RECORD(Global::ProtectPoolsList.Flink, POOL_TABLE, PoolsList);
		if (PoolTable)
		{
			RemoveEntryList(&PoolTable->PoolsList);
			ExFreePoolWithTag(PoolTable, 0);
		}
	}
	Common::SpinlockUnlock(&Global::g_ProtectPoolLock);
}

bool InProtectRegion(PVOID Address, SIZE_T NumberOfBytes)
{
	for (PLIST_ENTRY pListEntry = Global::ProtectPoolsList.Flink; pListEntry != &Global::ProtectPoolsList; pListEntry = pListEntry->Flink)
	{
		PPOOL_TABLE PoolTable = CONTAINING_RECORD(pListEntry, POOL_TABLE, PoolsList);
		if (PoolTable) {
			if (Address >= PoolTable->Address && (PVOID)(Address <= (PUCHAR)PoolTable->MaxAddress + NumberOfBytes))
				return true;
		}
	}
	return false;
}

bool InInstructionRegion(PVOID Address, SIZE_T NumberOfBytes)
{
	for (PLIST_ENTRY pListEntry = Global::InstructionPoolsList.Flink; pListEntry != &Global::InstructionPoolsList; pListEntry = pListEntry->Flink)
	{
		PPOOL_TABLE PoolTable = CONTAINING_RECORD(pListEntry, POOL_TABLE, PoolsList);
		if (PoolTable) {
			if (Address >= PoolTable->Address && (PVOID)(Address <= (PUCHAR)PoolTable->MaxAddress + NumberOfBytes))
				return true;
		}
	}
	return false;
}

bool CanMapRegion(PUCHAR CheckBase, SIZE_T CheckBytes, PVOID TargetAddress, SIZE_T NumberOfBytes)
{
	PUCHAR Start = 0;
	Start = (PUCHAR)TargetAddress;
	return (Start >= CheckBase) && (Start <= CheckBase + CheckBytes + NumberOfBytes);
}

bool ProcessHasProtectedRegions(HANDLE ProcessHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (ProcessHandle == NtCurrentProcess())
		return PsGetCurrentProcessId() == g_ProcessId;
	else
	{
		PROCESS_BASIC_INFORMATION pbi{};
		status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(status))
			return false;
		return g_ProcessId == (HANDLE)pbi.UniqueProcessId;
	}
}

ULONG_PTR __stdcall _InstructionTimeCheck(ULONG_PTR a1)
{
	ULONG_PTR Result = pfn_InstructionTimeCheck(a1);

	ULONG_PTR Func = *(ULONG_PTR*)(a1 + 0x18);
	if (Result == 0x64)
	{
		if (*(ULONG*)Func == 0xF03A010F)
		{
			*(ULONG*)(a1 + 0xC) = 0;
			*(UINT64*)(a1 + 0x10) = 0;
		}
		else if (*(ULONG*)Func == 0x8B485753)
		{
			*(ULONG*)(a1 + 0xC) = 0;
			*(UINT64*)(a1 + 0x10) = GetRealRandNumBetween(0, 20);
		}
	}
	return Result;
}

NTSTATUS __stdcall _NtSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	UNREFERENCED_PARAMETER(ProcessHandle);
	UNREFERENCED_PARAMETER(ProcessInformationLength);

	return STATUS_SUCCESS;
}

ULONG_PTR _TimeCheck()
{
	return 0;
}
ULONG_PTR _TimeCheck2()
{
	return 1;
}
ULONG_PTR _TimeCheck3()
{
	return 0xC000000D;
}
ULONG_PTR _TimeCheck4()
{
	return 0x16;
}
void EasyAntiCheat(MODULE_INFO Info)
{
	PUCHAR Result = NULL;
	EPTCleanInvalidHook(NULL, TRUE);

	UCHAR InstructionTimeChecksgdt[] = "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\xBF\x01";
	if (!NT_SUCCESS(Common::BBSearchPattern(InstructionTimeChecksgdt, 0xCC, sizeof(InstructionTimeChecksgdt) - 1, Info.Base, Info.Size, &Result)))
		return;

	EPTHookPerformPageHook(Result, _InstructionTimeCheck, (PVOID*)&pfn_InstructionTimeCheck, true);

	UCHAR RdtscTimeChecksgdt[] = "\x48\x0B\xC2\x4C\x8B\xC0\x33\xC9\xB8\x01\x00\x00\x00";
	if (!NT_SUCCESS(Common::BBSearchPattern(RdtscTimeChecksgdt, 0xCC, sizeof(RdtscTimeChecksgdt) - 1, Info.Base, Info.Size, &Result)))
		return;

	Global::g_CPUIDRip = (ULONG64)Result;

	UCHAR NtSetInformationProcesssgdt[] = "\x48\x89\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x48\x89\xCC\xCC\xCC\x57\x41\x56\x41\x57\x48\xCC\xCC\xCC\x65\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x41\x8B\xE9\x4D\x8B\xF0\x44\x8B\xFA";

	if (!NT_SUCCESS(Common::BBSearchPattern(NtSetInformationProcesssgdt, 0xCC, sizeof(NtSetInformationProcesssgdt) - 1, Info.Base, Info.Size, &Result)))
		return;

	EPTHookPerformPageHook(Result, _NtSetInformationProcess, (PVOID*)&pfn_NtSetInformationProcess, true);
}

void BattlEye(MODULE_INFO Info)
{
	PUCHAR Result = NULL;
	EPTCleanInvalidHook(NULL, TRUE);

	UCHAR CpuidSign[] = "\x40\x53\x48\x83\xEC\x10\x49\xBA\x14\x00\x00\x00\x80\xF7\xFF\xFF\x41\xB9\x90\x65\x00\x00\x4D\x8B\x02";
	UCHAR RdmsrSign[] = "\x49\xBA\x14\x00\x00\x00\x80\xF7\xFF\xFF\x41\xB9\x90\x65\x00\x00\x4D\x8B\x02\xB9\x80\x00\x00\xC0\x0F\x32";
	UCHAR XgetbvSign[] = "\x48\x83\xEC\x18\x49\xBA\x14\x00\x00\x00\x80\xF7\xFF\xFF\x4D\x8B\x02\x45\x33\xC9";
	if (NT_SUCCESS(Common::BBSearchPattern(CpuidSign, 0xCC, sizeof(CpuidSign) - 1, Info.Base, Info.Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	if (NT_SUCCESS(Common::BBSearchPattern(RdmsrSign, 0xCC, sizeof(RdmsrSign) - 1, Info.Base, Info.Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	if (NT_SUCCESS(Common::BBSearchPattern(XgetbvSign, 0xCC, sizeof(XgetbvSign) - 1, Info.Base, Info.Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
}
void AceGame(MODULE_INFO Info)
{
	PUCHAR Result = NULL;
	EPTCleanInvalidHook(NULL, TRUE);

	UCHAR Sign[] = "\x40\x53\x48\x83\xEC\x10\x33\xC0\x33\xC9\x0F\xA2";
	UCHAR Sign2[] = "\xC7\x84\x24\xA8\x00\x00\x00\x01\x00\x00\xC0\xE8\xCC\xCC\xCC\xCC\x85\xC0";
	UCHAR Sign3[] = "\xE8\xCC\xCC\xCC\xCC\x88\x84\x24\xA3\x00\x00\x00\x0F\xB6\x84\x24\xA3\x00\x00\x00";
	UCHAR Sign4[] = "\x48\x83\xEC\x28\xE8\xCC\xCC\xCC\xCC\x84\xC0\x74\x0C\x0F\x20\xE0";
	if (NT_SUCCESS(Common::BBSearchPattern(Sign, 0xCC, sizeof(Sign) - 1, Info.Base, Info.Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	/*if (NT_SUCCESS(Common::BBSearchPattern(Sign, 0xCC, sizeof(Sign) - 1, (Result + 0x5), Info.Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);*/
	if (NT_SUCCESS(Common::BBSearchPattern(Sign2, 0xCC, sizeof(Sign2) - 1, Info.Base, Info.Size, &Result)))
	{
		Result = Result + 0xB;
		Result = (PUCHAR)RVA(Result, 5);
		Result = (PUCHAR)RVA(Result, 5);
		EPTHookPerformPageHook(Result, _TimeCheck2, NULL, true);
	}
	if (NT_SUCCESS(Common::BBSearchPattern(Sign3, 0xCC, sizeof(Sign3) - 1, Info.Base, Info.Size, &Result)))
	{ 
		Result = (PUCHAR)RVA(Result, 5);
		Result = (PUCHAR)RVA(Result, 5);
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	}
	if (NT_SUCCESS(Common::BBSearchPattern(Sign4, 0xCC, sizeof(Sign4) - 1, Info.Base, Info.Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
}
typedef unsigned char       BYTE;
void AceBase(MODULE_INFO Info)
{
	PUCHAR Result = NULL;
	EPTCleanInvalidHook(NULL, TRUE);
	PVOID Start, End;
	ULONG Size;
	UCHAR Sign[] = "\xF3\xAA\x33\xC0\x33\xC9\x0F\xA2";
	UCHAR Sign2[] = "\xC7\x04\x24\x0D\x00\x00\xC0\xEB\x24\x8B\x4C\x24\x20\x0F\x32";
	UCHAR Sign3[] = "\xC7\x04\x24\x16\x00\x00\x00\xEB\x30\x8B\x4C\x24\x20\x0F\x32";
	UCHAR Sign4[] = "\x40\x53\x48\x83\xEC\x10\x33\xC9\xB8\x07\x00\x00\x00\x0F\xA2";
	if (NT_SUCCESS(Common::BBSearchPattern(Sign, 0xCC, sizeof(Sign) - 1, Info.Base, Info.Size, &Result)))
	{ 
		Result = Result - 0x21;
		EPTHookPerformPageHook(Result, _TimeCheck2, NULL, true);
	}
	if (NT_SUCCESS(Common::BBSearchPattern(Sign2, 0xCC, sizeof(Sign2) - 1, Info.Base, Info.Size, &Result)))
	{
		Result = Result - 0x1C;
		EPTHookPerformPageHook(Result, _TimeCheck3, NULL, true);
	}
	if (NT_SUCCESS(Common::BBSearchPattern(Sign3, 0xCC, sizeof(Sign3) - 1, Info.Base, Info.Size, &Result)))
	{
		Result = Result - 0x1C;
		EPTHookPerformPageHook(Result, _TimeCheck4, NULL, true);
	}
	if (NT_SUCCESS(Common::BBSearchPattern(Sign4, 0xCC, sizeof(Sign4) - 1, Info.Base, Info.Size, &Result)))
	{
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	}
	if (NT_SUCCESS(Common::BBSearchPattern(Sign4, 0xCC, sizeof(Sign4) - 1, (Result + 5), Info.Size, &Result)))
	{
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	}
	/*Common::RtlFindImageSection((PVOID)Info.Base, ".text", &Start, &End);
	Size = (ULONG64)End - (ULONG64)Start;
	ULONG64 Ptr2 = 0;
	UCHAR A1[] = "\x0F\xA2";
	if (NT_SUCCESS(Common::BBSearchPattern(A1, 0xCC, sizeof(A1) - 1, Start, Size, &Result)))
		EPTHookPerformPageHook(Result, _TimeCheck, NULL, true);
	int i = 0;
	while (true)
	{
		Size = (ULONG64)End - (ULONG64)Result;
		if (NT_SUCCESS(Common::BBSearchPattern(A1, 0xCC, sizeof(A1) - 1, Result, Size, &Result)))
		{
			if (Result)
			{
				ULONG64 Ptr = (ULONG64)Result;
				for (i = 0; i < 0x1000; i++) {
					if (*(BYTE*)(Ptr - i) == 0xCC && *(BYTE*)(Ptr - i - 1) == 0xCC && *(BYTE*)(Ptr - i - 2) == 0xCC)
						break;
				}
				Ptr = (ULONG64)Result - i + 1;
				if (Ptr != Ptr2)
				{
					Ptr2 = Ptr;
					EPTHookPerformPageHook((PVOID)Ptr, _TimeCheck, NULL, true);
				}
				Result = Result + 1;
			}

		}
		else
		{
			break;
		}
	}*/
	


}
NTSTATUS __fastcall _PnpDiagnosticTraceObject(PCEVENT_DESCRIPTOR EventDescriptor, unsigned __int16* a2)
{
	PVOID ReturnAddress = _ReturnAddress();
	if (ReturnAddress == (PVOID)Global::g_pSysRotineAddr.PnpDiagnosticTraceObject.ReturnAddress)
	{

		MODULE_INFO DriverInfo = { 0 };
		if (Common::GetKernelBase2("EasyAntiCheat.sys", &DriverInfo))
			EasyAntiCheat(DriverInfo);
		if (Common::GetKernelBase2("BEDaisy.sys", &DriverInfo))
			BattlEye(DriverInfo);
		if (Common::GetKernelBase2("ACE-GAME.sys", &DriverInfo))
			AceGame(DriverInfo);
		if (Common::GetKernelBase2("ACE-BASE.sys", &DriverInfo))
			AceBase(DriverInfo);
		//Log("A:%p", DriverInfo.Base);
	}
	return pfn_PnpDiagnosticTraceObject(EventDescriptor, a2);
}


extern "C" ULONG NTAPI _RtlWalkFrameChain(PVOID * Callers, ULONG Count, ULONG)
{
	for (size_t i = 0; i < Count; i++)
	{
		PVOID Address = Callers[i];
		if (InProtectRegion(Address, 1) || InInstructionRegion(Address, 1) || CanMapRegion(g_Driver.Base, g_Driver.Size, Address, 1))
		{
			RtlZeroMemory(&Callers[i], (Count - i) * sizeof(PVOID));
			Count = (ULONG)i;
			break;
		}
	}
	return Count;
}


unsigned int NTAPI _PspGetContext(__int64 a1, __int64 a2, __int64 a3)
{
	unsigned int Result = pfn_PspGetContext(a1, a2, a3);
	PCONTEXT context = (PCONTEXT)a3;
	if (InProtectRegion((PVOID)context->Rip, 1))
		context->Rip = g_Rip;
	if (InInstructionRegion((PVOID)context->Rip, 1))
		context->Rip = g_Rip;
	if (CanMapRegion(g_Driver.Base, g_Driver.Size, (PVOID)context->Rip, 1))
		context->Rip = g_Rip;
	return Result;
}

NTSTATUS NTAPI _MmCopyMemory(PVOID  TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG  Flags, PSIZE_T   NumberOfBytesTransferred)
{
	PVOID RetnAddress = _ReturnAddress();

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (TargetAddress && NumberOfBytes)
	{
		BOOLEAN InsideDriver1 = CanMapRegion(g_Driver.Base, g_Driver.Size, RetnAddress, 1);
		BOOLEAN InsideDriver2 = InInstructionRegion(RetnAddress, 1);
		if (Flags == MM_COPY_MEMORY_PHYSICAL && !InsideDriver1 && !InsideDriver2)
		{
			if (InProtectRegion(MmGetVirtualForPhysical(SourceAddress.PhysicalAddress), NumberOfBytes))
			{
				*NumberOfBytesTransferred = 0;
				status = STATUS_PARTIAL_COPY;
			}
		}
		/*else
		{
			if (CanMapRegion(g_Driver.Base, g_Driver.Size, SourceAddress.VirtualAddress, NumberOfBytes))
			{
				*NumberOfBytesTransferred = 0;
				status = STATUS_CONFLICTING_ADDRESSES;
			}
			if (InInstructionRegion(SourceAddress.VirtualAddress, NumberOfBytes))
			{
				*NumberOfBytesTransferred = 0;
				status = STATUS_CONFLICTING_ADDRESSES;
			}
		}*/
	}

	if (status == STATUS_UNSUCCESSFUL)
		status = pfn_MmCopyMemory(TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred);

	return status;
}

NTSTATUS _MmCopyVirtualMemory(IN  PUCHAR FromProcess, IN  PVOID FromAddress, IN  PUCHAR ToProcess, OUT PVOID ToAddress, IN  SIZE_T BufferSize, IN  KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied)
{
	if (ToProcess && FromProcess) {
		HANDLE FromProcessPid = *(HANDLE*)(FromProcess + Global::g_pSysRotineAddr.UniqueProcessId);
		if (FromProcessPid == g_ProcessId) {
			if (InProtectRegion(FromAddress, 1)) {
				return STATUS_NOT_SUPPORTED;
			}
		}
	}
	return pfn_MmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress, BufferSize, PreviousMode, NumberOfBytesCopied);
}

void _PspExitProcess(IN BOOLEAN LastThreadExit, IN PEPROCESS Process)
{
	if (LastThreadExit && Process) {
		HANDLE ToProcessPid = *(HANDLE*)((PUCHAR)Process + Global::g_pSysRotineAddr.UniqueProcessId);
		if (ToProcessPid == g_ProcessId)
			CleanProtectRegion();
		EPTCleanInvalidHook(Process, false);
	}
	return pfn_PspExitProcess(LastThreadExit, Process);
}


extern "C" void InstrumentationCallback(uint64_t Trapframe, CallbackInfo * Info, uint64_t CallbackAddress)
{
	if (Trapframe)
	{
		uint64_t ReturnAddress = *(uint64_t*)(Trapframe + 0xE8);
		Info->RetAddress = Global::g_pSysRotineAddr.InstrumentationCallback + 14;
		Info->Callback = 0;
		if (ReturnAddress)
		{
			if (InProtectRegion((PVOID)ReturnAddress, 1))
			{
				*(uint64_t*)(Trapframe + 0xE8) = CallbackAddress;
				Info->Callback = 1;
			}
			if (InInstructionRegion((PVOID)ReturnAddress, 1))
			{
				*(uint64_t*)(Trapframe + 0xE8) = CallbackAddress;
				Info->Callback = 1;
			}
			if (CanMapRegion(g_Driver.Base, g_Driver.Size, (PVOID)ReturnAddress, 1))
			{
				*(uint64_t*)(Trapframe + 0xE8) = CallbackAddress;
				Info->Callback = 1;
			}
		}
	}
}

char __fastcall MmIsAddressValidEx(ULONG64 Address)
{
	
	if (InProtectRegion((PVOID)Address, 1) || InInstructionRegion((PVOID)Address, 1) || CanMapRegion(g_Driver.Base, g_Driver.Size, (PVOID)Address, 1))
	{
		return 0;
	}
	
	return pfn_MmIsAddressValid(Address);
}
//typedef char(__fastcall* fn_KeBugCheckEx)(ULONG BugCheckCode,
//	 ULONG_PTR BugCheckParameter1,
//	 ULONG_PTR BugCheckParameter2,
//	 ULONG_PTR BugCheckParameter3,
//	 ULONG_PTR BugCheckParameter4);
//fn_KeBugCheckEx    pfn_KeBugCheckEx = nullptr;
//
//VOID NTAPI KeBugCheckExG(
//	 ULONG BugCheckCode,
//	 ULONG_PTR BugCheckParameter1,
//	 ULONG_PTR BugCheckParameter2,
//	 ULONG_PTR BugCheckParameter3,
//	 ULONG_PTR BugCheckParameter4
//)
//{
//	Log("蓝屏了 妈的");
//}


PHYSICAL_ADDRESS __fastcall _MmGetPhysicalAddress(PVOID BaseAddress)
{

	if (InProtectRegion(BaseAddress, 1) || InInstructionRegion(BaseAddress, 1) || CanMapRegion(g_Driver.Base, g_Driver.Size, BaseAddress, 1))
	{
		return QuadPart;
	}
	
	return pfn_MmGetPhysicalAddress(BaseAddress);
}



PVOID __fastcall _MmGetVirtualForPhysical(PHYSICAL_ADDRESS PhysicalAddress)
{

	if (InProtectRegion((PVOID)PhysicalAddress.QuadPart, 1) || InInstructionRegion((PVOID)PhysicalAddress.QuadPart, 1) || CanMapRegion(g_Driver.Base, g_Driver.Size, (PVOID)PhysicalAddress.QuadPart, 1))
	{
		return (PVOID)BlankAddress;
	}
	
	return pfn_MmGetVirtualForPhysical(PhysicalAddress);
}



PMDL __fastcall _MmCreateMdl(PMDL MemoryDescriptorList, PVOID Base, SIZE_T Length)
{

	if (InProtectRegion(Base, 1) || InInstructionRegion(Base, 1) || CanMapRegion(g_Driver.Base, g_Driver.Size, Base, 1))
	{
		Base = (PVOID)BlankAddress;
	}
	
	return pfn_MmCreateMdl(MemoryDescriptorList, Base, Length);
}



PMDL __fastcall _IoAllocateMdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)
{

	if (InProtectRegion(VirtualAddress, 1) || InInstructionRegion(VirtualAddress, 1) || CanMapRegion(g_Driver.Base, g_Driver.Size, VirtualAddress, 1))
	{
		VirtualAddress = (PVOID)BlankAddress;
	}
	
	return pfn_IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}

NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		if (initname)
		{
			RtlZeroMemory(initname, ObjectAttributes->ObjectName->Length * 2);
			RtlCopyMemory(initname, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
			if (wcsstr(initname, L"dtdn.sys"))
			{
				return STATUS_ACCESS_DENIED;
			}
		}
	}

	return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void MonitoringStart(PVOID Address, size_t Size)
{
	g_Driver.Base = (PUCHAR)Address;
	g_Driver.Size = Size;
	PHYSICAL_ADDRESS MaxAddrPa{ 0 }, LowAddrPa{ 0 };
	MaxAddrPa.QuadPart = MAXULONG64;
	LowAddrPa.QuadPart = 0;
	BlankAddress = (ULONG64)MmAllocateContiguousMemorySpecifyCache(0x100000, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
	//RtlZeroMemory((PVOID)BlankAddress, 0x100000);
	QuadPart = MmGetPhysicalAddress((PVOID)BlankAddress);

	initname = (wchar_t*)Common::AllocateMemory(0x1000, false);

	if (Global::g_pSysRotineAddr.buildNo == 22000 || Global::g_pSysRotineAddr.buildNo >= 22454)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_22xxx, NULL, TRUE);

	if (Global::g_pSysRotineAddr.buildNo == 19041 || Global::g_pSysRotineAddr.buildNo == 19042 || Global::g_pSysRotineAddr.buildNo == 19043 || Global::g_pSysRotineAddr.buildNo == 19044)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_1904x, NULL, TRUE);

	if (Global::g_pSysRotineAddr.buildNo == 18362 || Global::g_pSysRotineAddr.buildNo == 18363)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_1836x, NULL, TRUE);

	if (Global::g_pSysRotineAddr.buildNo == 17763)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_17763, NULL, TRUE);

	if (Global::g_pSysRotineAddr.buildNo == 17134)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_17134, NULL, TRUE);

	if (Global::g_pSysRotineAddr.buildNo == 16299)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_16299, NULL, TRUE);

	if (Global::g_pSysRotineAddr.buildNo == 15063)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.RtlWalkFrameChain, __redirect_15063, NULL, TRUE);
	//EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"KeBugCheckEx"), KeBugCheckExG, (PVOID*)&pfn_KeBugCheckEx, true);
	//EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"MmCopyVirtualMemory"), _MmCopyVirtualMemory, (PVOID*)&pfn_MmCopyVirtualMemory, true);
	//EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.PspGetContext, _PspGetContext, (PVOID*)&pfn_PspGetContext, TRUE);

	//EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.PspExitProcess, _PspExitProcess, (PVOID*)&pfn_PspExitProcess, TRUE);


	if (Global::g_pSysRotineAddr.buildNo >= 9600)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.MmCopyMemory, _MmCopyMemory, (PVOID*)&pfn_MmCopyMemory, TRUE);

	if (Global::g_pSysRotineAddr.buildNo >= 10586)
		EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.PnpDiagnosticTraceObject.HookAddress, _PnpDiagnosticTraceObject, (PVOID*)&pfn_PnpDiagnosticTraceObject, true);

	//EPTHookPerformPageHook((void*)Global::g_pSysRotineAddr.InstrumentationCallback, __InstrumentationCallback, NULL, TRUE);
	ULONG64 MmIsAddressValidE = (ULONG64)Common::GetSystemRoutineAddress(L"MmIsAddressValid");
	MmIsAddressValidE = MmIsAddressValidE + 5;
	MmIsAddressValidE = (ULONG64)(MmIsAddressValidE + *(PLONG)(MmIsAddressValidE)+0x4);
	EPTHookPerformPageHook((PVOID)MmIsAddressValidE, MmIsAddressValidEx, (PVOID*)&pfn_MmIsAddressValid, TRUE);
	EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"MmGetPhysicalAddress"), _MmGetPhysicalAddress, (PVOID*)&pfn_MmGetPhysicalAddress, TRUE);//防止 扫驱动 PE 文件
	EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"MmGetVirtualForPhysical"), _MmGetVirtualForPhysical, (PVOID*)&pfn_MmGetVirtualForPhysical, TRUE);//防止 扫驱动 PE 文件
	EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"MmCreateMdl"), _MmCreateMdl, (PVOID*)&pfn_MmCreateMdl, TRUE);
	EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"IoAllocateMdl"), _IoAllocateMdl, (PVOID*)&pfn_IoAllocateMdl, TRUE);
	EPTHookPerformPageHook(Common::GetSystemRoutineAddress(L"NtCreateFile"), MyNtCreateFile, (PVOID*)&g_NtCreateFile, TRUE);
}